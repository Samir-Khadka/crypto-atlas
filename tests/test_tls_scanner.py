"""TLS scanner: probed against a local TLS server the tests control.

The server runs on 127.0.0.1 with a self-signed certificate, so
every version, cipher, and key type is exactly what the test asks
for. No live network is needed.
"""
from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from crypto_atlas.cbom import validate_cbom, build_cbom
from crypto_atlas.cli import main
from crypto_atlas.tls_scanner import (check_pq, get_leaf_cert,
                                      probe_ciphers, probe_versions,
                                      scan_domain)


def _make_cert(key_size: int | None = 2048,
               curve: str | None = None):
    if curve:
        key = ec.generate_private_key(getattr(ec, curve)())
    else:
        key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc)
                             + timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost")]),
                critical=False)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    return cert_pem, key_pem


class TLSTestServer:
    """A TLS server on 127.0.0.1 with a chosen cert, TLS version
    range, and cipher list. Accepts connections until stopped."""

    def __init__(self, min_version=ssl.TLSVersion.TLSv1_2,
                 max_version=ssl.TLSVersion.TLSv1_2,
                 ciphers=None, key_size=2048, curve=None):
        cert_pem, key_pem = _make_cert(key_size, curve)
        self._cert_file = Path(__file__).parent / "_test_cert.pem"
        self._key_file = Path(__file__).parent / "_test_key.pem"
        self._cert_file.write_bytes(cert_pem)
        self._key_file.write_bytes(key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = min_version
        ctx.maximum_version = max_version
        # @SECLEVEL=0 so the server can offer TLS 1.0, 3DES, and
        # RSA-1024 certs — the things the scanner must detect
        ctx.set_ciphers((ciphers or "DEFAULT") + "@SECLEVEL=0")
        ctx.load_cert_chain(str(self._cert_file), str(self._key_file))
        self._ctx = ctx
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                wrapped = self._ctx.wrap_socket(conn, server_side=True)
                wrapped.close()
            except Exception:
                try:
                    conn.close()
                except OSError:
                    pass

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            socket.create_connection(("127.0.0.1", self.port),
                                     timeout=2).close()
        except OSError:
            pass
        self._thread.join(timeout=5)
        self._sock.close()
        self._cert_file.unlink(missing_ok=True)
        self._key_file.unlink(missing_ok=True)
        return False


def test_versions_tls12_only():
    with TLSTestServer() as server:
        versions = probe_versions("127.0.0.1", server.port)
        assert versions == {"TLS 1.0": False, "TLS 1.1": False,
                            "TLS 1.2": True, "TLS 1.3": False}


def test_versions_tls10_flagged():
    with TLSTestServer(min_version=ssl.TLSVersion.TLSv1,
                       max_version=ssl.TLSVersion.TLSv1) as server:
        versions = probe_versions("127.0.0.1", server.port)
        assert versions["TLS 1.0"] is True
        findings, _ = scan_domain("127.0.0.1", server.port)
        assert any(f.rule_id == "tls-old-version"
                   and f.algorithm == "TLS 1.0" for f in findings)


def test_tls12_only_has_no_old_version_finding():
    with TLSTestServer() as server:
        findings, _ = scan_domain("127.0.0.1", server.port)
        assert not any(f.rule_id == "tls-old-version"
                       for f in findings)


def test_rsa_2048_cert_is_weakness_4():
    with TLSTestServer(key_size=2048) as server:
        leaf = get_leaf_cert("127.0.0.1", server.port)
        assert leaf["key_type"] == "RSA"
        assert leaf["key_size"] == 2048
        findings, _ = scan_domain("127.0.0.1", server.port)
        rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
        assert rsa and rsa[0].weakness == 4
        assert rsa[0].asset_type == "certificate"


def test_rsa_1024_cert_is_weakness_5():
    with TLSTestServer(key_size=1024) as server:
        findings, _ = scan_domain("127.0.0.1", server.port)
        rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
        assert rsa and rsa[0].weakness == 5


def test_ecc_p256_cert_is_weakness_4():
    with TLSTestServer(curve="SECP256R1") as server:
        leaf = get_leaf_cert("127.0.0.1", server.port)
        assert leaf["key_type"] == "ECC"
        assert leaf["curve"] == "secp256r1"
        findings, _ = scan_domain("127.0.0.1", server.port)
        ecc = [f for f in findings if f.rule_id == "ecc-keygen"]
        assert ecc and ecc[0].weakness == 4


def test_deprecated_cipher_accepted_is_flagged():
    # AES128-SHA is CBC with no forward secrecy: deprecated,
    # weakness 3 — and it is in the default provider, so the probe
    # can actually test it end to end
    with TLSTestServer(ciphers="AES128-SHA") as server:
        ciphers = probe_ciphers("127.0.0.1", server.port)
        assert ciphers.get("AES128-SHA") is True
        findings, _ = scan_domain("127.0.0.1", server.port)
        weak = [f for f in findings if f.rule_id == "weak-cipher"]
        assert weak and weak[0].algorithm == "AES128-SHA"
        assert weak[0].weakness == 3


def test_broken_cipher_flagged_when_server_accepts_it():
    # DES/RC4 live in the legacy provider, so no real server here
    # can offer them — simulate the acceptance instead, and let
    # every other handshake through to the real server
    from crypto_atlas.tls_scanner import _handshake as real_handshake

    def fake_handshake(host, port, timeout, min_version=None,
                       max_version=None, ciphers=None):
        if ciphers == "DES-CBC3-SHA":
            class S:
                def close(self):
                    pass
            return S()
        if ciphers is not None:
            raise ssl.SSLError("no shared cipher")
        return real_handshake(host, port, timeout,
                              min_version=min_version,
                              max_version=max_version)

    with TLSTestServer() as server:
        with patch("crypto_atlas.tls_scanner._handshake",
                   side_effect=fake_handshake):
            findings, _ = scan_domain("127.0.0.1", server.port)
        weak = [f for f in findings if f.rule_id == "weak-cipher"
                and f.algorithm == "DES-CBC3-SHA"]
        assert weak and weak[0].weakness == 5


def test_broken_ciphers_untested_without_legacy_provider():
    # this runtime has no legacy provider, so RC4/DES cannot even
    # be offered — the probe must say untested, not clean
    with TLSTestServer() as server:
        ciphers = probe_ciphers("127.0.0.1", server.port)
        assert ciphers.get("DES-CBC3-SHA") is None
        assert ciphers.get("RC4-SHA") is None
        _, summary = scan_domain("127.0.0.1", server.port)
        assert "DES-CBC3-SHA" in summary["untested_ciphers"]


def test_strong_cipher_only_is_clean():
    with TLSTestServer(
            ciphers="ECDHE-RSA-AES256-GCM-SHA384") as server:
        findings, _ = scan_domain("127.0.0.1", server.port)
        assert not any(f.rule_id == "weak-cipher" for f in findings)


def test_pq_unknown_on_openssl_30():
    # this runtime is OpenSSL 3.0.13: the hybrid group does not
    # exist, so the check must say unknown, not guess
    result = check_pq("127.0.0.1", 1)
    assert result["status"] == "unknown"
    assert "3.5" in result["reason"]


def test_pq_supported_when_handshake_succeeds():
    fake = type("R", (), {})()
    fake.stdout = b"X25519MLKEM768\n"
    fake.stderr = b""
    ok = type("R", (), {})()
    ok.stdout = b"CONNECTED\nVerify return code: 0 (ok)\n"
    ok.stderr = b""

    def run(cmd, **kw):
        if cmd[:3] == ["openssl", "list", "-groups"]:
            return fake
        return ok

    with patch("crypto_atlas.tls_scanner.subprocess.run",
               side_effect=run):
        result = check_pq("example.com", 443)
        assert result["status"] == "supported"


def test_pq_not_supported_when_handshake_fails():
    fake = type("R", (), {})()
    fake.stdout = b"X25519MLKEM768\n"
    fake.stderr = b""
    fail = type("R", (), {})()
    fail.stdout = b""
    fail.stderr = b"no shared group"

    def run(cmd, **kw):
        if cmd[:3] == ["openssl", "list", "-groups"]:
            return fake
        return fail

    with patch("crypto_atlas.tls_scanner.subprocess.run",
               side_effect=run):
        result = check_pq("example.com", 443)
        assert result["status"] == "not-supported"


def test_cli_tls_local_server(tmp_path):
    with TLSTestServer() as server:
        code = main(["tls", f"127.0.0.1:{server.port}",
                     "--output", str(tmp_path)])
        assert code == 1  # RSA-2048 finding is weakness 4
        cbom = build_cbom([], "x")  # sanity: schema loads
        import json
        document = json.loads((tmp_path / "cbom.json")
                              .read_text(encoding="utf-8"))
        assert validate_cbom(document) == []
        assert (tmp_path / "report.md").exists()
        assert any(c["type"] == "cryptographic-asset"
                   for c in document["components"])


def test_cli_tls_file_input(tmp_path):
    with TLSTestServer() as server:
        domains = tmp_path / "domains.txt"
        domains.write_text(f"# comment\n127.0.0.1:{server.port}\n",
                           encoding="utf-8")
        code = main(["tls", "--file", str(domains),
                     "--output", str(tmp_path)])
        assert code == 1
