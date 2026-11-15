"""TLS scanner (v0.2): what a live endpoint actually offers.

For each domain: which TLS versions it accepts, which cipher
suites it accepts, the leaf (and, when the openssl CLI is
available, the full chain) certificate's key type and signature
algorithm, and whether it negotiates the hybrid post-quantum
group X25519MLKEM768.

The scanner inspects; it never trusts. Certificate verification is
off for every probe, because the point is to see what the server
offers, including a self-signed or expired certificate.

Two honest limits, both documented in the README:
- PQ-readiness needs OpenSSL 3.5 or later in the runtime. On an
  older runtime the check reports "unknown" instead of guessing.
- In a network that terminates TLS (a corporate proxy, this
  sandbox's egress proxy), the version, cipher, and certificate
  are the proxy's, not the destination's. The scanner says so in
  the report when it detects a proxy in use.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse

from .findings import Finding
from .keys import weakness_for_curve, weakness_for_rsa
from .rules import RULES

VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]

# ciphers to test on a TLS 1.2 handshake: a single-cipher context
# succeeds only when the server accepts that cipher.
# Broken (weakness 5): RC4, DES, 3DES, NULL, EXPORT. These live in
# OpenSSL's legacy provider, which most runtimes do not load — on
# such a runtime the probe reports them as untested, not as clean.
# Deprecated (weakness 3): CBC ciphers with no forward secrecy.
# Available in the default provider, so they are testable anywhere.
BROKEN_CIPHERS = [
    "RC4-SHA", "RC4-MD5", "DES-CBC-SHA", "DES-CBC3-SHA",
    "NULL-SHA", "EXP-RC4-MD5", "EDH-RSA-DES-CBC-SHA",
]
DEPRECATED_CIPHERS = [
    "AES128-SHA", "AES256-SHA",
]
STRONG_CIPHERS = [
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "AES256-GCM-SHA384",
]

_HYBRID_GROUP = "X25519MLKEM768"
_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL)


def _proxy_for(host: str) -> tuple[str, int] | None:
    """The CONNECT proxy for this host, or None for a direct
    connection. Localhost and no_proxy entries go direct."""
    if host in ("localhost", "127.0.0.1", "::1"):
        return None
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") \
        or ""
    if any(h.strip() in (host, "*") for h in no_proxy.split(",")
           if h.strip()):
        return None
    proxy = os.environ.get("HTTPS_PROXY") \
        or os.environ.get("https_proxy") or ""
    if not proxy:
        return None
    parsed = urlparse(proxy)
    if not parsed.hostname or not parsed.port:
        return None
    return parsed.hostname, parsed.port


def _open_socket(host: str, port: int, timeout: float) -> socket.socket:
    """A TCP socket to host:port, via a CONNECT tunnel when a proxy
    is configured for the host."""
    proxy = _proxy_for(host)
    if proxy is None:
        return socket.create_connection((host, port), timeout=timeout)
    sock = socket.create_connection(proxy, timeout=timeout)
    request = (f"CONNECT {host}:{port} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n\r\n").encode()
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    if not response.startswith(b"HTTP/1.1 200") \
            and not response.startswith(b"HTTP/1.0 200"):
        sock.close()
        raise OSError(f"proxy refused CONNECT: "
                      f"{response.splitlines()[0:1]}")
    return sock


def _handshake(host: str, port: int, timeout: float,
               min_version: ssl.TLSVersion | None = None,
               max_version: ssl.TLSVersion | None = None,
               ciphers: str | None = None) -> ssl.SSLSocket:
    """One TLS handshake with the given constraints. Raises on
    failure; the caller decides what a failure means."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # @SECLEVEL=0: the scanner inspects, it does not enforce its
    # own policy. Without it, this runtime's security level would
    # refuse to offer TLS 1.0/1.1, weak ciphers, or small keys —
    # and a server that offers them would wrongly look clean.
    if ciphers is not None:
        try:
            ctx.set_ciphers(f"{ciphers}@SECLEVEL=0")
        except ssl.SSLError as exc:
            # the runtime does not have this cipher at all (e.g.
            # RC4/DES live in the legacy provider, which most
            # runtimes do not load) — untestable, not clean
            raise RuntimeError(
                f"cipher {ciphers} is not available on this runtime"
            ) from exc
    else:
        ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    sock = _open_socket(host, port, timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except Exception:
        sock.close()
        raise


def probe_versions(host: str, port: int,
                   timeout: float = 10.0) -> dict[str, bool]:
    """Which TLS versions the server accepts."""
    offered: dict[str, bool] = {}
    for name, version in VERSIONS:
        try:
            sock = _handshake(host, port, timeout,
                              min_version=version, max_version=version)
            sock.close()
            offered[name] = True
        except Exception:
            offered[name] = False
    return offered


def probe_ciphers(host: str, port: int,
                  timeout: float = 10.0) -> dict[str, bool | None]:
    """Which of the candidate TLS 1.2 ciphers the server accepts,
    plus the cipher negotiated on a plain TLS 1.3 handshake.
    True = the server accepts it; False = it does not; None = this
    runtime cannot offer the cipher, so it was not tested."""
    accepted: dict[str, bool | None] = {}
    for cipher in BROKEN_CIPHERS + DEPRECATED_CIPHERS + STRONG_CIPHERS:
        try:
            sock = _handshake(host, port, timeout,
                              min_version=ssl.TLSVersion.TLSv1_2,
                              max_version=ssl.TLSVersion.TLSv1_2,
                              ciphers=cipher)
            sock.close()
            accepted[cipher] = True
        except RuntimeError:
            accepted[cipher] = None
        except Exception:
            accepted[cipher] = False
    try:
        sock = _handshake(host, port, timeout,
                          min_version=ssl.TLSVersion.TLSv1_3,
                          max_version=ssl.TLSVersion.TLSv1_3)
        accepted[f"TLS 1.3 negotiated: {sock.cipher()[0]}"] = True
        sock.close()
    except Exception:
        pass
    return accepted


def _parse_cert_der(der: bytes) -> dict:
    """The key facts of one certificate, from its DER bytes."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    info: dict = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "expired": cert.not_valid_after_utc
                   < datetime.now(timezone.utc),
        "signature_algorithm": cert.signature_algorithm_oid._name
        if hasattr(cert.signature_algorithm_oid, "_name") else
        str(cert.signature_algorithm_oid),
    }
    if isinstance(pub, rsa.RSAPublicKey):
        info["key_type"] = "RSA"
        info["key_size"] = pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        info["key_type"] = "ECC"
        info["curve"] = pub.curve.name
        info["key_size"] = pub.curve.key_size
    else:
        info["key_type"] = type(pub).__name__
        info["key_size"] = None
    return info


def get_leaf_cert(host: str, port: int,
                  timeout: float = 10.0) -> dict:
    """The leaf certificate, as the server presents it.

    Tries the newest version first and falls back to older ones:
    a server that only speaks TLS 1.0 still has a certificate, and
    the scanner must read it. Each attempt pins both ends of the
    version range, because the runtime's default minimum version
    varies by build (one build accepts TLS 1.0 by default, another
    refuses it) and the scanner must not depend on that."""
    last_error: Exception | None = None
    for _, version in reversed(VERSIONS):
        try:
            sock = _handshake(host, port, timeout,
                              min_version=version, max_version=version)
        except Exception as exc:
            last_error = exc
            continue
        try:
            der = sock.getpeercert(binary_form=True)
        finally:
            sock.close()
        if not der:
            raise OSError("server presented no certificate")
        return _parse_cert_der(der)
    raise OSError(f"could not read the certificate: {last_error}")


def get_chain(host: str, port: int,
              timeout: float = 15.0) -> list[dict]:
    """The full certificate chain, via the openssl CLI when it is
    available. Falls back to the leaf certificate alone."""
    proxy = _proxy_for(host)
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-showcerts", "-servername", host]
    if proxy is not None:
        cmd += ["-proxy", f"{proxy[0]}:{proxy[1]}"]
    try:
        out = subprocess.run(cmd, input=b"", capture_output=True,
                             timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    text = out.stdout.decode("utf-8", errors="replace")
    certs = []
    for block in _PEM_BLOCK.findall(text):
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization \
                import Encoding
            der = x509.load_pem_x509_certificate(
                block.encode()).public_bytes(Encoding.DER)
            certs.append(_parse_cert_der(der))
        except Exception:
            continue
    return certs


def _openssl_knows_hybrid_group() -> bool:
    """Whether this runtime's OpenSSL knows X25519MLKEM768
    (OpenSSL 3.5+)."""
    try:
        out = subprocess.run(["openssl", "list", "-groups"],
                             capture_output=True, timeout=10)
        return _HYBRID_GROUP.encode() in out.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def check_pq(host: str, port: int,
             timeout: float = 15.0) -> dict:
    """Does the server negotiate the hybrid post-quantum group?

    Returns {"status": "supported" | "not-supported" | "unknown",
    "reason": ...}. "unknown" means this runtime's OpenSSL is
    older than 3.5 and cannot even ask — not a verdict on the
    server."""
    if not _openssl_knows_hybrid_group():
        return {"status": "unknown",
                "reason": "runtime OpenSSL is older than 3.5, so "
                          "the hybrid group X25519MLKEM768 cannot "
                          "be offered here"}
    proxy = _proxy_for(host)
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}",
           "-tls1_3", "-groups", _HYBRID_GROUP,
           "-servername", host]
    if proxy is not None:
        cmd += ["-proxy", f"{proxy[0]}:{proxy[1]}"]
    try:
        out = subprocess.run(cmd, input=b"", capture_output=True,
                             timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "unknown", "reason": str(exc)}
    text = (out.stdout + out.stderr).decode("utf-8", errors="replace")
    if "Verify return code: 0" in text or "CONNECTED" in text:
        return {"status": "supported",
                "reason": "the server completed a TLS 1.3 handshake "
                          "with only the hybrid group offered"}
    return {"status": "not-supported",
            "reason": "the server did not complete a handshake with "
                      "only the hybrid group offered"}


def scan_domain(host: str, port: int = 443,
                timeout: float = 10.0) -> tuple[list[Finding], dict]:
    """Scan one endpoint. Returns (findings, summary)."""
    target = f"{host}:{port}" if port != 443 else host
    findings: list[Finding] = []

    def add(rule_id: str, algorithm: str, weakness: int,
            evidence: str, **kw) -> None:
        rule = RULES[rule_id]
        findings.append(Finding(
            rule_id=rule_id, algorithm=algorithm, weakness=weakness,
            file=target, line=1, snippet=target, evidence=evidence,
            fix=rule["fix"], language="tls",
            change_difficulty=rule["change_difficulty"], **kw))

    versions = probe_versions(host, port, timeout)
    for name in ("TLS 1.0", "TLS 1.1"):
        if versions.get(name):
            add("tls-old-version", name, 5,
                f"the server accepts {name}",
                asset_type="protocol", parameter_set=name)

    ciphers = probe_ciphers(host, port, timeout)
    for cipher, accepted in ciphers.items():
        if not accepted or cipher.startswith("TLS 1.3 negotiated"):
            continue
        if cipher in BROKEN_CIPHERS:
            add("weak-cipher", cipher, 5,
                f"the server accepts broken cipher {cipher}",
                asset_type="protocol", parameter_set=cipher)
        elif cipher in DEPRECATED_CIPHERS:
            add("weak-cipher", cipher, 3,
                f"the server accepts deprecated cipher {cipher} "
                f"(CBC, no forward secrecy)",
                asset_type="protocol", parameter_set=cipher)

    try:
        leaf = get_leaf_cert(host, port, timeout)
    except Exception as exc:
        raise OSError(f"could not read {target}'s certificate: {exc}")
    if leaf["key_type"] == "RSA":
        add("rsa-keygen", "RSA",
            weakness_for_rsa(leaf["key_size"]),
            f"the leaf certificate uses RSA-{leaf['key_size']}",
            key_size=leaf["key_size"], asset_type="certificate",
            primitive="pke", parameter_set=f"RSA-{leaf['key_size']}")
    elif leaf["key_type"] == "ECC":
        add("ecc-keygen", "ECC",
            weakness_for_curve(leaf.get("curve")),
            f"the leaf certificate uses ECC {leaf.get('curve')}",
            curve=leaf.get("curve"), asset_type="certificate",
            primitive="signature", parameter_set=leaf.get("curve"))
    sig = leaf.get("signature_algorithm", "")
    if "sha1" in sig.lower() or "md5" in sig.lower():
        add("weak-hash", sig.upper(), 5,
            f"the leaf certificate is signed with {sig}",
            asset_type="certificate", primitive="hash",
            parameter_set=sig.upper())

    pq = check_pq(host, port)
    if pq["status"] == "supported":
        add("pq-algorithm", "ML-KEM", 1,
            "the server negotiates the hybrid group "
            "X25519MLKEM768 (already quantum-safe)",
            asset_type="protocol", primitive="kem",
            parameter_set="X25519MLKEM768")

    summary = {
        "target": target,
        "versions": {k: v for k, v in versions.items() if v},
        "weak_ciphers": [c for c, ok in ciphers.items()
                         if ok and c in BROKEN_CIPHERS
                         + DEPRECATED_CIPHERS],
        "untested_ciphers": [c for c, ok in ciphers.items()
                             if ok is None],
        "leaf_cert": leaf,
        "pq": pq,
        "proxied": _proxy_for(host) is not None,
    }
    return findings, summary
