"""Config + PEM scanner: bad nginx fires, good nginx is clean;
certificates and keys are graded by size."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from crypto_atlas.scanners.config_scanner import scan_config, scan_pem

FIX = Path(__file__).parent / "fixtures"


def _make_cert(key_size: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc)
                             + timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_nginx_bad_fires():
    text = (FIX / "nginx_bad.conf").read_text(encoding="utf-8")
    findings = scan_config("nginx_bad.conf", text)
    assert len(findings) == 2
    assert all(f.rule_id == "tls-old-version" for f in findings)


def test_nginx_good_is_clean():
    text = (FIX / "nginx_good.conf").read_text(encoding="utf-8")
    assert scan_config("nginx_good.conf", text) == []


def test_pem_cert_rsa_1024_is_weakness_5():
    findings = scan_pem("cert.pem", _make_cert(1024))
    assert len(findings) == 1
    assert findings[0].rule_id == "rsa-keygen"
    assert findings[0].weakness == 5
    assert findings[0].asset_type == "certificate"


def test_pem_cert_rsa_2048_is_weakness_4():
    findings = scan_pem("cert.pem", _make_cert(2048))
    assert findings[0].weakness == 4


def test_pem_non_pem_is_skipped():
    assert scan_pem("notes.txt", b"hello, this is not a PEM") == []
