"""Config + certificate scanner (rule 8).

- nginx / Apache configs: ssl_protocols allowing TLS 1.0/1.1, and
  cipher lists containing RC4, DES, or 3DES.
- PEM files: certificates and private keys, parsed with the
  ``cryptography`` library. A file that is not a valid PEM is
  skipped silently — it is not a finding.
"""
from __future__ import annotations

import re

from ..findings import Finding
from ..keys import weakness_for_curve, weakness_for_rsa
from ..rules import RULES

_SSL_PROTOCOLS = re.compile(
    r"^\s*ssl_protocols\s+([^;]+);", re.MULTILINE)
_SSL_CIPHERS = re.compile(
    r"^\s*ssl_ciphers\s+([^;]+);", re.MULTILINE)
_WEAK_CIPHER = re.compile(r"\b(RC4|DES|3DES|DES-CBC|RC4-MD5)\b",
                          re.IGNORECASE)


def scan_config(path: str, text: str) -> list[Finding]:
    """Scan one nginx / Apache config file."""
    findings: list[Finding] = []
    lines = text.splitlines()
    rule = RULES["tls-old-version"]
    for match in _SSL_PROTOCOLS.finditer(text):
        protocols = match.group(1)
        # tokenize: "TLSv1.2" must not match the TLSv1.0 pattern
        tokens = protocols.split()
        if any(t in ("TLSv1", "TLSv1.0", "TLSv1.1") for t in tokens):
            lineno = text[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="tls-old-version", algorithm="TLS 1.0/1.1",
                weakness=5, file=path, line=lineno,
                snippet=lines[lineno - 1].strip(),
                evidence="TLS 1.0 or 1.1 allowed in ssl_protocols",
                fix=rule["fix"], language="config",
                change_difficulty=1, asset_type="protocol",
                parameter_set="TLS 1.0/1.1"))
    for match in _SSL_CIPHERS.finditer(text):
        ciphers = match.group(1)
        # tokens prefixed with ! are exclusions, not enabled ciphers
        enabled = [t for t in ciphers.split(":")
                   if not t.startswith("!")]
        weak = None
        for token in enabled:
            hit = _WEAK_CIPHER.search(token)
            if hit:
                weak = hit
                break
        if weak:
            lineno = text[:match.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="tls-old-version",
                algorithm=weak.group(1).upper(), weakness=5,
                file=path, line=lineno,
                snippet=lines[lineno - 1].strip(),
                evidence=f"weak cipher {weak.group(1)} in ssl_ciphers",
                fix=rule["fix"], language="config",
                change_difficulty=1, asset_type="protocol",
                parameter_set=weak.group(1).upper()))
    return findings


def scan_pem(path: str, data: bytes) -> list[Finding]:
    """Scan one PEM file (certificate or private key)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
    except ImportError:
        return []
    findings: list[Finding] = []
    # certificate
    try:
        cert = x509.load_pem_x509_certificate(data)
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            size = pub.key_size
            findings.append(Finding(
                rule_id="rsa-keygen", algorithm="RSA",
                weakness=weakness_for_rsa(size), file=path, line=1,
                snippet=f"certificate: {cert.subject.rfc4514_string()}",
                evidence=f"certificate uses RSA-{size}",
                fix=RULES["rsa-keygen"]["fix"], language="config",
                change_difficulty=1, asset_type="certificate",
                key_size=size, primitive="pke",
                parameter_set=f"RSA-{size}"))
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            curve = pub.curve.name
            findings.append(Finding(
                rule_id="ecc-keygen", algorithm="ECC",
                weakness=weakness_for_curve(curve), file=path, line=1,
                snippet=f"certificate: {cert.subject.rfc4514_string()}",
                evidence=f"certificate uses ECC {curve}",
                fix=RULES["ecc-keygen"]["fix"], language="config",
                change_difficulty=1, asset_type="certificate",
                curve=curve, primitive="signature",
                parameter_set=curve))
        return findings
    except ValueError:
        pass
    # private key
    try:
        key = serialization.load_pem_private_key(data, password=None)
        if isinstance(key, rsa.RSAPrivateKey):
            size = key.key_size
            findings.append(Finding(
                rule_id="rsa-keygen", algorithm="RSA",
                weakness=weakness_for_rsa(size), file=path, line=1,
                snippet="private key",
                evidence=f"private key is RSA-{size}",
                fix=RULES["rsa-keygen"]["fix"], language="config",
                change_difficulty=1,
                asset_type="related-crypto-material",
                key_size=size, primitive="pke",
                parameter_set=f"RSA-{size}"))
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            curve = key.curve.name
            findings.append(Finding(
                rule_id="ecc-keygen", algorithm="ECC",
                weakness=weakness_for_curve(curve), file=path, line=1,
                snippet="private key",
                evidence=f"private key is ECC {curve}",
                fix=RULES["ecc-keygen"]["fix"], language="config",
                change_difficulty=1,
                asset_type="related-crypto-material",
                curve=curve, primitive="signature",
                parameter_set=curve))
    except ValueError:
        pass
    return findings
