"""CBOM: the output validates against the CycloneDX 1.7 schema,
and every component carries its evidence."""
from __future__ import annotations

from crypto_atlas.cbom import build_cbom, validate_cbom
from crypto_atlas.findings import Finding


def _finding(**kw):
    base = dict(rule_id="weak-hash", algorithm="MD5", weakness=5,
                file="a.py", line=3, snippet="hashlib.md5(b'x')",
                evidence="MD5 used here", fix="Use SHA-256.",
                language="python", primitive="hash",
                parameter_set="MD5")
    base.update(kw)
    return Finding(**base)


def test_cbom_validates_against_schema():
    findings = [_finding(),
                _finding(rule_id="rsa-keygen", algorithm="RSA",
                         weakness=4, file="b.py", line=10,
                         snippet="rsa.generate_private_key(...)",
                         evidence="RSA key generated (2048 bits)",
                         fix="Plan the move to ML-KEM.",
                         key_size=2048, primitive="pke",
                         parameter_set="RSA-2048")]
    document = build_cbom(findings, "test-target")
    assert validate_cbom(document) == []


def test_cbom_empty_scan_validates():
    assert validate_cbom(build_cbom([], "empty")) == []


def test_cbom_carries_evidence():
    document = build_cbom([_finding()], "test-target")
    component = document["components"][0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    props = {p["name"]: p["value"]
             for p in component["properties"]}
    assert props["crypto-atlas:file"] == "a.py"
    assert props["crypto-atlas:line"] == "3"
    assert props["crypto-atlas:rule"] == "weak-hash"


def test_cbom_metadata_names_the_tool():
    document = build_cbom([], "test-target")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.7"
    assert document["metadata"]["tools"][0]["name"] == "crypto-atlas"
