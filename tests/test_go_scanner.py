"""Go scanner: every rule fires on the true-positive fixture,
nothing fires on the clean fixture."""
from __future__ import annotations

from pathlib import Path

from crypto_atlas.scanners.go_scanner import scan_go

FIX = Path(__file__).parent / "fixtures"


def _rules(findings):
    return {f.rule_id for f in findings}


def test_go_true_positives():
    text = (FIX / "go_crypto.go").read_text(encoding="utf-8")
    findings = scan_go("go_crypto.go", text)
    rules = _rules(findings)
    assert "rsa-keygen" in rules
    assert "weak-hash" in rules
    assert "weak-cipher" in rules
    assert "weak-random" in rules
    assert "tls-disabled" in rules
    assert "tls-old-version" in rules


def test_go_rsa_weakness_by_size():
    text = (FIX / "go_crypto.go").read_text(encoding="utf-8")
    findings = scan_go("go_crypto.go", text)
    rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
    by_size = {f.key_size: f.weakness for f in rsa}
    assert by_size[1024] == 5
    assert by_size[2048] == 4


def test_go_clean_file_is_clean():
    text = (FIX / "go_clean.go").read_text(encoding="utf-8")
    assert scan_go("go_clean.go", text) == []


def test_go_ecdsa_keygen():
    text = ("package main\nimport (\"crypto/ecdsa\"; "
            "\"crypto/elliptic\"; \"crypto/rand\")\nfunc main() { "
            "_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }")
    findings = scan_go("ec.go", text)
    assert any(f.rule_id == "ecc-keygen" for f in findings)
