"""JS/TS scanner: every rule fires on the true-positive fixture,
nothing fires on the clean fixture."""
from __future__ import annotations

from pathlib import Path

from crypto_atlas.scanners.js_scanner import scan_js

FIX = Path(__file__).parent / "fixtures"


def _rules(findings):
    return {f.rule_id for f in findings}


def test_js_true_positives():
    text = (FIX / "js_crypto.js").read_text(encoding="utf-8")
    findings = scan_js("js_crypto.js", text)
    rules = _rules(findings)
    assert "rsa-keygen" in rules
    assert "ecc-keygen" in rules
    assert "weak-hash" in rules
    assert "weak-cipher" in rules
    assert "weak-random" in rules
    assert "tls-disabled" in rules
    assert "tls-old-version" in rules


def test_js_rsa_weakness_by_size():
    text = (FIX / "js_crypto.js").read_text(encoding="utf-8")
    findings = scan_js("js_crypto.js", text)
    rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
    by_size = {f.key_size: f.weakness for f in rsa}
    assert by_size[1024] == 5
    assert by_size[2048] == 4


def test_js_clean_file_is_clean():
    text = (FIX / "js_clean.js").read_text(encoding="utf-8")
    assert scan_js("js_clean.js", text) == []


def test_js_webcrypto_generatekey():
    text = ("const k = await crypto.subtle.generateKey("
            "{name: 'RSA-OAEP', modulusLength: 2048, "
            "publicExponent: new Uint8Array([1, 0, 1]), "
            "hash: 'SHA-256'}, true, ['encrypt']);")
    findings = scan_js("webcrypto.js", text)
    assert any(f.rule_id == "rsa-keygen"
               and f.key_size == 2048 for f in findings)


def test_js_typescript_parses():
    text = ("const token: string = Math.random().toString(36);\n"
            "const d: string = crypto.createHash('md5')"
            ".update('x').digest('hex');")
    findings = scan_js("typed.ts", text)
    rules = _rules(findings)
    assert "weak-random" in rules
    assert "weak-hash" in rules
