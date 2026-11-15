"""Python scanner: every rule fires on the true-positive fixture,
nothing fires on the clean fixture."""
from __future__ import annotations

from pathlib import Path

from crypto_atlas.scanners.python_scanner import scan_python

FIX = Path(__file__).parent / "fixtures"


def _rules(findings):
    return {f.rule_id for f in findings}


def test_python_true_positives():
    text = (FIX / "python_crypto.py").read_text(encoding="utf-8")
    findings = scan_python("python_crypto.py", text)
    rules = _rules(findings)
    assert "rsa-keygen" in rules
    assert "ecc-keygen" in rules
    assert "weak-hash" in rules
    assert "weak-cipher" in rules
    assert "weak-random" in rules
    assert "hardcoded-key" in rules
    assert "tls-disabled" in rules
    assert "tls-old-version" in rules


def test_python_rsa_weakness_by_size():
    text = (FIX / "python_crypto.py").read_text(encoding="utf-8")
    findings = scan_python("python_crypto.py", text)
    rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
    by_size = {f.key_size: f.weakness for f in rsa}
    assert by_size[1024] == 5
    assert by_size[2048] == 4


def test_python_weak_hash_counts_both():
    text = (FIX / "python_crypto.py").read_text(encoding="utf-8")
    findings = scan_python("python_crypto.py", text)
    hashes = [f for f in findings if f.rule_id == "weak-hash"]
    assert {f.algorithm for f in hashes} == {"MD5", "SHA1"}


def test_python_clean_file_is_clean():
    text = (FIX / "python_clean.py").read_text(encoding="utf-8")
    assert scan_python("python_clean.py", text) == []


def test_python_syntax_error_is_not_a_finding():
    assert scan_python("broken.py", "def broken(:") == []


def test_python_aliases_resolve():
    text = "from hashlib import md5\nmd5(b'x').hexdigest()\n"
    findings = scan_python("alias.py", text)
    assert any(f.rule_id == "weak-hash" for f in findings)
    text2 = "import hashlib as hl\nhl.sha1(b'x').hexdigest()\n"
    findings2 = scan_python("alias2.py", text2)
    assert any(f.rule_id == "weak-hash" for f in findings2)
