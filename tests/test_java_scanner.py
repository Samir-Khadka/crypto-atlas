"""Java scanner: every rule fires on the true-positive fixture,
nothing fires on the clean fixture. Ranking: per-rule profile
overrides weight data lifetime by what the finding protects."""
from __future__ import annotations

import json
from pathlib import Path

from crypto_atlas.findings import Finding
from crypto_atlas.ranking import Profile, ranked, risk
from crypto_atlas.scanners.java_scanner import scan_java

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def _rules(findings):
    return {f.rule_id for f in findings}


def _finding(rule_id, weakness=5):
    return Finding(rule_id=rule_id, algorithm="X", weakness=weakness,
                   file="x.java", line=1, snippet="x",
                   evidence="test", fix="fix", language="java",
                   change_difficulty=1)


def test_java_true_positives():
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    rules = _rules(findings)
    assert "weak-hash" in rules
    assert "weak-cipher" in rules
    assert "rsa-keygen" in rules
    assert "ecc-keygen" in rules
    assert "weak-random" in rules
    assert "hardcoded-key" in rules
    assert "tls-old-version" in rules
    assert "tls-disabled" in rules
    assert "pq-algorithm" in rules


def test_java_clean_fixture_is_clean():
    text = (FIX / "java_clean.java").read_text(encoding="utf-8")
    findings = scan_java("java_clean.java", text)
    assert findings == []


def test_java_rsa_weakness_by_size():
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
    assert rsa and rsa[0].weakness == 5
    assert rsa[0].key_size == 1024


def test_java_ecc_weakness_by_curve():
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    ecc = [f for f in findings if f.rule_id == "ecc-keygen"]
    assert ecc and ecc[0].weakness == 5
    assert ecc[0].curve == "secp192r1"


def test_java_ecb_is_weak_cipher():
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    weak = [f for f in findings if f.rule_id == "weak-cipher"]
    assert any(f.algorithm == "AES-ECB" for f in weak)
    assert any(f.algorithm == "DES" for f in weak)


def test_java_pq_is_informational():
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    pq = [f for f in findings if f.rule_id == "pq-algorithm"]
    assert pq and pq[0].weakness == 1


def test_java_strong_keygen_is_weakness_3():
    # a strong key is still quantum-vulnerable, so it fires — at
    # weakness 3, not 5. The clean fixture avoids keygen entirely.
    text = ("public class A { void m() throws Exception {\n"
            " KeyPairGenerator rsa = KeyPairGenerator.getInstance"
            "(\"RSA\"); rsa.initialize(4096);\n"
            " KeyPairGenerator ec = KeyPairGenerator.getInstance"
            "(\"EC\"); ec.initialize(new ECGenParameterSpec"
            "(\"secp384r1\")); } }")
    findings = scan_java("a.java", text)
    rsa = [f for f in findings if f.rule_id == "rsa-keygen"]
    ecc = [f for f in findings if f.rule_id == "ecc-keygen"]
    assert rsa and rsa[0].weakness == 3
    assert ecc and ecc[0].weakness == 3


def test_java_tls_disabled_fires_three_times():
    # the lambda verifier plus the two empty TrustManager methods
    text = (FIX / "java_crypto.java").read_text(encoding="utf-8")
    findings = scan_java("java_crypto.java", text)
    disabled = [f for f in findings if f.rule_id == "tls-disabled"]
    assert len(disabled) == 3
    assert any("HostnameVerifier" in f.evidence for f in disabled)
    assert any("checkServerTrusted" in f.evidence for f in disabled)
    assert any("checkClientTrusted" in f.evidence for f in disabled)


def test_per_rule_override_weights_lifetime():
    # a hardcoded key guarding long-lived data outranks the same
    # weakness with default weights
    profile = Profile.from_dict(
        {"rules": {"hardcoded-key": {"lifetime": 5}}})
    key = _finding("hardcoded-key")
    other = _finding("weak-hash")
    assert risk(key, profile) == 5 * 5 * 3 * 3
    assert risk(other, profile) == 5 * 3 * 3 * 3
    assert ranked([other, key], profile)[0][0] is key


def test_profile_without_overrides_uses_globals():
    profile = Profile()
    finding = _finding("hardcoded-key")
    assert risk(finding, profile) == 5 * 3 * 3 * 3


def test_profile_example_loads_and_applies():
    data = json.loads((ROOT / "profile.example.json")
                      .read_text(encoding="utf-8"))
    profile = Profile.from_dict(data)
    key = _finding("hardcoded-key")
    tls = _finding("tls-old-version")
    # the example gives the hardcoded key lifetime 5 and the TLS
    # finding lifetime 2, so the key ranks higher
    assert risk(key, profile) > risk(tls, profile)
    assert profile.weights_for("hardcoded-key") == (5, 3, 5)
    assert profile.weights_for("tls-old-version") == (2, 3, 3)
