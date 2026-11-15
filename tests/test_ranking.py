"""Ranking: risk = weakness x lifetime x exposure x sensitivity;
the report sorts by it, and quick wins are high risk + one-liner."""
from __future__ import annotations

from crypto_atlas.findings import Finding
from crypto_atlas.ranking import Profile, quick_wins, ranked, risk
from crypto_atlas.report import build_report


def _finding(weakness, difficulty=2, rule_id="weak-hash"):
    return Finding(rule_id=rule_id, algorithm="MD5", weakness=weakness,
                   file="a.py", line=1, snippet="x", evidence="e",
                   fix="f", language="python",
                   change_difficulty=difficulty)


def test_risk_formula():
    profile = Profile(lifetime=5, exposure=5, sensitivity=5)
    assert risk(_finding(4), profile) == 4 * 5 * 5 * 5


def test_ranked_sorts_by_risk():
    profile = Profile()
    findings = [_finding(3), _finding(5), _finding(4)]
    ordered = ranked(findings, profile)
    assert [f.weakness for f, _ in ordered] == [5, 4, 3]


def test_quick_wins_are_one_liners():
    profile = Profile()
    findings = [_finding(5, difficulty=1),
                _finding(5, difficulty=3),
                _finding(4, difficulty=1)]
    wins = quick_wins(findings, profile)
    assert [f.change_difficulty for f, _ in wins] == [1, 1]
    assert wins[0][0].weakness == 5


def test_report_counts_high_risk():
    profile = Profile()  # defaults 3: risk 4*27=108 is high
    report = build_report([_finding(4), _finding(3),
                           _finding(5, difficulty=1)], profile, "t")
    assert report["total_findings"] == 3
    assert report["high_risk"] == 2
    assert report["quick_wins"] == 1
    assert len(report["top"]) == 3
