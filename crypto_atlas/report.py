"""The ranked report: the top 10 things to fix, with the evidence.

Markdown for humans, JSON for CI. Every finding shows its risk
score, the four weights, file:line, the snippet, and the fix.
"""
from __future__ import annotations

import json

from .findings import Finding
from .ranking import Profile, quick_wins, ranked, risk


def build_report(findings: list[Finding], profile: Profile,
                 target: str) -> dict:
    """The report as data (shared by the Markdown and JSON forms)."""
    ordered = ranked(findings, profile)
    wins = quick_wins(findings, profile)
    return {
        "target": target,
        "total_findings": len(findings),
        "high_risk": sum(1 for _, r in ordered if r >= 108),
        "quick_wins": len(wins),
        "top": [
            {"rule_id": f.rule_id, "algorithm": f.algorithm,
             "risk": r, "weakness": f.weakness,
             "lifetime": profile.lifetime,
             "exposure": profile.exposure,
             "sensitivity": profile.sensitivity,
             "file": f.file, "line": f.line, "snippet": f.snippet,
             "evidence": f.evidence, "fix": f.fix}
            for f, r in ordered[:10]
        ],
        "quick_win_list": [
            {"rule_id": f.rule_id, "algorithm": f.algorithm,
             "risk": r, "file": f.file, "line": f.line,
             "fix": f.fix}
            for f, r in wins
        ],
    }


def render_markdown(report: dict) -> str:
    lines = [
        f"# Crypto Atlas report — {report['target']}",
        "",
        f"{report['total_findings']} findings, "
        f"{report['high_risk']} high risk, "
        f"{report['quick_wins']} quick wins.",
        "",
        "## Top 10 things to fix",
        "",
    ]
    if not report["top"]:
        lines.append("No findings. Nothing to fix.")
    for i, item in enumerate(report["top"], 1):
        lines += [
            f"{i}. **{item['algorithm']}** — risk {item['risk']} "
            f"({item['file']}:{item['line']})",
            f"   {item['evidence']}",
            f"   `{item['snippet']}`",
            f"   Fix: {item['fix']}",
            "",
        ]
    if report["quick_win_list"]:
        lines += ["## Quick wins", ""]
        for item in report["quick_win_list"]:
            lines.append(
                f"- **{item['algorithm']}** — risk {item['risk']} "
                f"({item['file']}:{item['line']}): {item['fix']}")
        lines.append("")
    lines.append(
        "Risk = weakness x lifetime x exposure x sensitivity. "
        "Defaults are 3 (unknown = middle); pass --profile to set "
        "them for your data.")
    return "\n".join(lines)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2)
