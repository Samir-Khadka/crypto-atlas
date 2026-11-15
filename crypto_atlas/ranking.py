"""Risk ranking: what to fix first.

Risk = weakness x lifetime x exposure x sensitivity, each 1-5
(max 625). The weights live in a profile the user can edit; the
defaults are 3 (unknown = middle, honestly). Quick wins are high
risk with a one-line fix.
"""
from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding


@dataclass
class Profile:
    """The sensitivity profile: how much the scanned code's data
    matters, how long it must stay secret, and how exposed it is.
    Defaults are 3 — unknown, honestly middle."""
    lifetime: int = 3  # 5 = 15+ years, 1 = under a year
    exposure: int = 3  # 5 = internet-facing, 1 = offline
    sensitivity: int = 3  # 5 = PII / financial / health / secrets

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        return cls(
            lifetime=int(data.get("lifetime", 3)),
            exposure=int(data.get("exposure", 3)),
            sensitivity=int(data.get("sensitivity", 3)),
        )


def risk(finding: Finding, profile: Profile) -> int:
    return (finding.weakness * profile.lifetime * profile.exposure
            * profile.sensitivity)


def ranked(findings: list[Finding],
           profile: Profile) -> list[tuple[Finding, int]]:
    """Findings sorted by risk, highest first."""
    scored = [(f, risk(f, profile)) for f in findings]
    scored.sort(key=lambda pair: (-pair[1], pair[0].file, pair[0].line))
    return scored


def quick_wins(findings: list[Finding], profile: Profile,
               limit: int = 5) -> list[tuple[Finding, int]]:
    """High risk, one-line fix — the first things to do."""
    wins = [(f, risk(f, profile)) for f in findings
            if f.change_difficulty == 1]
    wins.sort(key=lambda pair: -pair[1])
    return wins[:limit]
