"""Risk ranking: what to fix first.

Risk = weakness x lifetime x exposure x sensitivity, each 1-5
(max 625). The weights live in a profile the user can edit; the
defaults are 3 (unknown = middle, honestly). Quick wins are high
risk with a one-line fix.

Data-lifetime weighting: the profile can override the weights per
rule, so a finding that protects long-lived data ranks above one
that protects a short-lived session. A hardcoded encryption key
that guards records for 15+ years gets lifetime 5; a TLS finding
on a short-lived session gets lifetime 2. See profile.example.json.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .findings import Finding


@dataclass
class Profile:
    """The sensitivity profile: how much the scanned code's data
    matters, how long it must stay secret, and how exposed it is.
    Defaults are 3 — unknown, honestly middle. ``rules`` overrides
    the three weights per rule, so data lifetime can be weighted
    by what the finding protects."""
    lifetime: int = 3  # 5 = 15+ years, 1 = under a year
    exposure: int = 3  # 5 = internet-facing, 1 = offline
    sensitivity: int = 3  # 5 = PII / financial / health / secrets
    rules: dict[str, dict[str, int]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        return cls(
            lifetime=int(data.get("lifetime", 3)),
            exposure=int(data.get("exposure", 3)),
            sensitivity=int(data.get("sensitivity", 3)),
            rules={rule_id: {key: int(value)
                             for key, value in override.items()}
                   for rule_id, override
                   in data.get("rules", {}).items()},
        )

    def weights_for(self, rule_id: str) -> tuple[int, int, int]:
        """(lifetime, exposure, sensitivity) for this rule: the
        per-rule override when the profile sets one, else the
        global weights."""
        override = self.rules.get(rule_id, {})
        return (override.get("lifetime", self.lifetime),
                override.get("exposure", self.exposure),
                override.get("sensitivity", self.sensitivity))


def risk(finding: Finding, profile: Profile) -> int:
    lifetime, exposure, sensitivity = profile.weights_for(
        finding.rule_id)
    return finding.weakness * lifetime * exposure * sensitivity


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
