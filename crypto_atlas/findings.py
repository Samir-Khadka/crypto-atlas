"""One finding: a single place where cryptography is used.

Every finding carries its evidence (file, line, snippet, and why it
fired), so a developer can judge it in seconds. A finding without
evidence is not a finding.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    rule_id: str
    algorithm: str
    weakness: int  # 1-5, per the plan's scale
    file: str  # path relative to the scan root
    line: int
    snippet: str  # the code line that fired
    evidence: str  # why this fired, in one sentence
    fix: str  # the fix, in one line
    language: str  # python | javascript | go | config
    key_size: int | None = None
    curve: str | None = None
    change_difficulty: int = 2  # 1 = one-liner, 5 = hardware/vendor
    asset_type: str = "algorithm"  # algorithm | certificate |
    # protocol | related-crypto-material
    primitive: str | None = None  # CycloneDX primitive, when known
    parameter_set: str | None = None  # e.g. "RSA-2048", "P-256"
