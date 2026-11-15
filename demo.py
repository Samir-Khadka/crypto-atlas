"""Demo: scan Crypto Atlas itself, then Kavach and Agent Gateway,
and print the ranked findings.

Run: python demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from crypto_atlas.ranking import Profile
from crypto_atlas.report import build_report, render_markdown
from crypto_atlas.scanner import scan_target

TARGETS = [
    # the scanner's own code (the test fixtures are intentionally
    # full of weak crypto, so they are not part of the self-scan)
    ("crypto-atlas (itself)", Path(__file__).parent / "crypto_atlas"),
    ("kavach", Path.home() / "workspace" / "kavach"),
    ("agent-gateway", Path.home() / "workspace" / "agent-gateway"),
]

def main() -> int:
    profile = Profile()
    for name, target in TARGETS:
        if not target.exists():
            print(f"--- {name}: not present, skipped")
            continue
        findings, files = scan_target(str(target))
        report = build_report(findings, profile, name)
        print(f"--- {name}: {len(findings)} findings in {files} files "
              f"({report['high_risk']} high risk, "
              f"{report['quick_wins']} quick wins)")
        for item in report["top"][:5]:
            print(f"    risk {item['risk']:>3}  {item['algorithm']:<10} "
                  f"{item['file']}:{item['line']} — {item['evidence']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
