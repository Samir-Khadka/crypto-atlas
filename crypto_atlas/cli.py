"""The CLI: one command, no server, no account.

``crypto-atlas scan <path>`` — writes cbom.json and report.md into
the output directory (or prints the report to stdout).

Exit codes: 0 = clean or only informational findings; 1 = a finding
at or above the fail threshold (default: weakness 4, i.e.
quantum-vulnerable or broken); 2 = the scan failed.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .cbom import write_cbom
from .ranking import Profile
from .report import build_report, render_json, render_markdown
from .scanner import scan_target


def _load_profile(path: str | None) -> Profile:
    if not path:
        return Profile()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Profile.from_dict(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="crypto-atlas",
        description="Find where cryptography lives, build a CBOM, "
                    "rank what to fix first.")
    parser.add_argument("--version", action="version",
                        version=f"crypto-atlas {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", choices=("cbom", "report", "json",
                                           "all"),
                      default="all",
                      help="what to output (default: all)")
    scan.add_argument("--output", default=".",
                      help="directory for cbom.json and report.md")
    scan.add_argument("--profile",
                      help="JSON file with lifetime / exposure / "
                           "sensitivity (each 1-5)")
    scan.add_argument("--fail-on", type=int, default=4,
                      help="exit 1 when a finding has weakness >= N "
                           "(default: 4)")

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        profile = _load_profile(args.profile)
    except (OSError, ValueError, KeyError) as exc:
        print(f"crypto-atlas: cannot read profile: {exc}",
              file=sys.stderr)
        return 2

    try:
        findings, files = scan_target(args.path)
    except OSError as exc:
        print(f"crypto-atlas: cannot scan {args.path}: {exc}",
              file=sys.stderr)
        return 2

    report = build_report(findings, profile, args.path)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    if args.format in ("cbom", "all"):
        try:
            write_cbom(findings, args.path, out / "cbom.json")
        except ValueError as exc:
            print(f"crypto-atlas: {exc}", file=sys.stderr)
            return 2
    if args.format in ("report", "all"):
        (out / "report.md").write_text(render_markdown(report),
                                       encoding="utf-8")
    if args.format in ("json", "all"):
        print(render_json(report))
    elif args.format == "report":
        print(render_markdown(report))

    worst = max((f.weakness for f in findings), default=0)
    print(f"crypto-atlas: {len(findings)} findings in {files} files "
          f"({report['high_risk']} high risk, "
          f"{report['quick_wins']} quick wins)",
          file=sys.stderr)
    return 1 if worst >= args.fail_on else 0


if __name__ == "__main__":
    sys.exit(main())
