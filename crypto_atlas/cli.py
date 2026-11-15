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
from .findings import Finding
from .ranking import Profile
from .report import build_report, render_json, render_markdown
from .scanner import scan_target


def _load_profile(path: str | None) -> Profile:
    if not path:
        return Profile()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Profile.from_dict(data)


def _parse_domains(args) -> list[tuple[str, int]]:
    """Domains from the command line and/or a file. Each entry is
    host or host:port; the file is one per line, # comments."""
    domains: list[tuple[str, int]] = []
    for entry in args.domains:
        domains.append(_split_host_port(entry))
    if args.file:
        for line in Path(args.file).read_text(
                encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(_split_host_port(line))
    return domains


def _split_host_port(entry: str) -> tuple[str, int]:
    if ":" in entry and not entry.startswith("["):
        host, _, port = entry.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return entry, 443


def _run_tls(args) -> int:
    from .tls_scanner import scan_domain
    try:
        profile = _load_profile(args.profile)
    except (OSError, ValueError, KeyError) as exc:
        print(f"crypto-atlas: cannot read profile: {exc}",
              file=sys.stderr)
        return 2
    domains = _parse_domains(args)
    if not domains:
        print("crypto-atlas: no domains given", file=sys.stderr)
        return 2
    findings: list[Finding] = []
    summaries = []
    for host, port in domains:
        try:
            found, summary = scan_domain(host, port, args.timeout)
        except OSError as exc:
            print(f"crypto-atlas: {exc}", file=sys.stderr)
            return 2
        findings += found
        summaries.append(summary)
    target = ", ".join(s["target"] for s in summaries)
    report = build_report(findings, profile, target)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    if args.format in ("cbom", "all"):
        try:
            write_cbom(findings, target, out / "cbom.json")
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
    for summary in summaries:
        pq = summary["pq"]
        proxied = " (via proxy — the version, cipher, and "
        proxied += "certificate are the proxy's, not the "
        proxied += "destination's)" if summary["proxied"] else ""
        print(f"crypto-atlas: {summary['target']}: versions "
              f"{sorted(summary['versions'])}; "
              f"PQ: {pq['status']}{proxied}", file=sys.stderr)
    worst = max((f.weakness for f in findings), default=0)
    return 1 if worst >= args.fail_on else 0


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

    tls = sub.add_parser("tls", help="scan live TLS endpoints")
    tls.add_argument("domains", nargs="*", help="host or host:port")
    tls.add_argument("--file",
                     help="file with one host or host:port per line")
    tls.add_argument("--timeout", type=float, default=10.0,
                     help="seconds per connection attempt")
    tls.add_argument("--format", choices=("cbom", "report", "json",
                                          "all"),
                     default="all",
                     help="what to output (default: all)")
    tls.add_argument("--output", default=".",
                     help="directory for cbom.json and report.md")
    tls.add_argument("--profile",
                     help="JSON file with lifetime / exposure / "
                          "sensitivity (each 1-5)")
    tls.add_argument("--fail-on", type=int, default=4,
                     help="exit 1 when a finding has weakness >= N "
                          "(default: 4)")

    args = parser.parse_args(argv)
    if args.command == "tls":
        return _run_tls(args)
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
