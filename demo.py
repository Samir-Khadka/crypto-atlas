"""Demo: scan Crypto Atlas itself, then Kavach and Agent Gateway,
and probe a local TLS server plus a real domain.

Run: python demo.py

The real-domain probe goes through this sandbox's egress proxy,
which terminates TLS and re-issues certificates — so the version,
cipher, and certificate shown for a real domain are the proxy's,
not the destination's. The local server is the honest demo of
what the scanner sees on a direct connection.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from crypto_atlas.ranking import Profile
from crypto_atlas.report import build_report
from crypto_atlas.scanner import scan_target
from crypto_atlas.tls_scanner import scan_domain

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

    # Java: scan the Java fixtures (true positives + clean)
    from crypto_atlas.scanners.java_scanner import scan_java
    for name in ("java_crypto.java", "java_clean.java"):
        path = Path(__file__).parent / "tests" / "fixtures" / name
        findings = scan_java(name, path.read_text(encoding="utf-8"))
        print(f"--- Java {name}: {len(findings)} findings")
        for item in build_report(findings, profile, name)["top"][:4]:
            print(f"    risk {item['risk']:>3}  {item['algorithm']:<10} "
                  f"{item['file']}:{item['line']} — {item['evidence']}")

    # TLS: a local server we control (TLS 1.2 only, RSA-2048 cert)
    from tests.test_tls_scanner import TLSTestServer
    with TLSTestServer() as server:
        findings, summary = scan_domain("127.0.0.1", server.port)
        print(f"--- TLS local server (TLS 1.2 only, RSA-2048): "
              f"{len(findings)} findings")
        print(f"    versions offered: {sorted(summary['versions'])}")
        print(f"    leaf cert: {summary['leaf_cert']['key_type']}-"
              f"{summary['leaf_cert']['key_size']}, "
              f"signed with {summary['leaf_cert']['signature_algorithm']}")
        print(f"    PQ: {summary['pq']['status']} — "
              f"{summary['pq']['reason']}")
        print(f"    untested ciphers: {summary['untested_ciphers']}")

    # TLS: a real domain (through the sandbox proxy — see the
    # note at the top of this file)
    try:
        findings, summary = scan_domain("github.com", 443)
        print(f"--- TLS github.com (via sandbox proxy): "
              f"{len(findings)} findings")
        print(f"    versions offered: {sorted(summary['versions'])}")
        print(f"    leaf cert: {summary['leaf_cert']['key_type']}-"
              f"{summary['leaf_cert']['key_size']}, issuer "
              f"{summary['leaf_cert']['issuer']}")
        print(f"    PQ: {summary['pq']['status']}")
    except OSError as exc:
        print(f"--- TLS github.com: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
