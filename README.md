# Crypto Atlas

A developer-friendly, open-source-first cryptographic inventory:
find every place cryptography is used — in code, configs,
certificates, and live endpoints — build a CBOM (cryptographic bill
of materials), rank what to fix first, and prove the migration to
post-quantum cryptography.

**Status: v0.3.0** — the code scanner (Python, JS/TS, Go, Java),
plus the TLS scanner. MIT licensed, CI green on Python 3.11 and
3.12.

## Why

The hard part of post-quantum migration is not the new algorithms.
The standards exist (NIST finalized FIPS 203/204/205 in Aug 2024).
The hard part is knowing where cryptography is used at all. Most
companies cannot answer "where do we use RSA?" Without that answer
they cannot plan, prioritize, or prove compliance — and the
deadlines are now published: NIST IR 8547 (final Oct 2026) deprecates
RSA/ECC after 2030 and disallows them after 2035; the EU and UK
roadmaps target full transition by 2035.

## Quickstart

```bash
git clone https://github.com/Samir-Khadka/crypto-atlas
cd crypto-atlas
pip install -r requirements.txt
python -m crypto_atlas scan /path/to/your/repo
```

That writes `cbom.json` (CycloneDX 1.7, validated against the 1.7
JSON schema) and `report.md` (the ranked top 10 things to fix) into
the current directory. Exit code 0 = clean, 1 = a finding at or
above the fail threshold, 2 = the scan failed.

## What v0.2 adds: the TLS scanner

```bash
python -m crypto_atlas tls example.com example.org
python -m crypto_atlas tls --file domains.txt
```

For each endpoint it reports which TLS versions it accepts, which
cipher suites it accepts, the leaf certificate's key type and
signature algorithm, and whether it negotiates the hybrid
post-quantum group X25519MLKEM768. Output is the same CBOM +
report pair, with `protocol` and `certificate` assets.

Two honest limits:

- **PQ-readiness needs OpenSSL 3.5 or later in the runtime.** On
  an older runtime the check reports `unknown` instead of
  guessing. The code is ready; the runtime is the gate.
- **Broken ciphers (RC4, DES, 3DES, NULL) live in OpenSSL's
  legacy provider**, which most runtimes do not load. On such a
  runtime the probe reports them as `untested`, not as clean.
  Deprecated CBC ciphers (AES128-SHA, AES256-SHA) are testable
  anywhere and are reported at weakness 3.
- **In a network that terminates TLS** (a corporate proxy, or a
  sandbox egress proxy), the version, cipher, and certificate are
  the proxy's, not the destination's. The report says so when it
  detects a proxy in use.
- **The scanner flags its own inspection code.** `tls_scanner.py`
  disables verification on purpose — an inspector has to read
  self-signed and expired certificates, not trust them. Same
  reason as Kavach's scanner. The finding is correct; the code is
  deliberate.

## What v0.1 finds

| Rule | What it catches |
|---|---|
| RSA / ECC key generation | Every RSA/ECC key pair generated, graded by size/curve (RSA <2048 is weakness 5, RSA-2048 is 4, RSA-4096 is 3) |
| Weak hash | MD5, SHA1 (with the note that a file checksum is safe to ignore) |
| Weak cipher / mode | DES, 3DES, RC4, AES-ECB |
| Weak randomness | `random` / `Math.random` / `math/rand` used for a key, token, or password |
| Hardcoded key / IV | A key written directly in the code |
| TLS disabled / old version | `CERT_NONE`, `rejectUnauthorized: false`, `InsecureSkipVerify`, TLS 1.0/1.1, weak nginx cipher lists, RSA/ECC certificates and keys |
| Post-quantum | ML-KEM / ML-DSA / SLH-DSA already in use — recorded as migrated, not as a problem |

Languages: Python (via `ast`), JavaScript/TypeScript, Go and Java
(via tree-sitter), plus nginx/Apache configs and PEM certificates.

## Ranking

Risk = weakness × lifetime × exposure × sensitivity, each 1–5.
Defaults are 3 (unknown = middle, honestly). Pass `--profile` with
a JSON file to set them for your data — see `profile.example.json`.
Quick wins — high risk with a one-line fix — are listed separately.

The three weights mean:

- **lifetime** — how long the protected data must stay secret.
  5 = 15+ years (medical records, identity documents, anything
  an attacker could decrypt later and still use); 1 = under a
  year. This is the "harvest now, decrypt later" weight: data
  that must stay secret for 15+ years ranks first, because a
  quantum computer in 2035 breaks what is recorded today.
- **exposure** — 5 = internet-facing, 1 = offline.
- **sensitivity** — 5 = PII, financial, health, or secrets.

The `rules` section overrides the weights per rule, so data
lifetime is weighted by what the finding protects. In the example,
a hardcoded key gets lifetime 5 (it guards long-lived data) while
a TLS finding gets lifetime 2 (a short-lived session). A finding's
risk is its weakness times the weights that apply to it.

## Accuracy

Every rule ships with a labeled test corpus: true positives and
known false-positive traps. The false-positive budget is under 5%
on the demo corpus, measured and reported, not claimed. Every
finding carries its evidence (file, line, snippet, and why it
fired), so a developer can judge it in seconds.

## Roadmap

- **v0.2** — TLS scanner: endpoint inventory and PQ-readiness
  (does the server negotiate hybrid X25519MLKEM768?) — **done**
- **v0.3** — Risk ranking with data-lifetime weighting (per-rule
  profile overrides, documented in `profile.example.json`); Java
  as the fourth language — **done**
- **v0.4** — Auto-remediation: pull requests for common fixes
- **v0.5** — Compliance reports mapped to NIST IR 8547, CNSA 2.0,
  the EU Roadmap, and the UK NCSC timeline; GitHub Action
- **v0.6+** — Hardware and vendor inventory

The full plan is in `PLAN.md`.

## How it differs

The open-source inventory already exists (the PQCA CBOM Kit). What
Crypto Atlas adds is ranking, the fix (a pull request for the common
cases), and no server to install — one CLI, one GitHub Action. The
category has solved finding; it has not solved proving.
