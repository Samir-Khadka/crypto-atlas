# Crypto Atlas

A developer-friendly, open-source-first cryptographic inventory:
find every place cryptography is used — in code, configs,
certificates, and live endpoints — build a CBOM (cryptographic bill
of materials), rank what to fix first, and prove the migration to
post-quantum cryptography.

**Status: v0.1.0** — the code scanner. MIT licensed, CI green on
Python 3.11 and 3.12.

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

Languages: Python (via `ast`), JavaScript/TypeScript and Go (via
tree-sitter), plus nginx/Apache configs and PEM certificates.

## Ranking

Risk = weakness × lifetime × exposure × sensitivity, each 1–5.
Defaults are 3 (unknown = middle, honestly). Pass `--profile` with
a JSON file to set them for your data. Quick wins — high risk with
a one-line fix — are listed separately.

## Accuracy

Every rule ships with a labeled test corpus: true positives and
known false-positive traps. The false-positive budget is under 5%
on the demo corpus, measured and reported, not claimed. Every
finding carries its evidence (file, line, snippet, and why it
fired), so a developer can judge it in seconds.

## Roadmap

- **v0.2** — TLS scanner: endpoint inventory and PQ-readiness
  (does the server negotiate hybrid X25519MLKEM768?)
- **v0.3** — Risk ranking with data-lifetime weighting; Java as
  the fourth language
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
