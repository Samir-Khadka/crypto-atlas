# Crypto Atlas — full plan

**Working name.** "Crypto Atlas" is a working name; the final name is
one of the open decisions at the end.

**One line.** A developer-friendly, open-source-first cryptographic
inventory: find every place cryptography is used — in code, configs,
certificates, and live endpoints — build a CBOM (cryptographic bill
of materials), rank what to fix first, and prove the migration to
post-quantum cryptography.

**Status.** Plan v1.0, 15 Nov 2026. All dates and competitor claims in
this document were verified against primary or vendor sources on
15 Nov 2026; the sources are listed at the end. Nothing is built yet.

## The problem

The hard part of post-quantum migration is not the new algorithms.
The standards exist. The hard part is knowing where cryptography is
used at all. It is buried in source code, third-party libraries, TLS
endpoints, certificates, VPNs, hardware security modules, databases,
embedded devices, and vendor products. Most companies cannot answer
"where do we use RSA?" Without that answer they cannot plan,
prioritize, or prove compliance.

The real problem is inventory. Everything else — the new algorithms,
the migration guides, the compliance reports — depends on it.

## Why now

The standards are final, the deadlines are published, and the
deadlines are no longer drafts.

| Date | Source | What happens |
|---|---|---|
| 13 Aug 2024 | NIST | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) finalized — the first post-quantum standards |
| Nov 2022 | White House (OMB M-23-02) | US federal agencies must inventory their cryptographic systems |
| May 2022 | White House (NSM-10) | National goal: mitigate as much quantum risk as feasible by 2035 |
| Sep 2022, updated 30 May 2025 | NSA (CNSA 2.0) | New national security system acquisitions must support PQC from 1 Jan 2027; software/firmware signing and networking exclusive by 2030; browsers, servers, cloud exclusive by 2033 |
| 23 Jun 2025 | EU (NIS Cooperation Group, ENISA) | Coordinated Implementation Roadmap: national transition roadmaps by end 2026; high-risk systems and critical infrastructure migrated by end 2030; full transition by 2035 (scope: NIS2, CRA, DORA) |
| 20 Mar 2025 | UK (NCSC) | Discovery and planning complete by 2028; high-priority migrations by 2031; all systems by 2035 |
| 27 Oct 2026 | NIST (IR 8547, final) | RSA and ECC deprecated after 2030, disallowed after 2035 |
| 27 Oct 2026 | IBM | IBM Quantum Safe suite announced (see competitors) |
| Jun 2026 | White House (EO 14412) | Federal key establishment on NIST-approved PQC by 31 Dec 2030; digital signatures by 31 Dec 2031; federal contractors to comply by end 2030 |
| Mar 2025 | NIST | HQC selected as a backup KEM (NIST IR 8545); FN-DSA (FIPS 206) still in development |

Three things make this urgent already, not in 2030:

- **Harvest now, decrypt later.** Attackers can record encrypted
  traffic today and decrypt it once quantum computers are capable.
  Data with a 15+ year lifetime (health records, state secrets,
  long-term contracts) is already exposed.
- **Migrations take 5–10 years.** The industry consensus, confirmed
  by NIST, ENISA, NCSC, and the major consultancies, is that a full
  enterprise migration takes five to ten years. An organisation
  starting in 2026 finishes between 2031 and 2036 — inside the
  deadline window, with no slack.
- **The inventory is the long pole.** The UK NCSC's first phase is
  discovery and planning, ending 2028. The EU's first milestone is
  national roadmaps by end 2026. Every jurisdiction's timeline
  starts with "find it", and that is the step most organisations
  have not done.

Two more facts that matter for the build: OpenSSL 3.5 ships all
three NIST algorithms and offers the hybrid X25519MLKEM768 group by
default in TLS 1.3, so post-quantum readiness is testable in
practice today, not in theory. And EO 14412 directs CISA and NIST to
publish guidance on the minimum elements of a CBOM on a fixed
deadline — the CBOM is becoming the federal inventory format, not
just a nice output.

## Who else is in this space

Verified 15 Nov 2026 against vendor documentation and independent
round-ups. The market is crowded at the top end and the category is
maturing fast — which is both the risk and the proof of demand.

| Vendor | What it does | What it costs you |
|---|---|---|
| **IBM Quantum Safe** (announced 27 Oct 2026; built on Guardium Cryptography Manager, 2025) | Three parts: Cryptography Manager (discovers assets, tracks migration), Explorer (scans source code for crypto, vulnerabilities, crypto-agility anti-patterns; generates CBOMs), Proxy (traffic between legacy and PQ clients/servers). IBM co-authored the CBOM spec. | Enterprise suite, enterprise pricing, long sales cycle. The closest direct competitor to the wedge — Explorer already scans code and emits CBOMs. |
| **SandboxAQ AQtive Guard** | Deep TLS traffic analysis (live or PCAP, hybrid and PQC groups), many data-source integrations, Impact Assessment simulation, MCP server, FedRAMP Ready. Strongest on TLS traffic. | Enterprise platform; strongest on network traffic, weaker on code and dependencies. |
| **Keyfactor AgileSec + Command** | Broadest discovery: code, binaries, containers, Artifactory, three clouds' KMS, HSMs via PKCS#11. CBOM export in CycloneDX 1.6 (verified Jul 2026). Links to Command and EJBCA for certificates. | Enterprise PKI vendor; certificate-centric; long sales cycle. |
| **Venafi TLS Protect PQC** (Venafi was acquired by CyberArk in 2024; Palo Alto Networks announced the CyberArk acquisition in 2025) | Certificate and machine-identity discovery, PQC readiness. | Certificate-centric; weakest on code. |
| **QuSecure QuProtect** | Software overlay: Recon (inventory), Resilience (moves live traffic to ML-KEM/ML-DSA), Reporting (CycloneDX CBOM). Crypto-agility without re-architecting; Accenture Ventures stake Jan 2025; Banco Sabadell case study (4,000-service cipher rotation). SaaS edition Q1 2026. | Subscription, scales with bandwidth; a network overlay, not a code scanner. |
| **PQShield** | Silicon IP + software SDK (PQCryptoLib, TLS plug-in). Libraries and chips. | Not a discovery platform at all — a different layer of the stack. |
| **AppViewX Quantum Trust Hub** | Assessment scanning code, packages, dependencies. Top-scored (7.58) in the PQC Discovery Index 2026.5. | Enterprise platform. |
| **Fortanix Key Insight / PQC Central** | Multi-cloud key discovery, CycloneDX CBOM, readiness score. | Key-centric; cloud KMS focus. |
| **DuoKey** | Live PQ key-exchange probing, STARTTLS and database TLS coverage, CycloneDX 1.7 CBOM, free entry point. | Smaller vendor; narrowest discovery surface. |
| **PQCA CBOM Kit** (formerly IBM, now under the Post-Quantum Cryptography Alliance) | **Open source.** `sonar-cryptography` (SonarQube plugin that finds crypto in source) + `cbomkit-theia` (Go CLI that finds certs, keys, and configs in container images and directories). Emits CycloneDX 1.6 CBOMs. | Free, but needs a SonarQube server for the code half, and it only inventories — it does not rank or remediate. |

Two findings shape the whole plan:

1. **The open-source inventory already exists.** The PQCA CBOM Kit
   is free and does code + image scanning. "Open-source code
   scanning" alone is not a wedge any more. The wedge has to be
   what CBOM Kit does not do: **rank** the findings, **open the
   fix**, and do it with **no server to install** — one CLI, one
   GitHub Action.
2. **The category has solved finding. It has not solved proving.**
   That is the PQC Discovery Index 2026.5's own conclusion (14
   products scored on 7 criteria; AppViewX 7.58, IBM 7.39,
   Keyfactor 7.37 at the top — the index is conflict-disclosed and
   sponsored by a vendor in the category, so treat the scores as
   directional, not gospel). Every vendor finds crypto. None of
   them tells you what to fix first, opens the fix for you, or
   proves the migration is complete. That is the gap.

## The gap

Developer-friendly, open-source-first, code-aware inventory with
prioritized, automated remediation. Specifically:

- **Code-aware, not just certificate-aware.** The big vendors are
  strongest on certificates and network scanning and weakest on
  code and dependencies. The code is where the migration work
  actually lives.
- **Ranked, not listed.** A report that lists 400 findings is a
  chore. A report that says "fix these 10 first, in this order,
  because they protect data that must last 15 years and face the
  internet" is a plan.
- **Remediation, not just reporting.** The fix is part of the
  product: a pull request for the common cases, a step-by-step
  guide for the rest.
- **No server to install.** One CLI, one GitHub Action. The
  enterprise tools need a platform, a procurement cycle, and a
  security review before they find a single RSA key. Crypto Atlas
  finds one in five minutes.

## Product: Crypto Atlas

Five pillars, in order. Each one is a real deliverable, not a
slogan.

### 1. Discover

Scan repositories, container images, dependencies, configs,
certificates, and live TLS endpoints. v0.1 covers repositories and
configs; container images and live endpoints follow in Phase 2;
hardware and vendor products in Phase 6.

### 2. Inventory

Build a CBOM — the cryptographic bill of materials, the crypto
equivalent of an SBOM. The format is **CycloneDX**: version 1.6
added CBOM support (April 2024, also published as ECMA-424), and
**1.7** extends it (algorithm families, a registry of elliptic
curves, richer certificate lifecycle fields). Crypto Atlas targets
**1.7 with 1.6 compatibility** — emit 1.7, validate against the
1.7 JSON schema, and keep the 1.6 field set intact so 1.6 consumers
can read it.

Each cryptographic item is a component of type
`cryptographic-asset` with a `cryptoProperties` object. The
`assetType` is one of four:

| assetType | Property block | Main fields |
|---|---|---|
| `algorithm` | `algorithmProperties` | `primitive` (signature, kem, key-agree, block-cipher, hash), `parameterSetIdentifier`, `curve`, `mode`, `padding`, `cryptoFunctions`, `executionEnvironment`, `classicalSecurityLevel`, `nistQuantumSecurityLevel` (0–6; 0 = no security against a quantum attacker) |
| `certificate` | `certificateProperties` | `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `certificateFormat` |
| `related-crypto-material` | `relatedCryptoMaterialProperties` | `type` (private-key, public-key, secret-key), `size`, `state`, `algorithmRef`, `securedBy` |
| `protocol` | `protocolProperties` | `type` (tls, ssh, ipsec, ike), `version`, `cipherSuites`, `ikev2TransformTypes` |

Every finding carries its evidence: file path, line number, and the
code snippet. A finding without evidence is not a finding.

### 3. Risk-rank

Score each finding by algorithm weakness, data sensitivity and
lifetime, exposure, and how hard it is to change. The formula is
explicit and configurable, not a black box:

- **Weakness (1–5).** 5 = broken today (MD5, DES, RC4, RSA <1024);
  4 = quantum-vulnerable and deprecated soon (RSA-2048, ECC P-256);
  3 = quantum-vulnerable but stronger (RSA-4096, ECC P-384);
  2 = post-quantum with weak parameters; 1 = a NIST standard at
  recommended parameters (ML-KEM-768+).
- **Lifetime (1–5).** 5 = data must stay secret 15+ years; 4 =
  10–15; 3 = 5–10; 2 = 1–5; 1 = under a year. This is the
  harvest-now-decrypt-later weight: long-lived data ranks first.
- **Exposure (1–5).** 5 = internet-facing; 4 = partner-facing;
  3 = internal network; 2 = localhost; 1 = offline or cold.
- **Sensitivity (1–5).** From a configurable profile: PII,
  financial, health, secrets, public. The profile ships with sane
  defaults and the user overrides it in one file.
- **Change difficulty (1–5).** 5 = hardware, firmware, or
  vendor-locked; 1 = a one-line config change.

**Risk = weakness × lifetime × exposure × sensitivity** (max 625).
The report sorts by risk, and flags **quick wins** separately:
high risk with low change difficulty. The weights live in a profile
file the user can edit; the default profile is documented and its
reasoning is in the README, so a CISO can argue with it.

### 4. Migrate

Generate pull requests or step-by-step guides. The common cases
get a PR: moving key exchange to hybrid (classical plus ML-KEM) in
a TLS config or library, bumping an RSA key size, replacing MD5/SHA1
with SHA-256, swapping `random` for `secrets`. The uncommon cases
get a guide with the exact commands. Nothing is auto-merged; the
human approves every change.

### 5. Prove

Compliance reports and a continuous monitor. The reports map
findings to the guidance that matters: NIST IR 8547, CNSA 2.0, the
EU Coordinated Roadmap, the UK NCSC timeline. The monitor re-scans
on every push and alerts when new weak crypto appears — so the
inventory never goes stale the week after the audit.

## Wedge MVP: find weak crypto in your repos and endpoints

A CLI and a GitHub Action that scans a repo for crypto usage and a
TLS scanner that checks a list of domains. Output: a CBOM file plus
a ranked report ("top 10 things to fix"). This is buildable by one
person, easy to demo on any open-source project, and genuinely
useful on day one.

### v0.1 — the code scanner (Phase 1)

**Command.** `crypto-atlas scan <path>` — one command, no server,
no account. `--format cbom|report|json`. `--output` for the CBOM
file. Exit code 0 = clean or only informational, 1 = findings
above the configured threshold, 2 = scan failed.

**Languages (v0.1): Python, JavaScript/TypeScript, Go.** These
three cover Samir's own stack and the most common crypto APIs.
Java is the obvious fourth (enterprise codebases are Java-heavy)
and is the first Phase 3 extension, not a v0.1 scope creep.

**Rules (v0.1): high-confidence only.** False positives make
developers ignore the tool, so every rule starts narrow and earns
breadth. Each rule ships with a labeled test corpus: true
positives and known false-positive traps.

| # | Rule | Python | JavaScript / TypeScript | Go |
|---|---|---|---|---|
| 1 | RSA key generation (record; flag <2048) | `cryptography` RSA.generate_private_key, `Crypto.PublicKey.RSA.generate` | `crypto.generateKeyPair('rsa')`, WebCrypto `generateKey` RSA | `rsa.GenerateKey` |
| 2 | ECC key generation (record; flag <P-256) | `ec.generate_private_key` | `crypto.generateKeyPair('ec')`, WebCrypto EC | `ecdsa.GenerateKey`, `ecdh` |
| 3 | Weak hash (MD5, SHA1) | `hashlib.md5`, `hashlib.sha1` | `crypto.createHash('md5' \| 'sha1')` | `crypto/md5`, `crypto/sha1` |
| 4 | Weak cipher / mode (DES, 3DES, RC4, ECB) | `AES.MODE_ECB`, `DES`, `ARC4` | `createCipheriv` with an `ecb` mode, `createCipher` (deprecated) | `crypto/des`, `crypto/rc4` |
| 5 | Weak randomness for secrets | `random` used for a key, token, or password | `Math.random` for a token or key | `math/rand` for a secret |
| 6 | Hardcoded key / IV | a bytes literal (≥16 bytes) passed directly to a crypto constructor | a string literal passed as a key or IV | a byte slice literal used as a key |
| 7 | Outdated or disabled TLS | `ssl.PROTOCOL_TLSv1`, `CERT_NONE`, `check_hostname=False` | `tls.connect` with `rejectUnauthorized: false`, `minVersion: 'TLSv1'` | `tls.Config{InsecureSkipVerify: true, MinVersion: < TLS 1.2}` |
| 8 | Weak / outdated TLS config files | nginx `ssl_protocols TLSv1 TLSv1.1`; cipher lists containing RC4, DES, 3DES; PEM certificates with RSA <2048 or ECC <P-256 | same | same |

**What v0.1 deliberately does not do.** No dependency scanning
(that is Phase 2, via lockfiles and SBOM import), no binary
scanning, no false-positive suppression learning, no auto-fix.
Each of those is a named later phase, not a v0.1 stretch goal.

**Output.** Two files, every run:

1. `cbom.json` — CycloneDX 1.7, validated against the 1.7 JSON
   schema before it is written. A CBOM that fails schema
   validation is a bug, not an output.
2. `report.md` (and `--format json` for CI) — the ranked top 10,
   each with risk score, the four weights, file:line, the snippet,
   and the fix (one line for a PR-able fix, a link to the guide
   otherwise). Plus a one-line summary: "X findings, Y high risk,
   Z quick wins".

**Demo targets.** Run v0.1 on Samir's own repos first (Kavach,
Agent Gateway, CricScore-v2, Kishan-Bazzar) and publish the
findings as the launch demo, then on one well-known public repo.
Dogfooding is the credibility: the tool found real things in real
code, including his own.

**False-positive budget.** Under 5% on the demo corpus, measured
and reported, not claimed. Every rule's corpus includes the traps:
MD5 used as a non-security checksum, `random` used for a test
fixture, a hardcoded IV in a test vector. A rule that cannot stay
under the budget gets narrowed or dropped.

### v0.2 — the TLS scanner (Phase 2)

`crypto-atlas tls <domains.txt>` — for each domain: TLS versions
offered, cipher suites, certificate chain key types and expiry, and
**PQ-readiness**: offer the hybrid X25519MLKEM768 group (OpenSSL
3.5) and report whether the server negotiates it, plus whether it
presents an ML-DSA certificate (rare now; reported as not-present
when absent). Output is the same CBOM + report pair, with
`protocol` and `certificate` assets.

## Architecture

**Scanner core language: Python.** Samir's strongest language;
`ast` is stdlib and exact for Python; the `cryptography` library
handles certificates; the fastest route to v0.1. Go is the later
option if scan speed demands it — the CLI must scan under 10,000
files in under 60 seconds, and if Python cannot hold that, the
core moves to Go in Phase 3 with the rules ported, not rewritten
from scratch.

**Parsing.** Python via `ast` (stdlib, exact, no grammar to
maintain). JavaScript/TypeScript and Go via tree-sitter
(`tree_sitter` plus the `tree-sitter-javascript` and
`tree-sitter-go` grammars). Semgrep rules are not in v0.1: they add
a dependency and a rule-maintenance burden for coverage the
hand-written rules already give; revisit in Phase 3 if rule
coverage needs it.

**TLS probing.** Python `ssl` plus `cryptography` for certificate
parsing. PQ-readiness needs OpenSSL 3.5 or later in the runtime
(the hybrid group does not exist in older OpenSSL), so the Docker
image and the CI image pin OpenSSL 3.5+ and the README says so.

**Data model.** CycloneDX 1.7 CBOM, stored in SQLite for the CLI
(one file per scan, next to the CBOM). Postgres arrives with the
dashboard (Phase 5 platform), not before — the CLI must work with
no database server.

**Ranking engine.** Rules plus the configurable sensitivity profile
(see the formula above). Pure Python, no model, no network. The
profile file is the only configuration.

**Remediation.** Templated pull requests via the GitHub API
(Phase 4). Guides first (Phase 3): each rule links to a guide
with the exact commands.

**Delivery.** CLI, then GitHub Action, then a web dashboard. The
Action runs the CLI in CI and fails the build above the configured
risk threshold — that is the distribution: it sits in the workflow
developers already run.

## Roadmap

| Phase | Weeks | Deliverable | Exit criteria |
|---|---|---|---|
| 0. Research | 1–2 | Read the NIST and CBOM specs; interview 8–10 security or compliance people; verify competitor offerings; pick the 3 languages and the rule list | The rule list is frozen; the CBOM schema decision (1.7, 1.6-compatible) is written down; at least 3 interviews done or a written reason they were deferred |
| 1. Code scanner | 3–6 | Detect crypto in 3 languages, output CBOM | v0.1: 8 rules, 3 languages, CBOM validates against the 1.7 schema, FP under 5% on the demo corpus, time to first CBOM under 5 minutes from install |
| 2. TLS scanner | 7–8 | Endpoint inventory, PQ-readiness check | v0.2: protocol versions, cipher suites, cert key types, hybrid-group negotiation reported per domain |
| 3. Risk ranking | 9–10 | Prioritized report with data-lifetime weighting | v0.3: the ranking formula implemented, quick wins flagged, profile file documented, Java as the fourth language |
| 4. Auto-remediation | 11–14 | Pull requests for common fixes | v0.4: PRs for the 5 most common fixes (hybrid TLS config, RSA key size, MD5/SHA1, `random` → `secrets`, ECB → GCM), each with a test that the PR applies cleanly |
| 5. Compliance reports | 15–18 | Exportable reports mapped to NIST and regional guidance | v0.5: reports mapped to IR 8547, CNSA 2.0, EU Roadmap, NCSC timeline; GitHub Action in the Marketplace; dashboard (Postgres) behind it |
| 6. Hardware and vendors | 19+ | Inventory for appliances, HSMs, third-party products | Scoped after v0.5, not before — this is where the enterprise vendors live, and it needs their APIs, not just code |

The 18-week scope is Phases 0–5. Phase 6 is deliberately
unscoped: it depends on vendor APIs and hardware access one person
cannot fake.

## Success metrics

The plan's targets, stated so they can be checked:

- **v0.1:** 3 languages, 8 rules, CBOM validates against the
  CycloneDX 1.7 schema, false-positive rate under 5% on the demo
  corpus, time to first CBOM under 5 minutes from install, scan
  under 10,000 files in under 60 seconds.
- **Launch:** open-source repo (MIT), GitHub Action in the
  Marketplace, demo run on 3 public repos with published findings,
  README carrying the verified timeline.
- **Accuracy:** every rule ships with a labeled corpus (true
  positives + known false-positive traps); accuracy is reported per
  rule, in the repo, not claimed in the README.
- **Adoption (first 6 months):** 100 GitHub stars and 10
  non-author repos scanned in CI is the honest early signal that
  developers find it useful. Anything grander is a guess, not a
  target.

## Business model

- **Open-source scanner for adoption and credibility.** MIT
  licensed. The scanner is the marketing: every scan is a demo.
- **Paid platform:** continuous monitoring, multi-repo dashboards,
  compliance exports, SSO, and support. The platform is where the
  money is; the scanner is where the trust is.
- **Services on top:** migration assessments for regulated
  companies, which also fund early development. An assessment is
  the scanner's output plus a human's judgement, sold as a fixed
  engagement.
- **Buyers:** banks, telecoms, healthcare, government contractors,
  and any company with long-lived sensitive data. The pitch is not
  "quantum is coming" — it is "your regulator already set a date,
  and you cannot answer where your RSA is".

## Honest risks

- **Timelines can slip.** Deadlines move, so lead with
  "visibility and risk reduction today", not "quantum is coming
  next year". The inventory is valuable even if every deadline
  slips five years.
- **Crowded with big names at the top end.** IBM's Explorer
  already scans code and emits CBOMs, and the PQCA CBOM Kit is
  free. Win with developer experience and code-level depth they
  do not have: no server to install, ranked findings, and the fix
  opened as a PR. If the wedge cannot beat CBOM Kit on DX, it has
  no wedge — that is the test every version must pass.
- **Accuracy matters.** False positives in code scanning make
  developers ignore you. Start with high-confidence rules, keep
  the 5% budget, and show the evidence on every finding.
- **Real migration is hard and depends on vendors and hardware
  you cannot control.** The inventory and prioritization are
  valuable even before fixes are possible — say so plainly, and
  do not promise migration dates the vendors have not promised.
- **Long enterprise sales cycles.** Consulting-style engagements
  (migration assessments) bridge the early period. The open-source
  scanner is the lead generator for those engagements.
- **The standards are still moving.** HQC was selected as a
  backup KEM in March 2025 and FN-DSA (FIPS 206) is still in
  development. The scanner must treat the algorithm list as data,
  not code: a new standard is a config change, not a rewrite.

## How the three ideas compare

| | AI agent security | Deepfake and voice fraud | Crypto inventory and PQ migration |
|---|---|---|---|
| Market timing | New, fast-moving | Painful today | Deadline-driven |
| Competition | Growing quickly | Established in detection | Big vendors at the top end |
| MVP size for one person | Medium | Small | Small to medium |
| Distribution difficulty | Developers first | Needs bank or telecom partners | Open-source adoption, then compliance buyers |
| Fit with your earlier work | Reuses audit and timeline ideas | Local relevance in South Asia | Reuses scanning and reporting skills |

If you want the pick on pure business logic, the crypto inventory
has the most predictable demand and the easiest MVP, while AI agent
security has the highest upside and the most risk. That is still
true after verification — and the verification strengthened the
crypto case, because IR 8547 is final now and EO 14412 added hard
federal dates the pitch did not have.

## Fit with your earlier work

- **Kavach** (web security scanner) is the direct ancestor: the
  same scanning-and-reporting shape, the same graded output, the
  same "evidence on every finding" discipline. Its TLS and
  certificate probing is reused for the Phase 2 endpoint scanner.
- **Agent Gateway** contributes the audit and timeline ideas: the
  "prove" pillar (continuous monitor, tamper-evident log of
  findings) is the gateway's hash-chained audit log applied to a
  different problem.
- **The launch playbook** is the same as both: MIT licence, CI
  green from day one, a demo that runs on real code, and a LinkedIn
  launch draft that waits for your approval of the exact text.
- **CYBERSURE evidence.** This is directly relevant to the
  CYBERSURE application: cryptography is one of the Year-2 tracks
  (Tartu), and a crypto-inventory tool is a stronger proof line
  than a scanner alone — "I built the tool that finds where
  cryptography lives, and ran it on my own projects".

## Open decisions (Samir's call)

1. **Name.** "Crypto Atlas" is a working name. Keep it, or pick
   another before the repo is created — renaming after launch
   costs more than renaming now.
2. **Scanner core language.** Python (recommended: your strongest
   language, `ast` is stdlib, fastest to v0.1) or Go (faster scans,
   harder to iterate). The plan assumes Python; say so if you want
   Go.
3. **The 3 v0.1 languages.** Python, JavaScript/TypeScript, Go
   (recommended). Swap Go for Java if you want the enterprise
   codebase angle first — but Java comes in Phase 3 either way.
4. **Phase 0 interviews.** 8–10 security or compliance people is
   the hardest part of Phase 0: you have no compliance contacts
   yet. Two honest options: (a) build from the specs and public
   write-ups first and interview later, once there is a tool to
   show; (b) do the interviews via LinkedIn outreach to security
   folks before writing code. The plan works either way, but it
   needs one of them named.
5. **Repo.** Create `Samir-Khadka/crypto-atlas` when Phase 1
   starts. Not before — a repo with only a plan in it is a promise,
   not a project.

## Sources (verified 15 Nov 2026)

- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA):
  finalized 13 Aug 2024. NIST IR 8547 (Transition to
  Post-Quantum Cryptography Standards): final 27 Oct 2026 —
  RSA/ECC deprecated after 2030, disallowed after 2035.
- NSA CNSA 2.0 (Sep 2022, updated 30 May 2025): new NSS
  acquisitions support PQC from 1 Jan 2027; signing and networking
  exclusive by 2030; browsers, servers, cloud exclusive by 2033.
- White House NSM-10 (May 2022); OMB M-23-02 (Nov 2022) — federal
  crypto inventory; EO 14412 (Jun 2026) — federal key establishment
  on PQC by 31 Dec 2030, signatures by 31 Dec 2031.
- EU Coordinated Implementation Roadmap (NIS Cooperation Group /
  ENISA, 23 Jun 2025): national roadmaps end 2026, high-risk
  systems end 2030, full transition 2035. UK NCSC timeline
  (20 Mar 2025): discovery by 2028, high-priority by 2031, all
  systems by 2035.
- CycloneDX 1.6 (Apr 2024, ECMA-424) added CBOM; 1.7 extends it
  (algorithm families, elliptic-curve registry, richer certificate
  fields). OWASP Authoritative Guide to CBOM.
- IBM Quantum Safe suite announced 27 Oct 2026 (Cryptography
  Manager, Explorer, Proxy). PQCA CBOM Kit (formerly IBM):
  `sonar-cryptography` + `cbomkit-theia`, open source.
- SandboxAQ AQtive Guard; Keyfactor AgileSec (CBOM export in
  CycloneDX 1.6, verified Jul 2026); Venafi TLS Protect PQC;
  QuSecure QuProtect (Recon / Resilience / Reporting); PQShield
  (silicon IP + SDK); AppViewX Quantum Trust Hub; Fortanix;
  DuoKey (CycloneDX 1.7 CBOM).
- PQC Discovery Index 2026.5 (14 products, 7 criteria): "the
  category has solved finding. It has not solved proving." The
  index is conflict-disclosed and vendor-sponsored — treat its
  scores as directional.
- OpenSSL 3.5 ships ML-KEM, ML-DSA, SLH-DSA and the hybrid
  X25519MLKEM768 group in TLS 1.3. HQC selected Mar 2025
  (NIST IR 8545); FN-DSA (FIPS 206) in development.
- Full enterprise migration takes 5–10 years (NIST, ENISA, NCSC,
  major consultancies).

*Re-check the dates before quoting them in any public document.
Standards and roadmaps move; this plan is dated 15 Nov 2026.*
