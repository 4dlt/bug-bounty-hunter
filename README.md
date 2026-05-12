# BugBountyHunter

Autonomous bug bounty pentesting system for [Claude Code](https://claude.ai/claude-code). Spawns parallel AI agents for reconnaissance, authentication, attack, validation, and reporting -- producing bounty-ready findings with working PoCs and HackerOne-precedent-grounded bounty estimates.

> **v3.2-patch (2026-04-19)**: Artifact-first adversarial validator. The single self-grading validator has been replaced by an Advocate / Triager debate gated by the Phase 2.9 artifact rules and HackerOne precedent index. Bounty totals are no longer hallucinated — they are anchored to disclosed reports.

## Architecture

```
User: "pentest target.com scope=*.target.com creds=user:pass@login program=hackerone.com/target"
         |
    +----v----------------------------+
    |  BugBountyHunter Orchestrator   |
    |  (Master skill -- autonomous)   |
    +--+-----+-----+-----+-----+---+-+
       |
   Phase 0           Phase 1            Phase 2         Phase 2b               Phase 2.9         Phase 3            Phase 4
   Scope + mode      Recon              Auth            Attack                 Artifact gate     Adversarial        Report
   detect            (4 agents)         acquire         (13 agents)            (rule-based)      validate           Bounty-ready
       |              |                  |                 |                      |                |                   |
       |        +--+--+--+--+--+   auth-acquire     +-+-+-+-+-+-+-+-+-+-+-+-+-+   PublicSafeList   Advocate           HackerOne /
       |        |R1 R2 R3 R4|                       |A B C D E F G H I J K L M|   ArtifactMatrix   + Triager          Bugcrowd
       |        +-----+-----+                       +-----------+-------------+   EvidenceRules    + Verifier         (precedent
       |              |                                         |                       |          + refusal           gated)
       |              +------------------ shared state.json ----+--------- findings[] --+------------- recovery -------+
       |                                       |
       |                              /tmp/pentest-ID/state.json + per-finding dirs
       |                                                                                                              |
       +--------------------------------------------------------------------------------------------------------------+
                                                                                                                      |
                                                                                                  /tmp/pentest-ID/report.md
```

## What It Does

BugBountyHunter runs a 7-phase pipeline against a target:

| Phase | What | Agents / Components | Purpose |
|-------|------|---------------------|---------|
| **0 -- Scope + Mode** | Parse program rules, detect account mode | Orchestrator + `detect-account-mode.sh` | Legal compliance, in/out-of-scope, anon vs auth vs cross-tenant |
| **1 -- Recon** | Map attack surface | R1 (assets), R2 (content), R3 (fingerprint), R4 (JS analysis) | Subdomains, endpoints, tech stack, JS endpoints + secrets |
| **2 -- Auth Acquire** | Establish session | `auth-acquire` agent + `refresh-monitor.sh` + `session-warmer.sh` | Login, extract tokens/cookies, keep session warm across phases |
| **2b -- Attack** | Find vulnerabilities | 13 parallel agents (A-M) | Auth, IDOR, injection, SSRF, logic, API, upload, WS, client-side, protocol, config, deserialization, race |
| **2.9 -- Artifact Gate** | Reject smoking-gun-free findings | `phase29-gate.sh` + `ArtifactMatrix.yaml` + `PublicSafeList.yaml` + `EvidenceRules.yaml` | Drop program-excluded classes, missing-artifact claims, public-by-design patterns, cross-tenant partial-IDOR, chain-constituents |
| **3 -- Adversarial Validate** | Debate-based exploitability check | Advocate + Triager + Verifier + refusal-recovery | Reproduce, chain, classify, close-or-keep with 10-code taxonomy |
| **4 -- Report** | Bounty-ready output | `generate-report.sh` + `precedent-lookup.sh` + `HackerOnePrecedents.jsonl` | HackerOne/Bugcrowd formatted, precedent-gated bounty totals (no hallucination) |

Every finding is validated with a working PoC. No theoretical vulnerabilities. Chains are attempted before severity is finalized. Bounty estimates are anchored to disclosed HackerOne reports of the same class and program tier — if no precedent exists, the finding is reported without a dollar figure rather than guessing.

## Why v3.2

The 2026-04-18 23andMe regression validated 10 findings (`$6,500–$17,200` claimed) that mostly would close at HackerOne triage as informative, duplicate, or program-excluded. Root cause: a single validator agent authored its own Q1–Q4 rationale **and** verdict; every "BORDERLINE" confession in `reportability_audit` still ended `gate_passed: true`. Bounty ranges were hallucinated with no precedent citation and no mechanism to validate.

v3.2-patch fixes this with three architectural changes:

1. **Artifact-first gate (Phase 2.9)** — findings without smoking-gun artifacts are dropped *before* validation, by rule, not by agent judgment.
2. **Adversarial debate (Phase 3)** — separate Advocate (defends the finding) and Triager (closes it under one of 10 codes) replace the self-grading validator. A second-refusal triggers conservative close, not a re-attempt.
3. **Precedent-gated bounty totals (Phase 4)** — no dollar figure is emitted unless `HackerOnePrecedents.jsonl` contains a same-class disclosed report for the program tier, with scope.yaml `reward_grid` as fallback.

Backed by 22 smoke tests including end-to-end regression against the Apr-18 fixture (10 in, 0 validated, 0 fake bounties).

## Prerequisites

- [Claude Code](https://claude.ai/claude-code) CLI installed and authenticated
- [dev-browser](https://www.npmjs.com/package/@anthropic-ai/dev-browser) (`npm install -g @anthropic-ai/dev-browser`)
- Go 1.21+ (for ProjectDiscovery tools)
- `jq`, `yq`, `bash` 4+ (for `lib/` scripts and `tests/smoke/`)
- Authorization to test the target (you must have written permission)

## Quick Install

```bash
git clone https://github.com/4dlt/bug-bounty-hunter.git
cd bug-bounty-hunter
chmod +x install.sh
./install.sh
```

Restart Claude Code after installation for skills to take effect.

## Usage

```bash
# Minimal -- just a target
pentest target.com

# With scope
pentest target.com scope=*.target.com

# With credentials for authenticated testing
pentest target.com scope=*.target.com creds=user:pass@https://target.com/login

# Full -- with bug bounty program URL (enables precedent lookup)
pentest target.com scope=*.target.com creds=user:pass@https://target.com/login program=https://hackerone.com/target

# Synonym triggers also work
bug bounty target.com
find vulnerabilities in target.com
security assessment target.com
```

## What's Included

### Core Skills (installed as symlinks)

| Component | Description | Files |
|-----------|-------------|-------|
| **BugBountyHunter** | Master orchestrator -- parses input, spawns agents, manages state, runs Phase 2.9 gate and Phase 3 debate | `SKILL.md` (1864 lines), 23 agent prompts, `check-tools.sh`, `config/`, `data/`, `lib/` (18 scripts), `tests/smoke/` (22 tests) |
| **Payloads** | 10 YAML payload databases with WAF bypasses | XSS, SQLi, SSRF, IDOR, LFI, auth-bypass, business-logic, 403-bypass, rate-limit-bypass, SSTI |
| **ImpactValidator** | Finding validation, severity classification, chain detection (legacy support; v3.2 uses Advocate/Triager) | `SKILL.md`, ChainPatterns, SeverityMatrix, BountyFilter, ReportTemplate |
| **TechniqueFetcher** | Pre-engagement intelligence -- latest CVEs, disclosed reports, bypass techniques | `SKILL.md` |

### New Workflows (copied into existing skills)

| Component | Description | Destination |
|-----------|-------------|-------------|
| **Recon/JsAnalysis** | JS endpoint and secret extraction | `Security/Recon/Workflows/` |
| **Recon/HistoricalUrls** | gau/waybackurls historical URL mining | `Security/Recon/Workflows/` |
| **Recon/DorkGeneration** | Google/GitHub/Shodan dork generation | `Security/Recon/Workflows/` |
| **Recon/CloudAssetDiscovery** | S3/Azure/GCP cloud asset enumeration | `Security/Recon/Workflows/` |
| **IDOR/ImpactValidation** | Data sensitivity assessment after IDOR | `IdorPentest/Workflows/` |
| **IDOR/ChainExploitation** | IDOR-to-ATO/priv-esc chain workflows | `IdorPentest/Workflows/` |

### Upgrade Patches (for ai-security-arsenal users)

| Skill | What Was Added |
|-------|----------------|
| **DastAutomation** | WAF-specific XSS bypasses (6 providers), SSRF IP encoding engine (8 variants), LFI PHP wrapper chain, 403/429 bypass, single-packet race conditions, dev-browser migration |
| **ApiSecurity** | JWK/kid/JKU/X5U JWT attacks, parameter mining, GraphQL field-level auth testing, API version downgrade, mass assignment detection |
| **WebAssessment** | Autonomous authentication directive, 9-category business logic checklist, OWASP WSTG v4.2 taxonomy, dev-browser migration |
| **IdorPentest** | Blind IDOR detection (timing/error/side-channel), UUID prediction/leakage, impact validation workflow, chain exploitation workflow |

See the `skills/*Upgrades/README.md` files for copy-paste content blocks.

## Tool Requirements

### Required

| Tool | Purpose | Install |
|------|---------|---------|
| `dev-browser` | Browser automation | `npm install -g @anthropic-ai/dev-browser` |
| `subfinder` | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | HTTP probing and tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `nuclei` | Template-based vuln scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `katana` | Web crawling (SPA support) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `ffuf` | Directory and parameter fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| `nmap` | Port scanning | System package manager |
| `curl` | HTTP requests | System (usually pre-installed) |
| `jq` | JSON processing | System package manager |
| `yq` | YAML processing (for `lib/yaml2json.sh`) | `go install github.com/mikefarah/yq/v4@latest` |

### Recommended

| Tool | Purpose | Install |
|------|---------|---------|
| `sqlmap` | SQL injection exploitation | `pip install sqlmap` |
| `arjun` | Hidden parameter discovery | `pip install arjun` |
| `gau` | Historical URL fetching | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `dalfox` | XSS scanning | `go install github.com/hahwul/dalfox/v2@latest` |
| `interactsh-client` | Out-of-band detection | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` |
| `unfurl` | URL parsing | `go install github.com/tomnomnom/unfurl@latest` |

### Wordlists

[SecLists](https://github.com/danielmiessler/SecLists) is recommended for fuzzing and brute-force operations. The installer will clone it to `~/SecLists` if not already present.

## How Agents Work

BugBountyHunter uses Claude Code's Agent tool to spawn parallel sub-agents. Each agent receives:

1. **A specialized prompt** from `AgentPrompts/` defining its attack domain
2. **The shared state file path** (`/tmp/pentest-ID/state.json`) for reading recon data
3. **A per-finding directory** (`/tmp/pentest-ID/findings/<agent>-<class>-<id>/`) for writing artifacts (PoC requests, responses, screenshots, evidence files)
4. **Scope constraints** from `scope.yaml` -- every agent checks scope before every request
5. **`{{PIPELINE_MODE}}`** injection — agents are aware of whether they are running anon, authenticated, or cross-tenant, so they tailor their attack surface

Agents operate autonomously:
- **No stopping for auth** -- `auth-acquire` and `refresh-monitor.sh` keep sessions warm
- **No stopping for decisions** -- they make judgment calls within scope constraints
- **No theoretical findings** -- every finding needs a smoking-gun artifact (the Phase 2.9 gate will drop unbacked claims)

### Agent Roster

**Recon Phase (4 parallel):**
- **R1** -- Subdomain and asset discovery (subfinder, DNS, cloud assets)
- **R2** -- Content and API discovery (katana, historical URLs, ffuf)
- **R3** -- Tech fingerprinting and vulnerability scanning (httpx, nuclei, dorks)
- **R4** -- JavaScript analysis (endpoint extraction, secrets, source-map mining)

**Auth Phase (1 agent):**
- **auth-acquire** -- Establishes session, extracts tokens/cookies, captures refresh flow, hands off to `refresh-monitor.sh`

**Attack Phase (13 parallel):**
- **A** -- Auth and session testing (JWT, MFA bypass, OAuth, password reset, session fixation)
- **B** -- Access control / IDOR (16-layer attack matrix, blind IDOR, UUID prediction)
- **C** -- Injection (SQLi, XSS, SSTI, command injection, NoSQL, CRLF)
- **D** -- SSRF and network (8 IP encodings, protocol smuggling, cloud metadata, DNS rebinding)
- **E** -- Business logic and race conditions (price manipulation, coupon abuse, single-packet attack)
- **F** -- API deep dive (GraphQL, parameter mining, mass assignment, API version downgrade)
- **G** -- File upload (extension bypass, polyglots, path traversal, XXE)
- **H** -- WebSocket and real-time (CSWSH, auth bypass, injection via WS, subscription abuse)
- **I** -- Client-side (DOM XSS, prototype pollution, postMessage, client-side path traversal)
- **J** -- Protocol-level (HTTP smuggling, request splitting, host header injection, cache poisoning)
- **K** -- Configuration (CORS, security headers, mixed content, secrets in client, debug endpoints)
- **L** -- Deserialization (Java/PHP/Python/Ruby/.NET object gadgets, JNDI, ysoserial chains)
- **M** -- Race conditions (single-packet, multi-step workflow races, TOCTOU, parallel state writes)

**Artifact Gate (Phase 2.9 — rule-based, not agent-based):**
- `phase29-gate.sh` runs `ArtifactMatrix.yaml` × `EvidenceRules.yaml` × `PublicSafeList.yaml` checks
- Drops: program-excluded classes (20 categories: CSP, missing security headers, self-XSS, etc.), missing-artifact claims, public-safe patterns, cross-tenant partial-IDOR, chain-constituents that don't stand alone

**Validation Phase (3 agents in debate):**
- **Advocate** -- defends the finding under 4 hard rules; cites the smoking-gun artifact
- **Triager** -- closes the finding under one of 10 codes (not-applicable, informative, duplicate, out-of-scope, etc.) with HackerOne-style rationale
- **Verifier** -- spawned to reproduce when Advocate and Triager disagree; binary verdict
- **Refusal recovery** — if any of the three refuses twice, the orchestrator closes conservatively rather than retrying

**Report Phase (Phase 4):**
- `precedent-lookup.sh` checks `data/HackerOnePrecedents.jsonl` for same-class disclosed reports in the same program tier
- Bounty totals are emitted only when a precedent exists; otherwise the finding is reported without a dollar figure
- `scope.yaml`'s `reward_grid` is used as fallback when precedent is missing but program-declared payouts exist

## Payload Databases

The `skills/Payloads/` directory contains 10 structured YAML files:

| File | Payloads | Highlights |
|------|----------|------------|
| `xss.yaml` | 26+ techniques | WAF bypasses for Cloudflare, Imperva, AWS WAF, CloudFront, ModSecurity, Akamai |
| `sqli.yaml` | 6 attack types | Per-database payloads (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) |
| `ssrf.yaml` | 8 IP encodings | Cloud metadata (AWS IMDSv1/v2, GCP, Azure), protocol smuggling |
| `idor.yaml` | 16 techniques | Sequential, UUID, encoded, composite, method switching, blind |
| `lfi.yaml` | 14 techniques | PHP wrappers, null byte, path truncation, encoding variants |
| `auth-bypass.yaml` | JWT, MFA, OAuth | None algorithm, JWK injection, kid traversal, MFA race condition |
| `business-logic.yaml` | 9 categories | Price tampering, coupon abuse, race conditions, workflow bypass |
| `403-bypass.yaml` | Headers, paths, methods | X-Original-URL, path manipulation, method override |
| `rate-limit-bypass.yaml` | Header rotation | X-Forwarded-For, IP rotation, path variation |
| `ssti.yaml` | 10 template engines | Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pug, ERB, Handlebars, Tornado |

## HackerOne Precedent Index

`skills/BugBountyHunter/data/HackerOnePrecedents.jsonl` is a seed index of disclosed bounty reports keyed by `(vulnerability_class, program_tier, asset_type)`. Phase 4's `precedent-lookup.sh` queries it to anchor every bounty estimate to a real disclosed report.

If no precedent exists for a finding's class/tier/asset combination, the finding is reported without a dollar figure rather than guessed. This kills the v2 hallucination problem at the source.

To extend the index, append JSONL rows matching the schema in the file's header comment.

## Tests

`skills/BugBountyHunter/tests/smoke/` contains 22 smoke tests, runnable individually:

```bash
cd skills/BugBountyHunter
bash tests/smoke/test_apr18_full_regression.sh        # end-to-end against Apr-18 fixture
bash tests/smoke/test_bounty_hallucination_canary.sh  # rule 3 enforcement
bash tests/smoke/test_phase29_program_excluded.sh     # excluded class drop
bash tests/smoke/test_phase29_public_safe_list.sh     # public-safe pattern drop
bash tests/smoke/test_phase29_missing_artifact.sh     # missing-artifact drop
bash tests/smoke/test_phase29_partial_idor_guard.sh   # cross-tenant guard
bash tests/smoke/test_phase29_chain_constituent.sh    # chain-constituent rejection
bash tests/smoke/test_state_schema.sh                 # v3.2 state.json schema
# ...and 14 more
```

`tests/smoke/RESULTS.md` records the last clean run.

## Project Structure

```
bug-bounty-hunter/
├── README.md                          # This file
├── install.sh                         # One-command installer
├── LICENSE                            # MIT license
├── skills/
│   ├── BugBountyHunter/              # Master orchestrator (v3.2-patch)
│   │   ├── SKILL.md
│   │   ├── AgentPrompts/             # 23 prompts: 4 recon + auth-acquire + 13 attack + advocate + triager + verifier
│   │   ├── config/
│   │   │   ├── ArtifactMatrix.yaml   # Smoking-gun requirements per vuln class
│   │   │   ├── EvidenceRules.yaml    # Phase 2.9 evidence enforcement
│   │   │   └── PublicSafeList.yaml   # Known-safe-by-design patterns
│   │   ├── data/
│   │   │   └── HackerOnePrecedents.jsonl  # Disclosed report index for bounty grounding
│   │   ├── lib/                      # 18 shell scripts (gates, monitors, generators)
│   │   ├── tests/smoke/              # 22 smoke tests
│   │   ├── docs/plans/               # Design and ADR docs
│   │   └── check-tools.sh
│   ├── Payloads/                     # 10 YAML payload databases
│   ├── ImpactValidator/              # Legacy finding validator (kept for non-v3 callers)
│   ├── TechniqueFetcher/             # Fresh technique pulling
│   ├── Recon/Workflows/              # New recon workflows
│   ├── DastUpgrades/                 # Patches for DastAutomation
│   ├── ApiSecurityUpgrades/          # Patches for ApiSecurity
│   ├── IdorPentestUpgrades/          # New IDOR workflows + patches
│   └── WebAssessmentUpgrades/        # Patches for WebAssessment
└── docs/plans/                       # Repo-level design docs
```

## Contributing

Contributions welcome. Areas that would benefit most:

- **HackerOne precedent rows** -- append disclosed reports to `data/HackerOnePrecedents.jsonl` to extend bounty grounding coverage
- **Phase 2.9 rules** -- new patterns for `PublicSafeList.yaml` or evidence requirements for `EvidenceRules.yaml`
- **New attack agents** -- additional vulnerability classes beyond A-M (e.g., supply-chain, server-side prototype pollution)
- **New payload files** -- additional vulnerability classes or WAF bypass updates
- **Chain patterns** -- new vulnerability chain combinations in `ImpactValidator/ChainPatterns.md`
- **Tool integrations** -- support for additional security tools
- **Platform formatters** -- Intigriti, YesWeHack, and other platform report formats

Please ensure all payloads and precedents are sourced from public research and properly attributed.

## Disclaimer

This tool is for authorized security testing only. Always obtain written permission before testing any target. The authors are not responsible for misuse. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
