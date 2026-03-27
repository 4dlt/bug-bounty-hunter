# BugBountyHunter

Autonomous bug bounty pentesting system for [Claude Code](https://claude.ai/claude-code). Spawns parallel AI agents for reconnaissance, attack, validation, and reporting -- producing bounty-ready findings with working PoCs.

## Architecture

```
User: "pentest target.com scope=*.target.com creds=user:pass@login program=hackerone.com/target"
         |
    +----v----------------------------+
    |  BugBountyHunter Orchestrator   |
    |  (Master skill -- autonomous)   |
    +--+-----+-----+-----+-----+---+-+
       |     |     |     |     |   |
   Phase 0  Phase 1   Phase 2  Phase 2b         Phase 3       Phase 4
   Scope    Recon      Auth    Attack            Validate      Report
   Parse    (3 agents) Login   (8 agents)        Chain+PoC     Bounty-ready
       |     |     |           |     |     |         |             |
       |  +--+--+--+--+  +----+-----+-----+----+    |             |
       |  |R1  R2  R3 |  |A  B  C  D  E  F G H|    |             |
       |  +-----+-----+  +----------+----------+    |             |
       |        |                    |               |             |
       |   shared state.json        |          ImpactValidator    |
       |   (endpoints, tech,    findings[]     (reproduce,        |
       |    subdomains, JS)                     chain, classify)  |
       |                                             |             |
       +---------------------------------------------+-------------+
                                                     |
                                              /tmp/pentest-ID/report.md
```

## What It Does

BugBountyHunter runs a 5-phase pipeline against a target:

| Phase | What | Agents | Purpose |
|-------|------|--------|---------|
| **0 -- Scope** | Parse program rules | Orchestrator | Legal compliance, in/out-of-scope |
| **1 -- Recon** | Map attack surface | R1 (assets), R2 (content), R3 (fingerprint) | Subdomains, endpoints, tech stack |
| **2 -- Auth** | Establish session | Orchestrator | Login, extract tokens/cookies |
| **2b -- Attack** | Find vulnerabilities | 8 parallel agents (A-H) | Auth, IDOR, injection, SSRF, logic, API, upload, WebSocket |
| **3 -- Validate** | Confirm exploitability | Validator agent | Reproduce, chain, classify P1-P5 |
| **4 -- Report** | Bounty-ready output | Orchestrator | HackerOne/Bugcrowd formatted |

Every finding is validated with a working PoC. No theoretical vulnerabilities. Chains are attempted before severity is finalized.

## Prerequisites

- [Claude Code](https://claude.ai/claude-code) CLI installed and authenticated
- [dev-browser](https://www.npmjs.com/package/@anthropic-ai/dev-browser) (`npm install -g @anthropic-ai/dev-browser`)
- Go 1.21+ (for ProjectDiscovery tools)
- Authorization to test the target (you must have written permission)

## Quick Install

```bash
git clone https://github.com/YOUR_USERNAME/bug-bounty-hunter.git
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

# Full -- with bug bounty program URL
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
| **BugBountyHunter** | Master orchestrator -- parses input, spawns agents, manages state | `SKILL.md`, 13 agent prompts, `check-tools.sh` |
| **Payloads** | 10 YAML payload databases with WAF bypasses | XSS, SQLi, SSRF, IDOR, LFI, auth-bypass, business-logic, 403-bypass, rate-limit-bypass, SSTI |
| **ImpactValidator** | Finding validation, severity classification, chain detection | `SKILL.md`, ChainPatterns, SeverityMatrix, BountyFilter, ReportTemplate |
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
2. **The shared state file path** (`/tmp/pentest-ID/state.json`) for reading recon data and writing findings
3. **Scope constraints** from `scope.yaml` -- every agent checks scope before every request

Agents operate autonomously:
- **No stopping for auth** -- they extract tokens, refresh sessions, handle CSRF
- **No stopping for decisions** -- they make judgment calls within scope constraints
- **No theoretical findings** -- every finding needs a working PoC before reporting

### Agent Roster

**Recon Phase (3 parallel):**
- **R1** -- Subdomain and asset discovery (subfinder, DNS, cloud assets)
- **R2** -- Content and API discovery (katana, JS analysis, historical URLs, ffuf)
- **R3** -- Tech fingerprinting and vulnerability scanning (httpx, nuclei, dorks)

**Attack Phase (8 parallel):**
- **A** -- Auth and session testing (JWT, MFA bypass, OAuth, password reset, session fixation)
- **B** -- Access control / IDOR (16-layer attack matrix, blind IDOR, UUID prediction)
- **C** -- Injection (SQLi, XSS, SSTI, command injection, NoSQL, CRLF)
- **D** -- SSRF and network (8 IP encodings, protocol smuggling, cloud metadata, DNS rebinding)
- **E** -- Business logic and race conditions (price manipulation, coupon abuse, single-packet attack)
- **F** -- API deep dive (GraphQL, parameter mining, mass assignment, API version downgrade)
- **G** -- File upload and deserialization (extension bypass, polyglots, path traversal, XXE)
- **H** -- WebSocket and real-time (CSWSH, auth bypass, injection via WS, subscription abuse)

**Validation Phase (1 agent):**
- **Validator** -- Reproduces findings, attempts chaining, classifies P1-P5, filters bounty-worthiness

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

## Impact Validation and Chaining

The ImpactValidator runs after all attack agents complete. For every finding:

1. **Reproduce independently** -- rebuild the exploit from scratch, run it 3 times minimum
2. **Verify real impact** -- not "vulnerable to X" but "extracted N user records" or "executed command Y"
3. **Attempt chaining** -- cross-reference all findings against 10 known chain patterns:
   - XSS --> ATO (steal session cookie)
   - XSS --> CSRF --> ATO (change email, password reset)
   - SSRF --> Cloud metadata --> credential theft
   - SSRF --> Internal admin --> RCE
   - IDOR --> Data exfil --> Privilege escalation
   - Open redirect --> OAuth token theft --> ATO
   - Info disclosure --> API key --> Further access
   - Race condition --> Financial impact
   - LFI --> Source code --> Credential extraction
   - Auth bypass --> Admin access --> Full compromise
4. **Classify severity** (P1-P5) with CVSS score and CWE ID
5. **Filter bounty-worthiness** -- drop self-XSS, missing headers, theoretical issues
6. **Estimate bounty payout** based on severity and program history

## Project Structure

```
bug-bounty-hunter/
├── README.md                          # This file
├── install.sh                         # One-command installer
├── LICENSE                            # MIT license
├── skills/
│   ├── BugBountyHunter/              # Master orchestrator
│   │   ├── SKILL.md
│   │   ├── AgentPrompts/
│   │   │   ├── recon-r1-assets.md
│   │   │   ├── recon-r2-content.md
│   │   │   ├── recon-r3-fingerprint.md
│   │   │   ├── attack-a-auth.md
│   │   │   ├── attack-b-idor.md
│   │   │   ├── attack-c-injection.md
│   │   │   ├── attack-d-ssrf.md
│   │   │   ├── attack-e-business-logic.md
│   │   │   ├── attack-f-api.md
│   │   │   ├── attack-g-file-upload.md
│   │   │   ├── attack-h-websocket.md
│   │   │   └── validator.md
│   │   └── check-tools.sh
│   ├── Payloads/                     # 10 YAML payload databases
│   ├── ImpactValidator/              # Finding validation and severity
│   ├── TechniqueFetcher/             # Fresh technique pulling
│   ├── Recon/Workflows/              # New recon workflows
│   ├── DastUpgrades/                 # Patches for DastAutomation
│   ├── ApiSecurityUpgrades/          # Patches for ApiSecurity
│   ├── IdorPentestUpgrades/          # New IDOR workflows + patches
│   └── WebAssessmentUpgrades/        # Patches for WebAssessment
└── docs/plans/                       # Design and implementation docs
```

## Contributing

Contributions welcome. Areas that would benefit most:

- **New payload files** -- additional vulnerability classes or WAF bypass updates
- **Chain patterns** -- new vulnerability chain combinations in `ImpactValidator/ChainPatterns.md`
- **Agent prompts** -- improved attack strategies in `BugBountyHunter/AgentPrompts/`
- **Tool integrations** -- support for additional security tools
- **Platform formatters** -- Intigriti, YesWeHack, and other platform report formats

Please ensure all payloads are sourced from public research and properly attributed.

## Disclaimer

This tool is for authorized security testing only. Always obtain written permission before testing any target. The authors are not responsible for misuse. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
