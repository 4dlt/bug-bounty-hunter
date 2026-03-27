# Bug Bounty Hunter System — Design Document

**Date:** 2026-03-27
**Author:** PAI Brainstorming Session
**Status:** Approved
**Approach:** A — Orchestrator + Skill Overhaul

---

## Problem Statement

Current pentest skills (16+ skills, ~10,000 lines) are individually deep but:
1. **Don't find real bugs** — methodologies are thorough on paper but don't translate to exploitable findings
2. **No impact validation** — findings aren't verified for exploitability or bounty-worthiness
3. **Too many unnecessary stops** — agents pause for tasks they could handle (token refresh, auth, CSRF tokens)
4. **No fresh techniques** — static skills don't pull new CVEs, writeups, or bypass techniques
5. **No parallelism** — each skill runs sequentially in a single conversation
6. **Operate as isolated silos** — no orchestration layer for end-to-end engagements

## Solution

Build a **BugBountyHunter** master orchestrator skill that:
- Reads bug bounty program rules and enforces scope compliance
- Spawns 8+ parallel agents for different attack surfaces
- Uses upgraded existing skills with real-world payload databases
- Validates every finding for exploitability and bounty-worthiness
- Chains low-severity findings into high-severity exploits
- Pulls fresh techniques before each engagement
- Uses `dev-browser` CLI for all browser automation

---

## Architecture

```
User: "pentest target.com scope=*.target.com creds=user:pass@login-url program=hackerone/target"
         |
    +----v-------------------------+
    |  BugBountyHunter Skill       |  <-- Master orchestrator
    |  (Autonomous, parallel)      |
    +--+--+--+--+--+--+--+--+--+--+
       |                           |
    Phase 0                    Phase 1-4
    Scope Compliance           Parallel Execution
```

### Phase 0 — Program Rules & Scope (MANDATORY)

The orchestrator's FIRST action before any testing:

1. **Fetch the bug bounty program page** (HackerOne/Bugcrowd/Intigriti/self-hosted)
2. **Extract and parse:**
   - In-scope domains/assets
   - Out-of-scope domains/assets
   - Allowed test types (no DoS, no social engineering, no physical, etc.)
   - Forbidden actions (no data exfiltration, no automated mass scanning, etc.)
   - Severity exclusions (self-XSS, missing headers, clickjacking on non-sensitive pages, etc.)
   - Response SLAs and safe harbor terms
3. **Generate scope.yaml** that every agent inherits
4. **Every agent checks scope before every request** — out-of-scope = hard block

```yaml
# scope.yaml example
program: target-program
platform: hackerone
in_scope:
  - "*.target.com"
  - "api.target.com"
out_of_scope:
  - "staging.target.com"
  - "blog.target.com"
forbidden_tests:
  - dos
  - social_engineering
  - automated_mass_scanning
excluded_findings:
  - self_xss
  - missing_security_headers
  - clickjacking_on_non_sensitive_pages
rate_limit: 10_req_per_second
```

### Phase 1 — Recon & Attack Surface Mapping (3 parallel agents)

All agents are scope-constrained by Phase 0 output.

**Agent R1: Subdomain & Asset Discovery**
- subfinder (passive, dozens of APIs)
- DNS enumeration (dnsx, puredns)
- Cloud asset discovery (S3 buckets, Azure blobs, GCP storage)
- Certificate transparency (crt.sh)
- Shodan/Censys lookup for target ASN

**Agent R2: Content & API Discovery**
- katana crawling (SPA support, headless mode)
- JS file extraction and analysis (LinkFinder, SecretFinder patterns)
- Historical URL mining (waybackurls/gau)
- ffuf directory brute-force with recursive 401 path follow-up (Haddix technique)
- API endpoint discovery (kiterunner patterns)

**Agent R3: Tech Fingerprinting & Vuln Scanning**
- httpx tech detection (Wappalyzer)
- nuclei with latest templates for identified tech
- Google/GitHub/Shodan dork generation for target
- dev-browser screenshots of key pages

All agents write to shared state file. Recon output feeds Phase 2 agents.

### Phase 2 — Authenticated Testing (8 parallel agents)

The orchestrator authenticates ONCE using provided credentials via dev-browser:
1. Navigate to login URL
2. Fill credentials
3. Extract tokens/cookies/CSRF tokens
4. Store in shared auth state
5. Auto-refresh tokens as needed (no stopping to ask)

**Agent A: Auth & Session Testing**
- JWT attacks: none algorithm, RS256-to-HS256, JWK injection, kid path traversal, JKU/X5U injection, algorithm confusion, weak secret brute-force
- MFA bypass: forced browsing, race condition, code reuse, backup code brute-force
- Password reset: host header injection, token predictability, email parameter pollution
- OAuth: redirect URI manipulation, state parameter bypass, token leakage, scope escalation
- Session: fixation, token entropy analysis, concurrent session handling
- SAML: assertion manipulation, XML signature wrapping

**Agent B: Access Control / IDOR**
- Full 16-layer attack matrix from IdorPentest skill:
  1. Sequential IDs
  2. UUID/non-sequential (prediction, leakage)
  3. Encoded refs (Base64/hex/JWT)
  4. Composite keys
  5. HTTP method switching (GET blocked then try PUT/PATCH/DELETE)
  6. API version bypass (/v2 has auth then try /v1)
  7. Mass assignment + IDOR
  8. Parameter pollution
  9. Content-Type switching
  10. State-based/workflow IDOR
  11. Second-order/chained IDOR
  12. Blind IDOR (mutations, timing)
  13. Race condition IDOR (TOCTOU)
  14. GraphQL/gRPC/WebSocket IDOR
  15. Webhook/callback/file IDOR
  16. Multi-tenant isolation bypass
- Impact validation: after finding IDOR, assess data sensitivity and exposure scope
- Chain: IDOR to data exfil to privilege escalation

**Agent C: Injection Testing**
- SQL Injection: error-based, UNION-based, blind boolean, blind time-based, out-of-band, second-order, stacked queries. Per-database payloads (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). WAF bypass via sqlmap tamper scripts
- XSS: 26 techniques + WAF bypass payloads per provider:
  - Cloudflare bypasses
  - Imperva bypasses
  - AWS WAF bypasses
  - CloudFront bypasses
  - ModSecurity bypasses
  - Akamai bypasses
- SSTI: Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Pug detection and exploitation
- Command injection: basic, blind (OOB via interactsh), time-based
- NoSQL injection: MongoDB, CouchDB operator injection ($regex, $gt, $ne)
- CRLF injection: header injection, HTTP response splitting

**Agent D: SSRF & Network**
- IP encoding permutation engine (8 variants): hex, octal, dword, mixed, URL-encoded, IPv6, bubble text, DNS rebinding
- Protocol smuggling: file://, dict://, ftp://, gopher://, tftp://
- Cloud metadata exploitation:
  - AWS IMDSv1/v2 (169.254.169.254)
  - GCP metadata (metadata.google.internal, Metadata-Flavor header)
  - Azure IMDS (169.254.169.254, Metadata header)
- DNS rebinding attacks
- Redirect chain SSRF
- SSRF to internal admin to RCE chain attempts

**Agent E: Business Logic & Race Conditions**
- Price/payment manipulation: price params, negative quantities, currency confusion, discount stacking
- Coupon abuse: multi-use via race condition, code prediction, stacking
- Workflow bypass: skip required steps, force-browse past auth, state manipulation
- Race conditions: James Kettle single-packet attack (HTTP/2), coupon redemption, fund transfer, MFA bypass, rate limit bypass
- Feature flag manipulation
- Referral/reward abuse
- Subscription tier manipulation
- Free trial reset

**Agent F: API Deep Dive**
- GraphQL: introspection, field-level auth testing, alias-based batching, nested query DoS, subscription abuse
- Parameter mining: Arjun-style brute-force for hidden params on every discovered endpoint
- Mass assignment: POST with extra fields, compare response diffs
- Rate limit bypass: header rotation (X-Forwarded-For, X-Real-IP), path variation, method switching
- API version downgrade testing
- Content-Type confusion (JSON to XML to form-data)

**Agent G: File Upload & Deserialization**
- Unrestricted file upload: extension bypass (.php5, .phtml, .php.jpg), content-type bypass, double extensions
- Polyglot files: PHP/JPEG, SVG/XSS, PDF/JS
- Path traversal in filename
- Race condition in upload + execute
- Deserialization: Java (ysoserial), PHP (phpggc), Python (safe alternatives when available), .NET, Ruby
- Content-type specific attacks: XXE in XML uploads, SVG XSS, CSV injection

**Agent H: WebSocket & Real-time**
- Cross-Site WebSocket Hijacking (CSWSH)
- Authorization bypass on WS connections
- Injection via WebSocket messages (SQLi, XSS, command injection)
- Subscription abuse (unauthorized data streams)
- Message manipulation and replay
- Connection hijacking

### Phase 3 — Impact Validation & Chaining

Dedicated **Impact Validator** agent that:

1. **Reviews all findings** from Phase 2 agents
2. **Validates exploitability:**
   - Can we actually extract data / perform the action?
   - Is the impact real and demonstrable?
   - Can we create a clear PoC?
3. **Attempts vulnerability chaining:**
   - XSS to ATO (steal admin session)
   - XSS to CSRF to ATO (change email then password reset)
   - SSRF to Cloud Metadata to Credential Theft to Full Access
   - IDOR to Data Exfil to Privilege Escalation
   - Open Redirect to OAuth Token Theft to ATO
   - Information Disclosure to API Key to Further Access
4. **Classifies severity (P1-P5):**
   - P1 (Critical): RCE, full ATO, payment manipulation, mass data breach
   - P2 (High): IDOR with PII, privilege escalation, significant data exposure
   - P3 (Medium): Stored XSS, CSRF on sensitive actions, information disclosure of credentials
   - P4 (Low): Reflected XSS, CSRF on non-sensitive actions, verbose errors
   - P5 (Informational): Missing headers, theoretical issues, no demonstrated impact
5. **Drops findings programs won't accept:**
   - Self-XSS (unless chainable)
   - Missing security headers (unless combined with attack)
   - Clickjacking on non-sensitive pages
   - Theoretical DoS without PoC
   - Best practices / informational only
6. **Estimates bounty payout** based on program history and severity

### Phase 4 — Reporting

Generates a professional report formatted for direct submission:

```markdown
# Bug Bounty Report: target.com
## Engagement Summary
- Date: YYYY-MM-DD
- Scope: *.target.com
- Platform: HackerOne
- Findings: N validated (breakdown by severity)

## Finding N: [Descriptive Title]
**Severity:** P1 (Critical) | **CVSS:** 9.1 | **CWE:** CWE-XXX
**Bounty Estimate:** $X,XXX-$XX,XXX

### Summary
[2-3 sentence description of the vulnerability and its impact]

### Steps to Reproduce
1. [Step-by-step with exact URLs, parameters, payloads]
2. [Include curl commands / dev-browser scripts]
3. [Screenshots where applicable]

### Impact
[Business impact: what can attacker achieve, users affected, data exposed]

### Proof of Concept
[curl commands, HTTP requests, screenshots, or dev-browser script]

### Remediation
[Specific fix recommendation]
```

---

## Agent Communication — Shared State

Agents share discoveries via a shared state file:

**Location:** `/tmp/pentest-<engagement-id>/state.json`

```json
{
  "scope": {
    "in_scope": ["*.target.com"],
    "out_of_scope": ["staging.target.com"],
    "forbidden_tests": ["dos"],
    "excluded_findings": ["self_xss"],
    "rate_limit": "10_req_per_second"
  },
  "auth": {
    "access_token": "...",
    "refresh_token": "...",
    "cookies": { "session": "..." },
    "csrf_token": "...",
    "last_refreshed": "2026-03-27T16:00:00Z"
  },
  "discovered_endpoints": [
    {
      "url": "/api/v2/users/{id}",
      "method": "GET",
      "params": ["id"],
      "auth_required": true,
      "found_by": "recon-r2"
    }
  ],
  "discovered_parameters": ["debug", "admin", "internal_id"],
  "tech_stack": {
    "framework": "Django 4.2",
    "server": "nginx",
    "waf": "Cloudflare"
  },
  "findings": [
    {
      "id": "F-001",
      "class": "IDOR",
      "severity": "P2",
      "validated": true,
      "chainable": true,
      "chain_with": ["F-003"],
      "endpoint": "/api/v2/users/123",
      "poc": "Change user_id to 124, access other user PII",
      "impact": "Access to 50K+ user records",
      "bounty_estimate": "$5,000-$10,000"
    }
  ]
}
```

**Sharing rules:**
- Recon agents write endpoints, attack agents read them
- Auth agent manages tokens, all agents read them
- When WAF detected, injection agents switch to WAF-specific payloads
- When IDOR found, validator checks chaining to privilege escalation
- All agents respect rate_limit from scope

---

## Browser Automation — dev-browser

All browser-based testing uses `dev-browser` CLI instead of Playwright MCP.

**Advantages for pentesting:**
- Persistent named pages across scripts (`browser.getPage("auth")`)
- Multiple parallel contexts (`"idor-test"`, `"xss-test"`, `"auth-test"`)
- `--ignore-https-errors` for self-signed certs
- `snapshotForAI()` for AI-optimized DOM discovery
- Script-based architecture — each test is a small focused script
- `--connect` attaches to existing Chrome sessions (proxy interception)

**Authentication pattern:**
```js
// auth.js - run once, session persists
const page = await browser.getPage("auth");
await page.goto("https://target.com/login");
await page.fill("#username", "user");
await page.fill("#password", "pass");
await page.click("#login-btn");
await page.waitForURL("**/dashboard");
const cookies = await page.context().cookies();
await writeFile("auth.json", JSON.stringify(cookies));
console.log("Authenticated successfully");
```

**Testing pattern:**
```js
// idor-test.js - uses persistent auth session
const page = await browser.getPage("idor-test");
await page.goto("https://target.com/api/users/123");
const response = await page.textContent("body");
await page.goto("https://target.com/api/users/124");
const other = await page.textContent("body");
console.log(JSON.stringify({ own: response, other: other }));
```

---

## Tool Requirements

| Tool | Purpose | Install | Required |
|------|---------|---------|----------|
| `dev-browser` | Browser automation | Already installed | Yes |
| `subfinder` | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Yes |
| `httpx` | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | Yes |
| `nuclei` | Template scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Yes |
| `katana` | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | Yes |
| `ffuf` | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` | Yes |
| `nmap` | Port scanning | System package manager | Yes |
| `curl` | HTTP requests | System | Yes |
| `sqlmap` | SQLi exploitation | `pip install sqlmap` | Recommended |
| `interactsh-client` | OOB detection | `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` | Recommended |
| `arjun` | Param discovery | `pip install arjun` | Recommended |
| `gau` | Historical URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` | Recommended |
| `dalfox` | XSS scanning | `go install github.com/hahwul/dalfox/v2@latest` | Recommended |

The skill checks for tool availability at start and warns about missing optional tools.

---

## Existing Skill Upgrades

### Major Upgrades

**1. Security/WebAssessment**
- Add autonomous authentication handling
- Add business logic test cases (9 categories from AllAboutBugBounty)
- Add OWASP WSTG v4.2 test case taxonomy
- Add "never stop for what you can do yourself" directive
- Integrate dev-browser for all browser testing

**2. DastAutomation**
- Add XSS WAF bypass payloads per provider (Cloudflare, Imperva, CloudFront, AWS WAF, ModSecurity, Akamai)
- Add SSRF IP encoding permutation engine (8 variants)
- Add LFI PHP wrapper chain (14 techniques)
- Add 403 bypass techniques
- Add rate limit (429) bypass techniques
- Add single-packet race condition testing
- Replace Playwright MCP with dev-browser

**3. ApiSecurity**
- Add Arjun-style parameter brute-forcing
- Expand JWT attacks (JWK injection, kid traversal, JKU/X5U, algorithm confusion)
- Add GraphQL field-level authorization testing
- Add API version downgrade attacks
- Add mass assignment detection via response diff

**4. IdorPentest**
- Add impact validation (assess data sensitivity after finding IDOR)
- Add chaining logic (IDOR to data exfil to privilege escalation)
- Add blind IDOR detection (timing, error analysis)
- Add UUID prediction/leakage detection

**5. Security/Recon**
- Add JS file extraction and analysis
- Add historical URL mining
- Add dork generation (Google, GitHub, Shodan)
- Add cloud asset discovery
- Add recursive 401 path brute-forcing (Haddix technique)

### Minor Upgrades

**6. LlmSecurity** — Add MCP protocol attacks, agentic system exploitation
**7. SastOrchestration** — Add AI-assisted triage
**8. ThreatModeling** — Add bug-bounty-specific threat model template

### New Components

**9. Payload Database** (`~/.claude/skills/Security/Payloads/`)
- Structured YAML files per vulnerability class
- Sources: AllAboutBugBounty, research intelligence, HackerOne disclosures
- WAF-specific bypass sets per provider
- Refreshable via web fetch before engagements

**10. Impact Validator Module**
- P1-P5 severity classification
- Chain detection engine
- Bounty-worthiness filter
- HackerOne/Bugcrowd report generator

**11. Fresh Technique Fetcher**
- Latest nuclei templates for target tech stack
- Recent HackerOne disclosed reports for the program
- CVEs for identified software versions
- New bypass techniques from security research

---

## Behavioral Rules (All Agents)

1. **Never stop for things you can do yourself** — token refresh, cookie extraction, CSRF token fetching, redirect following, login with provided credentials
2. **Validate before reporting** — every finding must be confirmed exploitable with a PoC
3. **Chain everything** — always attempt to escalate severity through chaining
4. **Respect scope** — check scope.yaml before every request, hard-block out-of-scope
5. **Respect rate limits** — honor program rate limits, use delays between requests
6. **Pull fresh techniques** — fetch latest CVEs/bypasses for the target's tech stack
7. **Be autonomous** — only stop for truly ambiguous decisions (is this endpoint really in scope?)
8. **Prioritize depth over breadth** — one confirmed P2 is worth more than ten unvalidated P4s

---

## Success Criteria

1. System can run a full engagement from "pentest target.com" to validated findings report
2. Parallel agents execute simultaneously, sharing context
3. Every reported finding is validated exploitable with PoC
4. Agents handle authentication autonomously
5. Fresh techniques are pulled before each engagement
6. Scope compliance is enforced at every step
7. Reports are formatted for direct submission to bug bounty platforms
8. System finds bugs that the individual skills running manually would miss (through chaining, deeper testing, and fresh techniques)

---

## References

- AllAboutBugBounty (daffainfo) — payload database and bypass techniques
- BugBountyBooks (akr3ch) — OWASP WSTG, zseano methodology, API security
- ProjectDiscovery toolchain — recon pipeline standard
- James Kettle single-packet attack — race condition testing
- Jason Haddix Bug Hunter's Methodology — recon depth, recursive 401 brute-forcing
- HackerOne 2024-2025 statistics — payout data and vulnerability trends
- dev-browser CLI — browser automation tool
