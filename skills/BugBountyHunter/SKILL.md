---
name: BugBountyHunter
description: Autonomous bug bounty pentesting orchestrator. Reads program rules, spawns parallel recon and attack agents, validates findings for real exploitability, chains vulnerabilities, and generates bounty-ready reports. Triggers on "pentest target.com", "bug bounty", "find vulnerabilities in", "security assessment", "hack target.com for bugs".
---

# BugBountyHunter — Master Orchestrator

Autonomous bug bounty pentesting system. Parses target and scope, runs parallel recon, authenticates, launches parallel attacks, validates findings, and produces bounty-ready reports.

## Behavioral Rules (MANDATORY — ZERO EXCEPTIONS)

1. **Never stop for things you can do yourself** — Token refresh, cookie extraction, CSRF tokens, login with provided creds. Read state.json, use dev-browser, handle it.
2. **Validate before reporting** — Every finding must be confirmed exploitable with a reproducible PoC curl command or dev-browser script. No theoretical findings.
3. **Chain everything** — Always attempt to escalate severity by combining findings. A P3 IDOR + a P4 info leak can become P1 ATO. See Phase 3.
4. **Respect scope** — Check scope.yaml before every request. Out-of-scope = hard block. No exceptions.
5. **Respect rate limits** — Honor program rate limits from scope.yaml. Default to 10 req/s if unspecified.
6. **Pull fresh techniques** — Use WebSearch to fetch latest CVEs and bypasses for the target tech stack before attack phase.
7. **Be autonomous** — Only stop for truly ambiguous scope decisions. Everything else, handle yourself.
8. **Prioritize depth over breadth** — One confirmed P2 beats ten unvalidated P4s.

## Input Parsing

Parse user input to extract engagement parameters.

**Minimal format:**
```
pentest target.com
```

**Full format:**
```
pentest target.com scope=*.target.com creds=user:pass@https://target.com/login program=https://hackerone.com/target
```

**Parameter extraction:**
- `target` — First argument after trigger word. The primary domain/URL.
- `scope` — Glob pattern for in-scope assets. Default: `*.{target_domain}` + `{target_domain}`
- `creds` — Format `user:pass@login_url`. Optional.
- `program` — Bug bounty program URL (HackerOne, Bugcrowd, Intigriti). Optional.

**Trigger words:** `pentest`, `bug bounty`, `security assessment`, `hack`, `find vulnerabilities`

```bash
# Generate unique engagement ID
PENTEST_ID="pentest-$(date +%Y%m%d-%H%M%S)"
WORKDIR="/tmp/${PENTEST_ID}"
mkdir -p "${WORKDIR}"
mkdir -p "${WORKDIR}/agents"
```

---

## Phase 0 — Scope Compliance (MANDATORY FIRST STEP)

**Purpose:** Establish legal boundaries before any testing begins.

### If program URL is provided:

1. Fetch the program page:
```bash
# Use WebFetch or dev-browser to retrieve program rules
dev-browser <<'EOF'
const page = await browser.getPage("scope");
await page.goto("PROGRAM_URL");
const content = await page.snapshotForAI();
console.log(content.full);
EOF
```

2. Parse and extract:
   - **In-scope assets** (domains, IPs, wildcards)
   - **Out-of-scope assets** (specific subdomains, third-party services)
   - **Allowed test types** (can we SQLi? Can we brute force?)
   - **Forbidden actions** (no DoS, no social engineering, no physical)
   - **Excluded finding types** (self-XSS, logout CSRF, missing headers without impact)
   - **Rate limits** (requests per second/minute)
   - **Special rules** (no automated scanning, requires VPN, testing hours)

3. Generate scope files:

```yaml
# /tmp/pentest-{ID}/scope.yaml
target: target.com
program_url: https://hackerone.com/target
in_scope:
  - "*.target.com"
  - "api.target.com"
out_of_scope:
  - "blog.target.com"
  - "*.third-party.com"
allowed_tests:
  - injection
  - auth_bypass
  - idor
  - ssrf
  - business_logic
forbidden:
  - dos
  - social_engineering
  - physical
excluded_findings:
  - self_xss
  - logout_csrf
  - missing_headers_no_impact
rate_limit: 10  # requests per second
testing_hours: "24/7"
```

4. Generate initial state file:

```json
// /tmp/pentest-{ID}/state.json
{
  "id": "pentest-{ID}",
  "target": "target.com",
  "status": "phase-0-scope",
  "scope": {},
  "auth": {
    "authenticated": false,
    "cookies": [],
    "tokens": {},
    "csrf_token": null
  },
  "subdomains": [],
  "discovered_endpoints": [],
  "tech_stack": {},
  "js_endpoints": [],
  "cloud_assets": [],
  "parameters": [],
  "findings": [],
  "validated_findings": [],
  "agent_outputs_dir": "/tmp/pentest-{ID}/agents/"
}
```

5. Display scope summary and request user confirmation before proceeding.

### If no program URL:
- Use provided scope or default to `*.{target_domain}`
- Generate scope.yaml with permissive defaults
- Still require user confirmation of target authorization

---

## Phase 1 — Recon (3 Agents, Batched)

**Purpose:** Map the attack surface comprehensively before testing.

**CRITICAL: Spawn max 2 agents per batch.** Launching 3+ concurrent agents causes ECONNRESET (API connection reset) due to concurrent streaming connection limits. Always batch and wait.

Each agent gets scope.yaml and state.json path injected into its prompt template.

### Batch 1 (spawn together):

**Agent R1: Subdomain & Asset Discovery**
```
Read AgentPrompts/recon-r1-assets.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
**References:** `~/.claude/skills/Security/Recon/SKILL.md` (DomainRecon, CloudAssetDiscovery workflows)

**Agent R2: Content & API Discovery**
```
Read AgentPrompts/recon-r2-content.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
**References:** `~/.claude/skills/Security/Recon/SKILL.md` (JsAnalysis, HistoricalUrls workflows)

### Wait for Batch 1 to return, then merge agent output files into state.json:

```bash
# After Batch 1 (R1, R2):
for agent_file in "${WORKDIR}/agents/r1-results.json" "${WORKDIR}/agents/r2-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {
      subdomains: (.[0].subdomains + (.[1].subdomains // []) | unique),
      discovered_endpoints: (.[0].discovered_endpoints + (.[1].discovered_endpoints // []) | unique_by(.url)),
      tech_stack: (.[0].tech_stack * (.[1].tech_stack // {})),
      cloud_assets: (.[0].cloud_assets + (.[1].cloud_assets // []) | unique_by(.url)),
      js_endpoints: (.[0].js_endpoints + (.[1].js_endpoints // []) | unique)
    }' "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

### Batch 2 (spawn after Batch 1 completes):

**Agent R3: Tech Fingerprinting & Vulnerability Scanning**
```
Read AgentPrompts/recon-r3-fingerprint.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
**References:** `~/.claude/skills/Security/Recon/SKILL.md` (DorkGeneration workflow), `~/.claude/skills/DastAutomation/SKILL.md`

### After R3 returns:

```bash
# After Batch 2 (R3):
agent_file="${WORKDIR}/agents/r3-results.json"
if [ -f "$agent_file" ]; then
  jq -s '.[0] * {
    subdomains: (.[0].subdomains + (.[1].subdomains // []) | unique),
    discovered_endpoints: (.[0].discovered_endpoints + (.[1].discovered_endpoints // []) | unique_by(.url)),
    tech_stack: (.[0].tech_stack * (.[1].tech_stack // {})),
    cloud_assets: (.[0].cloud_assets + (.[1].cloud_assets // []) | unique_by(.url)),
    js_endpoints: (.[0].js_endpoints + (.[1].js_endpoints // []) | unique),
    findings: (.[0].findings + (.[1].findings // []))
  }' "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
    && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
fi
```

1. Read state.json — review merged recon data
2. Display recon summary:
   - Subdomain count
   - Live host count
   - Endpoint count
   - Tech stack detected
   - Cloud assets found
   - Notable findings (open buckets, exposed admin panels, etc.)
3. Update state.json status to `phase-1-complete`

### On ECONNRESET failure:
If any agent fails with ECONNRESET, retry it **alone** (no parallel agents) after a 10-second wait.

---

## Phase 2 — Authentication

**Purpose:** Establish authenticated session for deeper testing.

### If credentials provided:

```bash
# Use dev-browser to login and capture auth state
dev-browser --ignore-https-errors <<'EOF'
const page = await browser.getPage("auth");
await page.goto("LOGIN_URL");
await page.fill("input[name='username'], input[name='email'], #username, #email", "USERNAME");
await page.fill("input[name='password'], #password", "PASSWORD");
await page.click("button[type='submit'], input[type='submit']");
await page.waitForLoadState("networkidle");

// Extract all auth artifacts
const cookies = await page.context().cookies();
const storage = await page.evaluate(() => ({
  localStorage: JSON.stringify(localStorage),
  sessionStorage: JSON.stringify(sessionStorage)
}));

// Look for JWT in localStorage
const jwt = await page.evaluate(() => {
  for (const [k, v] of Object.entries(localStorage)) {
    if (v && v.startsWith('eyJ')) return { key: k, token: v };
  }
  return null;
});

// Look for CSRF token in page
const csrf = await page.evaluate(() => {
  const meta = document.querySelector('meta[name="csrf-token"], meta[name="_csrf"]');
  const input = document.querySelector('input[name="_csrf"], input[name="csrf_token"], input[name="_token"]');
  return meta?.content || input?.value || null;
});

console.log(JSON.stringify({ cookies, storage, jwt, csrf }, null, 2));
EOF
```

Update state.json auth section with extracted tokens, cookies, CSRF.

### If no credentials:
- Skip to Phase 2b with unauthenticated testing
- Note in state.json: `"auth": { "authenticated": false }`

---

## Phase 2b — Attack (8 Agents, Batched in Pairs)

**Purpose:** Systematic vulnerability discovery across all attack classes.

**CRITICAL: Spawn max 2 agents per batch.** Launching 3+ concurrent agents causes ECONNRESET (API connection reset). Batch in pairs, wait for each pair to return and merge results before spawning the next pair.

Before spawning agents, use WebSearch to pull latest CVEs and bypasses for the detected tech stack:
```
WebSearch: "latest CVE {tech_stack.framework} {tech_stack.server} 2026 bypass"
```

Each agent receives: scope.yaml path, state.json path (with auth, endpoints, tech stack).

### Batch 1 — High-value auth/access (spawn together):

**Agent A: Auth & Session Testing**
```
Read AgentPrompts/attack-a-auth.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/Security/Payloads/auth-bypass.yaml`

**Agent B: Access Control / IDOR**
```
Read AgentPrompts/attack-b-idor.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/IdorPentest/SKILL.md` (16-layer attack matrix), `~/.claude/skills/Security/Payloads/idor.yaml`

### Wait for Batch 1 → merge agent output files into state.json:

```bash
for agent_file in "${WORKDIR}/agents/attack-a-results.json" "${WORKDIR}/agents/attack-b-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {findings: (.[0].findings + (.[1].findings // []))}' \
      "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

### Batch 2 — Injection/SSRF (spawn together):

**Agent C: Injection (SQLi, XSS, SSTI, Command Injection)**
```
Read AgentPrompts/attack-c-injection.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/Security/Payloads/xss.yaml`, `sqli.yaml`, `ssti.yaml`

**Agent D: SSRF & Network**
```
Read AgentPrompts/attack-d-ssrf.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/Security/Payloads/ssrf.yaml`

### Wait for Batch 2 → merge agent output files into state.json:

```bash
for agent_file in "${WORKDIR}/agents/attack-c-results.json" "${WORKDIR}/agents/attack-d-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {findings: (.[0].findings + (.[1].findings // []))}' \
      "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

### Batch 3 — Logic/API (spawn together):

**Agent E: Business Logic & Race Conditions**
```
Read AgentPrompts/attack-e-business-logic.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/Security/Payloads/business-logic.yaml`, `~/.claude/skills/Security/WebAssessment/SKILL.md` (Business Logic Checklist)

**Agent F: API Deep Dive**
```
Read AgentPrompts/attack-f-api.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/ApiSecurity/SKILL.md` (OWASP API Top 10)

### Wait for Batch 3 → merge agent output files into state.json:

```bash
for agent_file in "${WORKDIR}/agents/attack-e-results.json" "${WORKDIR}/agents/attack-f-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {findings: (.[0].findings + (.[1].findings // []))}' \
      "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

### Batch 4 — File/WebSocket (spawn together):

**Agent G: File Upload & Deserialization**
```
Read AgentPrompts/attack-g-file-upload.md
Inject: TARGET, ID
```

**Agent H: WebSocket & Real-time**
```
Read AgentPrompts/attack-h-websocket.md
Inject: TARGET, ID
```

### After Batch 4 returns:

```bash
for agent_file in "${WORKDIR}/agents/attack-g-results.json" "${WORKDIR}/agents/attack-h-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {findings: (.[0].findings + (.[1].findings // []))}' \
      "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

1. Read state.json — review merged findings from all 4 batches
2. Deduplicate findings by endpoint + vulnerability class
3. Display attack summary: finding count by agent, severity distribution
4. Update state.json status to `phase-2b-complete`

### On ECONNRESET failure:
If any agent fails with ECONNRESET, retry it **alone** (no parallel agents) after a 10-second wait. Do not abandon the agent — its coverage matters.

---

## Phase 3 — Validation

**Purpose:** Confirm exploitability, chain vulnerabilities, classify severity.

Spawn validator agent:
```
Read AgentPrompts/validator.md
Inject: TARGET, ID
```
**References:** `~/.claude/skills/Security/ImpactValidator/SKILL.md`

The validator agent:
1. **Reproduces** each finding using the poc_curl or dev-browser PoC
2. **Chains** findings — attempts multi-step exploitation:
   - Info leak + IDOR = account takeover
   - SSRF + cloud metadata = RCE
   - XSS + CSRF = stored ATO
   - Race condition + payment = financial impact
3. **Classifies** severity (P1-P5):
   - **P1** ($5k-$50k): RCE, SQLi with data exfil, ATO, payment bypass, mass PII leak
   - **P2** ($2k-$10k): Stored XSS on critical page, SSRF to internal, privilege escalation
   - **P3** ($500-$3k): Reflected XSS, IDOR on non-sensitive data, info disclosure
   - **P4** ($100-$500): Self-XSS requiring social engineering, low-impact CSRF
   - **P5** (informational): Missing headers, verbose errors, no real impact
4. **Filters** — drops anything below P3 unless it chains to higher severity
5. Writes validated findings to `/tmp/pentest-{ID}/agents/validator-results.json`

After the validator returns, the orchestrator merges validated_findings into state.json:

```bash
agent_file="${WORKDIR}/agents/validator-results.json"
if [ -f "$agent_file" ]; then
  jq -s '.[0] * {validated_findings: (.[0].validated_findings + (.[1].validated_findings // []))}' \
    "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
    && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
fi
```

---

## Phase 4 — Reporting

**Purpose:** Generate bounty-ready report.

### Generate Report

Read validated findings from state.json and produce:

```markdown
# Bug Bounty Report — {target}
## Engagement ID: {pentest_id}
## Date: {date}
## Scope: {scope_summary}

## Executive Summary
- Findings: {count} validated vulnerabilities
- Critical (P1): {p1_count}
- High (P2): {p2_count}
- Medium (P3): {p3_count}
- Estimated bounty range: ${min}-${max}

## Findings

### F-001: {title}
**Severity:** P{n} | **Class:** {vuln_class} | **CVSS:** {score}
**Endpoint:** {method} {url}
**Impact:** {impact_description}

#### Steps to Reproduce
1. {step}
2. {step}

#### PoC
```bash
{poc_curl_command}
```

#### Evidence
{response_summary}

#### Remediation
{fix_recommendation}

---
{repeat for each finding}

## Vulnerability Chain Analysis
{description of how findings chain together for increased impact}

## Methodology
Automated assessment using BugBountyHunter orchestrator with:
- 3 parallel recon agents (asset discovery, content discovery, fingerprinting)
- 8 parallel attack agents (auth, IDOR, injection, SSRF, business logic, API, file upload, WebSocket)
- Automated validation with impact assessment
```

Save to `/tmp/pentest-{ID}/report.md`

### Display Summary

```
═══ BugBountyHunter Report ════════════════════
Target:    {target}
Duration:  {elapsed_time}
Findings:  {total} validated ({p1} P1, {p2} P2, {p3} P3)
Est. Bounty: ${min} - ${max}
Report:    /tmp/pentest-{ID}/report.md
═══════════════════════════════════════════════
```

### Offer Platform Formatting

Ask if the user wants individual findings formatted for:
- **HackerOne** submission format
- **Bugcrowd** submission format
- **Intigriti** submission format

---

## Tool Check

Before starting, verify tooling:
```bash
bash ~/.claude/skills/BugBountyHunter/check-tools.sh
```

## Skill Dependencies

| Skill | Path | Used By |
|-------|------|---------|
| Recon | `~/.claude/skills/Security/Recon/SKILL.md` | R1, R2, R3 agents |
| WebAssessment | `~/.claude/skills/Security/WebAssessment/SKILL.md` | E agent (business logic checklist) |
| DastAutomation | `~/.claude/skills/DastAutomation/SKILL.md` | R3 agent (vuln scanning) |
| ApiSecurity | `~/.claude/skills/ApiSecurity/SKILL.md` | F agent (API Top 10) |
| IdorPentest | `~/.claude/skills/IdorPentest/SKILL.md` | B agent (16-layer matrix) |
| ImpactValidator | `~/.claude/skills/Security/ImpactValidator/SKILL.md` | Validator agent |
| Payloads | `~/.claude/skills/Security/Payloads/` | C, D, E agents (attack payloads) |

## State File Schema

```json
{
  "id": "string — engagement ID",
  "target": "string — primary target domain",
  "status": "string — current phase",
  "scope": {
    "in_scope": ["array of glob patterns"],
    "out_of_scope": ["array of exclusions"],
    "rate_limit": "number — req/sec"
  },
  "auth": {
    "authenticated": "boolean",
    "cookies": [{"name": "", "value": "", "domain": ""}],
    "tokens": {"bearer": "", "jwt": ""},
    "csrf_token": "string or null"
  },
  "subdomains": ["array of discovered subdomains"],
  "discovered_endpoints": [
    {"url": "", "method": "", "params": [], "auth_required": "boolean"}
  ],
  "tech_stack": {
    "server": "", "framework": "", "language": "",
    "cdn": "", "waf": "", "cms": ""
  },
  "js_endpoints": ["array of URLs extracted from JS"],
  "cloud_assets": [{"provider": "", "url": "", "permissions": ""}],
  "parameters": ["array of discovered parameter names"],
  "findings": [
    {
      "id": "F-NNN",
      "agent": "letter",
      "class": "vuln class",
      "severity_estimate": "P1-P5",
      "validated": false,
      "endpoint": "URL",
      "method": "HTTP method",
      "payload": "what was sent",
      "response_summary": "key evidence",
      "poc_curl": "curl command",
      "impact": "attacker achieves",
      "chain_potential": "chains with"
    }
  ],
  "validated_findings": []
}
```
