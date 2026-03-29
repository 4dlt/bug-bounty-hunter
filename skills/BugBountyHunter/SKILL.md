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

## Agent Failure Retry Protocol

When any agent fails (ECONNRESET, timeout, or any spawn error), follow this graduated retry:

**Retry 1:** Wait 15 seconds. Retry the failed agent ALONE (no parallel agents).
**Retry 2:** Wait 30 seconds. Retry with a reduced prompt — remove Reference lines and tool descriptions, keep only the mission, methodology steps, and behavioral rules.
**Retry 3:** Wait 60 seconds. Final retry with minimal prompt — mission and behavioral rules only.
**Give up:** Log the coverage gap:
```bash
echo "[COVERAGE GAP] Agent ${AGENT_ID} failed after 4 attempts. Uncovered: ${AGENT_MISSION_SUMMARY}" >> "${WORKDIR}/coverage-gaps.txt"
```

**CRITICAL:** Between retries, verify your API connection before spawning:
```bash
curl -s -o /dev/null -w "%{http_code}" https://api.anthropic.com/v1/messages
# If this returns 000 or fails, the network is down — wait longer before using a retry attempt
```

Do NOT abandon an agent — its coverage matters. Every skipped agent is a blind spot in the assessment.

## Agent Timeout Policy

Agents are autonomous but not infinite. Apply these timeouts to prevent pipeline stalls:

| Agent Type | Base Timeout | Hard Ceiling |
|------------|-------------|--------------|
| Recon (R1-R3) | 10 minutes | 15 minutes |
| Attack (A-H) | max(10min, endpoint_count × 5s) | 30 minutes |
| Validator | max(15min, finding_count × 2min) | 45 minutes |

**Activity monitoring:** After spawning each batch, check the agent output files every 3 minutes:
```bash
# Check if agent is still producing output
LAST_MOD=$(stat -c %Y "${WORKDIR}/agents/${AGENT_ID}-results.json" 2>/dev/null || echo 0)
NOW=$(date +%s)
IDLE_SECONDS=$((NOW - LAST_MOD))
if [ "$IDLE_SECONDS" -gt 180 ]; then
  echo "[TIMEOUT WARNING] Agent ${AGENT_ID} idle for ${IDLE_SECONDS}s — may be stalled"
fi
```

**On timeout:** Do NOT discard partial work. Because agents write findings incrementally (Rule 6), their output file already contains everything discovered so far. Merge what exists and log the gap:
```bash
echo "[TIMEOUT] Agent ${AGENT_ID} hit ${ELAPSED}min ceiling. Partial results merged." >> "${WORKDIR}/coverage-gaps.txt"
```

**Key dependency:** This policy requires agents to write findings immediately (Rule 6 from the behavioral rules). If an agent batches findings at the end, a timeout loses all work.

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

### Input Sanitization

Validate and sanitize parsed inputs before injecting into agent prompts:

```bash
# Validate target doesn't contain shell metacharacters
if echo "{{TARGET}}" | grep -qP '[;&|$`><]'; then
  echo "[ERROR] Target contains shell metacharacters — aborting for safety"
  echo "Target must be a clean domain or URL (e.g., target.com or https://target.com)"
  # Stop execution
fi

# URL-encode target for safe use in curl commands
TARGET_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${TARGET}', safe='/:@'))" 2>/dev/null || echo "${TARGET}")

# Escape credentials for shell safety (if provided)
if [ -n "${CREDS}" ]; then
  CREDS_USER=$(echo "${CREDS}" | cut -d: -f1 | sed "s/'/'\\\\''/g")
  CREDS_PASS=$(echo "${CREDS}" | cut -d: -f2 | cut -d@ -f1 | sed "s/'/'\\\\''/g")
  LOGIN_URL=$(echo "${CREDS}" | sed 's/.*@//')
fi
```

Use `TARGET_ENCODED` in curl commands within agent prompts. Use `TARGET` for display and logging only.

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

### Generate Scope Allowlist

Convert scope patterns into an explicit domain allowlist for agents:

```bash
# Build explicit allowlist from scope
echo "{{TARGET}}" > "${WORKDIR}/scope-allowlist.txt"

# Extract in-scope entries
grep -A100 'in_scope:' "${WORKDIR}/scope.yaml" | grep '^ *-' | sed 's/.*- *"\(.*\)"/\1/' >> "${WORKDIR}/scope-allowlist.txt"

echo "[SCOPE] Allowlist created with $(wc -l < "${WORKDIR}/scope-allowlist.txt") entries"
```

After Phase 1 recon completes, update the allowlist with discovered in-scope subdomains:

```bash
# Append discovered subdomains that match scope patterns
if [ -f "${WORKDIR}/state.json" ]; then
  jq -r '.subdomains[]' "${WORKDIR}/state.json" >> "${WORKDIR}/scope-allowlist.txt"
  sort -u -o "${WORKDIR}/scope-allowlist.txt" "${WORKDIR}/scope-allowlist.txt"
  echo "[SCOPE] Allowlist updated with discovered subdomains: $(wc -l < "${WORKDIR}/scope-allowlist.txt") entries"
fi
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
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Recon/SKILL.md` (DomainRecon, CloudAssetDiscovery workflows)

**Agent R2: Content & API Discovery**
```
Read AgentPrompts/recon-r2-content.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Recon Batch 1/2 ══════════════════════"
echo "  Agents completed: R1, R2"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: R3 fingerprinting"
echo "═══════════════════════════════════════════════════════════"
```

### Batch 2 (spawn after Batch 1 completes):

**Agent R3: Tech Fingerprinting & Vulnerability Scanning**
```
Read AgentPrompts/recon-r3-fingerprint.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Recon Batch 2/2 ══════════════════════"
echo "  Agents completed: R3"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: Authentication (Phase 2)"
echo "═══════════════════════════════════════════════════════════"
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

If any agent fails, follow the **Agent Failure Retry Protocol** above.

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

### Verify Authentication

After extracting auth artifacts, verify the session actually works before proceeding:

```bash
# Test auth against common protected endpoints
AUTH_CHECK_URLS=("https://{{TARGET}}/api/me" "https://{{TARGET}}/api/user" "https://{{TARGET}}/api/profile" "https://{{TARGET}}/api/account" "https://{{TARGET}}/dashboard")

AUTH_VERIFIED=false
for url in "${AUTH_CHECK_URLS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$url" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Cookie: ${COOKIE_STRING}")
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
    AUTH_VERIFIED=true
    AUTH_CHECK_URL="$url"
    echo "[AUTH OK] Session verified at $url (HTTP $STATUS)"
    break
  fi
done

if [ "$AUTH_VERIFIED" = false ]; then
  echo "[AUTH FAILED] Could not verify authentication on any common endpoint."
  echo "Possible causes: wrong login selectors, CAPTCHA, MFA not handled, session not created."
  echo "Proceeding with unauthenticated testing — attack coverage will be limited."
fi
```

Update state.json auth section to include verification status:
```json
"auth": {
  "authenticated": true,
  "verified": true,
  "verified_at": "URL_THAT_WORKED",
  ...
}
```

Store `AUTH_CHECK_URL` for use in health checks between batches.

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

### Calculate Per-Agent Rate Limits

```bash
TOTAL_RATE=$(grep 'rate_limit:' "${WORKDIR}/scope.yaml" | awk '{print $2}')
AGENTS_PER_BATCH=2
AGENT_RATE=$((TOTAL_RATE / AGENTS_PER_BATCH))
echo "[RATE] Total: ${TOTAL_RATE} req/s | Per agent: ${AGENT_RATE} req/s"
```

Inject `AGENT_RATE` into each agent prompt template alongside TARGET and ID.

### Batch 1 — High-value auth/access (spawn together):

**Agent A: Auth & Session Testing**
```
Read AgentPrompts/attack-a-auth.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/auth-bypass.yaml`

**Agent B: Access Control / IDOR**
```
Read AgentPrompts/attack-b-idor.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Attack Batch 1/4 ══════════════════════"
echo "  Agents completed: A (auth), B (IDOR)"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: C (injection), D (SSRF)"
echo "═══════════════════════════════════════════════════════════"
```

### Auth Health Check

Before spawning next batch, verify auth is still valid:

```bash
if [ "$AUTH_VERIFIED" = true ]; then
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_CHECK_URL}" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Cookie: ${COOKIE_STRING}")
  if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    echo "[AUTH EXPIRED] Session expired between batches — re-authenticating..."
    # Re-run Phase 2 authentication flow
    # Update state.json with fresh tokens
    # Update JWT and COOKIE_STRING variables for next batch
  fi
fi
```

### Batch 2 — Injection/SSRF (spawn together):

**Agent C: Injection (SQLi, XSS, SSTI, Command Injection)**
```
Read AgentPrompts/attack-c-injection.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/xss.yaml`, `sqli.yaml`, `ssti.yaml`

**Agent D: SSRF & Network**
```
Read AgentPrompts/attack-d-ssrf.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Attack Batch 2/4 ══════════════════════"
echo "  Agents completed: C, D"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: E (business logic), F (API)"
echo "═══════════════════════════════════════════════════════════"
```

### Auth Health Check

Before spawning next batch, verify auth is still valid:

```bash
if [ "$AUTH_VERIFIED" = true ]; then
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_CHECK_URL}" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Cookie: ${COOKIE_STRING}")
  if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    echo "[AUTH EXPIRED] Session expired between batches — re-authenticating..."
    # Re-run Phase 2 authentication flow
    # Update state.json with fresh tokens
    # Update JWT and COOKIE_STRING variables for next batch
  fi
fi
```

### Batch 3 — Logic/API (spawn together):

**Agent E: Business Logic & Race Conditions**
```
Read AgentPrompts/attack-e-business-logic.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/business-logic.yaml`, `~/.claude/skills/Security/WebAssessment/SKILL.md` (Business Logic Checklist)

**Agent F: API Deep Dive**
```
Read AgentPrompts/attack-f-api.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Attack Batch 3/4 ══════════════════════"
echo "  Agents completed: E, F"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: G (file upload), H (WebSocket)"
echo "═══════════════════════════════════════════════════════════"
```

### Auth Health Check

Before spawning next batch, verify auth is still valid:

```bash
if [ "$AUTH_VERIFIED" = true ]; then
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_CHECK_URL}" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Cookie: ${COOKIE_STRING}")
  if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
    echo "[AUTH EXPIRED] Session expired between batches — re-authenticating..."
    # Re-run Phase 2 authentication flow
    # Update state.json with fresh tokens
    # Update JWT and COOKIE_STRING variables for next batch
  fi
fi
```

### Batch 4 — File/WebSocket (spawn together):

**Agent G: File Upload & Deserialization**
```
Read AgentPrompts/attack-g-file-upload.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**Agent H: WebSocket & Real-time**
```
Read AgentPrompts/attack-h-websocket.md
Inject: TARGET, ID
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Attack Batch 4/4 ══════════════════════"
echo "  Agents completed: G, H"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: Validation (Phase 3)"
echo "═══════════════════════════════════════════════════════════"
```

1. Read state.json — review merged findings from all 4 batches
2. Deduplicate findings using composite key `(normalized_path, parameter, vulnerability_class, payload_family)`:
   - **Normalize paths:** strip API version prefixes (`/api/v1/users` and `/api/v2/users` → `/api/users`)
   - **Same path + same parameter + same vuln class** = duplicate → keep higher severity
   - **Same path + different parameters + same vuln class** = distinct findings → keep both
   - **Different paths + same parameter + same vuln class + same response** = likely duplicate → merge, note both endpoints
3. Display attack summary: finding count by agent, severity distribution
4. Update state.json status to `phase-2b-complete`

If any agent fails, follow the **Agent Failure Retry Protocol** above.

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

### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P1=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P2=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
P3=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
ENDPOINT_COUNT=$(jq '.discovered_endpoints | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)
SUB_COUNT=$(jq '.subdomains | length' "${WORKDIR}/state.json" 2>/dev/null || echo 0)

echo "═══ Progress: Validation complete ══════════════════════"
echo "  Agents completed: Validator"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: Reporting (Phase 4)"
echo "═══════════════════════════════════════════════════════════"
```

---

## Phase 4 — Reporting

**Purpose:** Generate bounty-ready report.

### Include Coverage Gaps

If `${WORKDIR}/coverage-gaps.txt` exists, append to the report:

```markdown
## Coverage Gaps

The following test categories could not be completed due to agent failures:

{contents of coverage-gaps.txt}

These areas require manual testing or a re-run of the engagement.
```

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

## Phase 5 — Cleanup

After the report is delivered:

```bash
# Scrub auth tokens from state.json (security hygiene)
jq '.auth = {"authenticated": false, "scrubbed": true}' \
  "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"

# Remove agent output files (findings already merged into state.json)
rm -f "${WORKDIR}/agents/"*-results.json

echo "[CLEANUP] Auth tokens scrubbed from state.json"
echo "[CLEANUP] Agent output files removed"
echo "[CLEANUP] Report preserved at: ${WORKDIR}/report.md"
echo "[CLEANUP] State preserved at: ${WORKDIR}/state.json (tokens scrubbed)"
```

Ask user: "Delete the entire engagement directory (${WORKDIR})? Or keep for reference?"

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
