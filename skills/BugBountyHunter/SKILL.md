---
name: BugBountyHunter
description: Autonomous bug bounty pentesting orchestrator. Parses target and scope, runs parallel recon, authenticates, launches 13 parallel attack agents, validates findings via Advocate/Triager debate with HackerOne precedent gating, and produces bounty-ready reports. Triggers on "pentest target.com", "bug bounty", "find vulnerabilities in", "security assessment", "hack target.com for bugs".
---

# BugBountyHunter — Master Orchestrator

Autonomous bug bounty pentesting system. Parses target and scope, runs parallel recon, authenticates, launches parallel attacks, validates findings, and produces bounty-ready reports.

## v3.2-patch: Artifact-First Adversarial Validator (2026-04-19)

**This supersedes the self-grading validator flow for Phases 2.9, 3, and 4.** Older sections of this document still describe the legacy validator; trust this block when they conflict.

### Root cause the patch fixes

The 2026-04-18 23andMe run validated 10 findings (`$6,500–$17,200` claimed) that mostly would close at HackerOne triage as informative, duplicate, or program-excluded. Root cause: a single validator agent authored its own Q1–Q4 rationale AND verdict; every "BORDERLINE" confession in `reportability_audit` ended `gate_passed: true`. Bounty ranges were hallucinated (no precedent citation, no mechanism to validate).

### New flow

```
Phase 0    lib/detect-account-mode.sh   → writes pipeline-mode.json
Phase 1a-2 existing recon + attack (attack prompts now emit per-finding dirs)
Phase 2    lib/phase2-merge.sh          → collects findings/<id>/ into state.json.findings[]
Phase 2.9  lib/phase29-gate.sh          → mechanical gate (no LLM)
           Branches: PROGRAM_EXCLUDED_CLASS | UNPROVABLE_SINGLE_ACCOUNT |
                    PUBLIC_BY_DESIGN | MISSING_ARTIFACT | survive
           + chain-constituent rejection (CHAIN_CONSTITUENT_REJECTED)
Phase 3    AgentPrompts/advocate.md + AgentPrompts/triager.md spawned per survivor,
           then lib/phase3-debate.sh applies the decision rule:
             ACCEPT + precedent + high/med confidence → validated_findings[]
             else                                     → triager_closed[]
           Tie-breaks (low-confidence ACCEPT) → close. Ties always go to close.
Phase 4    lib/generate-report.sh       → report.md with precedent-cited-only
                                         bounty totals (never invents ranges)
```

### Core configs (load-bearing, read during Phase 2.9 and Phase 3)

- `config/ArtifactMatrix.yaml` — per-class required evidence artifacts, program-excluded classes, cross-tenant class list, class aliases, source-only P4 cap
- `config/PublicSafeList.yaml` — known-safe-by-design patterns (Datadog RUM, git SHA, robots.txt, etc.)
- `data/HackerOnePrecedents.jsonl` — precedent rows; Advocate must cite a non-placeholder resolved row to populate `bounty_estimate`. No cite → null bounty, no exceptions.
- `lib/yaml2json.sh` — Python3+PyYAML shim used throughout (yq is not available on target hosts)

### Agent retirement

- `AgentPrompts/validator.md` — **DEPRECATED** (renamed `.deprecated`). Replaced by the Advocate + Triager pair.

### Acceptance bars

- Apr-18 regression: ≥4 Phase 2.9 mechanical discards + ≤2 validated findings after full pipeline (test: `tests/smoke/test_apr18_full_regression.sh`)
- Bounty-hallucination canary: null precedent + non-null bounty NEVER validates (test: `tests/smoke/test_bounty_hallucination_canary.sh`)
- Schema: `state.json` gains `artifact_discarded[]`, `triager_closed[]`, `pipeline_mode`, `account_count` fields — enforced by `lib/validate-state-schema.sh`

### When in doubt

- Attack-agent output contract: see "Output Protocol v3.2 (SUPERSEDES earlier instructions)" section at the bottom of every `AgentPrompts/attack-*.md`
- Phase 0 mode detection and class allowlist per mode: see "Pipeline Mode (injected by orchestrator)" in attack prompts
- Plan doc: `docs/plans/2026-04-18-artifact-first-adversarial-validator.md` (implementation plan with all 22 tasks)
- Design PRD: `~/.claude/MEMORY/WORK/20260418-184500_bbh-v32-artifact-first-adversarial-validator/PRD.md`

---

## Behavioral Rules (MANDATORY — ZERO EXCEPTIONS)

1. **Never stop for things you can do yourself** — Token refresh, cookie extraction, CSRF tokens, login with provided creds. Read state.json, use dev-browser, handle it.
2. **Validate before reporting** — Every finding must be confirmed exploitable with a reproducible PoC curl command or dev-browser script. No theoretical findings.
3. **Chain everything** — Always attempt to escalate severity by combining findings. A P3 IDOR + a P4 info leak can become P1 ATO. See Phase 3.
4. **Respect scope** — Check scope.yaml before every request. Out-of-scope = hard block. No exceptions.
5. **Respect rate limits** — Honor program rate limits from scope.yaml. Default to 10 req/s if unspecified.
6. **Pull fresh techniques** — Use WebSearch to fetch latest CVEs and bypasses for the target tech stack before attack phase.
7. **Be autonomous** — Only stop for truly ambiguous scope decisions. Everything else, handle yourself.
8. **Prioritize depth over breadth** — One confirmed P2 beats ten unvalidated P4s.
9. **Browser-execution proof required for client-side findings** — XSS, DOM injection, open redirect, and any finding that depends on client-side rendering MUST be verified in dev-browser. An API response proving payload storage is NOT proof of exploitation — the client may sanitize it on render. If dev-browser shows the payload is neutralized (e.g., `javascript:` rewritten to `#`), the finding is NOT exploitable regardless of what the API returns.
10. **Never revoke, delete, or destroy shared auth state** — Do not revoke tokens, delete sessions, change passwords, or perform any destructive auth action that could break other running agents. Test revocation on TEMPORARY tokens you create specifically for that test, never on the shared pipeline tokens.
11. **Cross-reference every finding against the program's non-qualifying list** — Before reporting ANY finding, check `scope.yaml` `excluded_findings` and the program's non-qualifying vulnerability types. If the finding type is listed (e.g., "session management issues", "race conditions", "missing headers without impact"), it is NOT reportable regardless of your severity estimate. Log it as informational and move on.
12. **Severity is assigned by demonstrated impact, not vulnerability class** — Never assign severity from the vulnerability type alone ("Stored XSS = P2"). Severity comes from DEMONSTRATED impact: what data was actually stolen, what action was actually performed on behalf of another user, what security control was actually bypassed. If you cannot demonstrate impact beyond "the payload is stored", the finding is P5 informational at best.
13. **Source map analysis is THEORETICAL until browser-verified** — Finding `bypassSecurityTrustHtml()` in source code means the CODE EXISTS. It does not mean the vulnerability is exploitable. Label all source-map-derived findings as "THEORETICAL — requires browser verification" and do not assign severity above P4 until verified in an actual browser rendering context.
14. **The Reportability Test (MANDATORY before any finding is marked validated)** — Every finding must pass ALL FOUR questions:
    - Q1: "Did I trigger this in a real browser (dev-browser), not just curl?" — If no, it's UNVERIFIED.
    - Q2: "Is this finding type in the program's non-qualifying list?" — If yes, it's NOT REPORTABLE.
    - Q3: "Does the PoC demonstrate actual security impact (data theft, action on behalf of user, privilege escalation), not just payload reflection or storage?" — If no, it's INFORMATIONAL.
    - Q4: "Would a skilled bounty hunter with 100+ accepted reports submit this to THIS program?" — If no, don't report it.
    If ANY answer disqualifies the finding, do NOT mark it as validated. Log it as "observed but not reportable" with the specific disqualifying reason.

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

## Agent Refusal Recovery Protocol

Distinct from failure retry (which handles infrastructure errors), **refusal
recovery** handles the case where a subagent returns cleanly but its response
text refuses the mission ("I cannot", "I will not verify this is authorized",
etc.). Origin: v3 Phase 8 auth-acquire refused the first dispatch citing
inability to verify HackerOne authorization; I (orchestrator) had to run the
flow inline. v3.1 added explicit Authorization Context to auth-acquire.md to
prevent *that* refusal, but the general pattern can hit any subagent.

**Detection.** After every Agent tool return, scan the first 200 characters
of the response text (case-insensitive) for any of: `"I refuse"`, `"I cannot"`,
`"I will not"`, `"I decline"`, `"STOP"` at line start, `"halt"`. A match flags
the response as a refusal — do NOT silently accept it as a completed run.

**Classification + response.**

| Refusal class | Detection (substring in refusal text) | Response |
|---------------|---------------------------------------|----------|
| Missing authz context | "verify authorization", "HackerOne enrollment", "cannot independently verify", "scope.yaml is not sufficient" | Re-dispatch the agent with an explicit Authorization Context paragraph prepended: pointer to `~/Documents/Pentests/<target>/report-v*.md`, operator H1 alias from scope.yaml, and statement that enrollment was verified out-of-band |
| Human-required (MFA/captcha) | "MFA", "captcha", "2FA", "human input", "interactive challenge" | Trigger AskUser per Failure 2 path (existing v3 mechanism — orchestrator prompts operator for MFA code or interactive completion, then resumes) |
| Principled refusal (unrecoverable) | anything else — scope genuinely out-of-bounds, PII concern, target ambiguity | Log `[AGENT REFUSED] <agent_id>: <first 500 chars of refusal>` to `${WORKDIR}/coverage-gaps.txt`. Orchestrator falls back to **inline execution** of the agent's mission: read `AgentPrompts/<agent>.md`, perform the methodology steps directly from the orchestrator's own tool-calling loop |

**Hard cap: 2 refusal-recovery attempts per agent.** Track per-agent refusal
count in `${WORKDIR}/refusal-log.json`. On the 2nd refusal for the same agent
(regardless of class), log `[REFUSAL EXHAUSTED] <agent_id> — 2 recovery
attempts failed` to `coverage-gaps.txt` and trigger AskUser before continuing.
Do not attempt a 3rd recovery — the loop would waste budget.

**Cross-reference.** `AgentPrompts/auth-acquire.md` and `AgentPrompts/verifier.md`
both include explicit "Authorization Context" sections designed to prevent
class-1 (missing-authz) refusals up front. The orchestrator's fallback-to-inline
is the safety net for cases where the prompt-side preventive didn't suffice.

```bash
# Pseudocode — run after every Agent return
is_refusal() {
  local text="${1:0:200}"
  echo "$text" | grep -qiE '(^|[^a-z])(I refuse|I cannot|I will not|I decline)|^STOP|(^|[^a-z])halt([^a-z]|$)'
}

classify_refusal() {
  local text="$1"
  if echo "$text" | grep -qiE 'verify authorization|hackerone enrollment|cannot independently verify|scope\.yaml is not sufficient'; then
    echo "missing_authz"
  elif echo "$text" | grep -qiE 'mfa|captcha|2fa|human input|interactive challenge'; then
    echo "human_required"
  else
    echo "principled"
  fi
}

# Per-agent refusal counter
jq -n --arg agent "$AGENT_ID" '.["\($agent)"] = 0' > "${WORKDIR}/refusal-log.json"  # init once
# On each refusal: increment + branch per classify_refusal; if count == 2 → REFUSAL EXHAUSTED + AskUser
```

## Agent Timeout Policy

Agents should test as deeply and thoroughly as possible. No artificial time constraints — let agents go deep.

| Agent Type | Soft Warning (log only) | Hard Ceiling |
|------------|------------------------|--------------|
| Recon (R1-R4) | 15 minutes | 45 minutes |
| Attack (A-M) | 30 minutes | 60 minutes |
| Validator | 30 minutes | 90 minutes |

**Soft warning** = orchestrator logs "Agent X at {N} minutes" but does NOT kill. The agent continues working.
**Hard ceiling** = orchestrator collects whatever the agent has returned and moves on. Log the gap.

**On timeout:** Collect the agent's return text (which contains its JSON results block per the Agent Output Protocol). Merge what exists and log the gap:
```bash
echo "[TIMEOUT] Agent ${AGENT_ID} hit ${ELAPSED}min ceiling. Partial results from return text merged." >> "${WORKDIR}/coverage-gaps.txt"
```

## Agent Output Protocol (MANDATORY)

**Agents return results in their output text, NOT via filesystem writes.** Subagent filesystem writes do not reliably persist to the orchestrator's context. The orchestrator parses agent return text to extract results.

### Agent Output Rules

1. **Every agent MUST end its response with a structured JSON block** wrapped in a fenced code block tagged `json`. This is the LAST code block in the agent's response.
2. **Agents MAY also write to the filesystem as a backup**, but the orchestrator NEVER depends on those files existing.
3. **The orchestrator extracts the last ```json block** from the agent's return text and writes it to state.json and to `${WORKDIR}/agents/${AGENT_NAME}-results.json` from the parent process.

### Orchestrator Result Extraction

After each agent returns from the Agent tool, the orchestrator:

1. Extracts the last ```json block from the agent's return text
2. Writes it to `${WORKDIR}/agents/${AGENT_NAME}-results.json` (from orchestrator process — this WILL persist)
3. Merges findings into state.json
4. Updates pipeline-status.json for the monitor

```bash
# The orchestrator parses the agent's return text for the JSON results block
# Then writes the results file from the PARENT process (not the agent subprocess)
echo "$AGENT_JSON" > "${WORKDIR}/agents/${AGENT_NAME}-results.json"

# Merge findings into state.json
jq --argjson new "$(echo "$AGENT_JSON" | jq '.findings // []')" \
  '.findings += $new' "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" \
  && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"

# Update pipeline status for monitor
jq --arg agent "$AGENT_NAME" --arg time "$(date -Iseconds)" \
  '.last_agent_completed = $agent | .last_updated = $time | .agents_completed += 1 | .findings_count = (.findings_count + ($new | length))' \
  "${WORKDIR}/pipeline-status.json" > "${WORKDIR}/pipeline-status.tmp" \
  && mv "${WORKDIR}/pipeline-status.tmp" "${WORKDIR}/pipeline-status.json"
```

### Pipeline Status File

The orchestrator maintains `${WORKDIR}/pipeline-status.json` for the monitor agent:

```json
{
  "phase": "phase-2b-attack",
  "last_agent_completed": "attack-c",
  "agents_completed": 7,
  "agents_total": 18,
  "findings_count": 15,
  "last_updated": "2026-04-05T09:22:00+04:00"
}
```

Initialize this file in Phase 0 alongside state.json.

---

## Phase Gate Protocol (MANDATORY — ZERO EXCEPTIONS)

**Every phase transition has a gate.** You CANNOT skip a phase or jump to reporting early. The pipeline is sequential and mandatory. If a phase cannot be completed, you MUST:

1. **Log WHY** to `${WORKDIR}/coverage-gaps.txt` with specific reason (not "limited attack surface")
2. **Ask the user** via AskUserQuestion before skipping auth (Phase 2) or validation (Phase 3)
3. **Continue to the next phase** — a failed phase does NOT abort the pipeline

### Gate Checklist (verify at each transition)

| Transition | Gate Condition | If NOT met |
|------------|---------------|------------|
| Phase 0 → 1a | scope.yaml exists, user confirmed authorization | STOP — cannot proceed without scope |
| Phase 1a → 1b | Passive recon outputs `subdomains.txt` + login candidates list | Retry passive enumeration |
| Phase 1b → 1c | auth-acquire returned (success/partial/failed), user decision logged if AskUser fired, refresh-monitor + stale-watcher PIDs running | If `failed` and no user decision: AskUser path or interactive dev-browser fallback |
| Phase 1c → 2 | R1-R4 ran with authenticated context, state.json populated | Retry failed recon agents per Retry Protocol |
| Phase 2 batches | ALL 7 batches ATTEMPTED (A+B, C+D, E+F, G+H, I+J, K+L, M) | Log failed agents but NEVER skip a batch. Accessible targets get full agent battery even if some targets are WAF-blocked |
| Phase 2 → 2.5 | All 7 batches attempted AND Phase 2.5 trigger gate fires (no P1/P2 yet, <3 confirmed, or broker non-compliance observed) | Skip 2.5 if zero findings total OR ≥1 P1/P2 already present |
| Phase 2.5 → 2c | Up to 3 rounds of top-5 candidate re-attacks attempted, or an early P1/P2 exit fires | Exhaustion logged to coverage-gaps.txt; 2.5 is best-effort, never blocks 2c |
| Phase 2 → 3 | All 7 batches attempted, findings merged. `auth.refresh_failure_count <= 2` | If 3+ refresh failures: degraded-unauth mode logged to coverage-gaps.txt |
| Phase 3 → 4 | Validator agent ran, validated_findings populated | **MANDATORY:** Cannot generate report without validation pass |
| Phase 4 → 5 | Report generated; refresh-monitor + stale-watcher PIDs killed | Cleanup |

### Pipeline Completion Check (run before Phase 4)

Before generating the report, verify the pipeline was actually completed:

```bash
# Mandatory pipeline completion check
AGENTS_EXPECTED="r1 r2 r3 r4 attack-a attack-b attack-c attack-d attack-e attack-f attack-g attack-h attack-i attack-j attack-k attack-l attack-m validator"
AGENTS_MISSING=""
for agent in $AGENTS_EXPECTED; do
  if [ ! -f "${WORKDIR}/agents/${agent}-results.json" ]; then
    AGENTS_MISSING="${AGENTS_MISSING} ${agent}"
  fi
done

if [ -n "$AGENTS_MISSING" ]; then
  echo "═══ PIPELINE INCOMPLETE ═══════════════════════════════"
  echo "  Missing agent results:${AGENTS_MISSING}"
  echo "  These agents were never spawned or their results were lost."
  echo "  You MUST attempt these agents before generating the report."
  echo "  If they truly cannot run, log each to coverage-gaps.txt with a specific reason."
  echo "═══════════════════════════════════════════════════════════"
  # DO NOT proceed to Phase 4 — go back and run missing agents
fi
```

**CRITICAL:** "Limited attack surface" or "WAF blocking" is NOT a valid reason to skip attack agents. Attack agents test ACCESSIBLE targets too. If 3 of 7 targets are accessible, all 13 attack agents run against those 3 targets. WAF-blocked targets get logged as coverage gaps separately.

## WAF Bypass Protocol

**Triggers when:** Any in-scope target returns HTTP 403, connection reset, or a WAF block page during recon or attack phases.

**CRITICAL:** WAF blocking on some targets does NOT reduce testing on accessible targets. It is a per-target issue, not a pipeline-abort signal.

### Step 1: WAF Detection & Classification

After Phase 1 recon, audit target accessibility and identify WAF types:

```bash
# Target accessibility audit — run after R1-R4 merge
echo '{}' > "${WORKDIR}/target-accessibility.json"
for target in $(jq -r '.scope.in_scope[]' "${WORKDIR}/scope.yaml" 2>/dev/null || grep -A100 'in_scope:' "${WORKDIR}/scope.yaml" | grep '^ *-' | sed 's/.*- *"\(.*\)"/\1/'); do
  # Strip wildcard prefix
  clean_target=$(echo "$target" | sed 's/^\*\.//')
  STATUS=$(curl -s -o /tmp/waf-check-body.txt -w "%{http_code}" -D /tmp/waf-check-headers.txt "https://${clean_target}/" -H "X-Hackerone: ${H1_USER}" --connect-timeout 10 2>/dev/null || echo "000")

  # Detect WAF type from headers
  WAF_TYPE="none"
  if grep -qi 'akamai\|AkamaiGHost' /tmp/waf-check-headers.txt 2>/dev/null; then WAF_TYPE="akamai"; fi
  if grep -qi 'cf-ray' /tmp/waf-check-headers.txt 2>/dev/null; then WAF_TYPE="cloudflare"; fi
  if grep -qi 'x-imperva-id\|incap_ses' /tmp/waf-check-headers.txt 2>/dev/null; then WAF_TYPE="imperva"; fi
  if grep -qi 'x-amz-cf-id\|x-amzn-waf' /tmp/waf-check-headers.txt 2>/dev/null; then WAF_TYPE="aws_waf"; fi

  ACCESSIBLE="true"
  if [ "$STATUS" = "403" ] || [ "$STATUS" = "000" ]; then ACCESSIBLE="false"; fi

  echo "[WAF AUDIT] ${clean_target}: HTTP ${STATUS}, WAF: ${WAF_TYPE}, Accessible: ${ACCESSIBLE}"
done
```

Update state.json with a `target_accessibility` map so agents know which targets to focus on:

```json
"target_accessibility": {
  "target1.example.com": {"status": 200, "waf": "none", "accessible": true},
  "target2.example.com": {"status": 403, "waf": "akamai", "accessible": false, "bypass_attempted": false}
}
```

### Step 2: Browser-Based WAF Bypass (First Attempt)

Many WAFs (Akamai Bot Manager, Cloudflare) block automated curl but allow JavaScript-capable browsers. **Try dev-browser BEFORE giving up on a target:**

```bash
dev-browser --ignore-https-errors <<'EOF'
const page = await browser.getPage("waf-bypass");
await page.goto("https://TARGET_DOMAIN/", { waitUntil: "networkidle", timeout: 30000 });
// Akamai Bot Manager serves a JS challenge — the browser solves it automatically
await page.waitForTimeout(5000);  // Wait for challenge resolution
const status = await page.evaluate(() => document.title);
const cookies = await page.context().cookies();
const content = await page.snapshotForAI();
console.log(JSON.stringify({ title: status, cookies, accessible: !content.full.includes("Access Denied") }));
EOF
```

If the browser succeeds, extract session cookies and inject them into state.json for agent use.

### Step 3: 403 Header Bypass Techniques

Reference: `~/.claude/skills/Security/Payloads/bypass/403-bypass.yaml`

```bash
# Try header injection bypasses for each WAF-blocked target
BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Original-URL: /"
  "X-Rewrite-URL: /"
  "X-Custom-IP-Authorization: 127.0.0.1"
)

for header in "${BYPASS_HEADERS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET_DOMAIN/" -H "$header" -H "X-Hackerone: ${H1_USER}")
  if [ "$STATUS" != "403" ] && [ "$STATUS" != "000" ]; then
    echo "[WAF BYPASS] Header '$header' returned HTTP ${STATUS} — potential bypass!"
  fi
done
```

### Step 4: WAF-Specific Payload Selection for Attack Agents

When a target has a detected WAF type, inject WAF-specific bypass guidance into the attack agent prompts:

- **Akamai:** Reference `~/.claude/skills/Security/Payloads/xss/xss.yaml` section `waf_bypass_akamai` (prototype chain, constructor access, URL fragment, dynamic import)
- **Cloudflare:** Reference `xss.yaml` section `waf_bypass_cloudflare`
- **Imperva:** Reference `xss.yaml` section `waf_bypass_imperva`
- **AWS WAF:** Reference `xss.yaml` section `waf_bypass_aws_waf`
- **General:** Reference `~/.claude/skills/DastAutomation/SKILL.md` WAF Detection methodology (lines 435-491)

### Step 5: Log Inaccessible Targets

After all bypass attempts, log remaining blocked targets as specific coverage gaps:

```bash
# For each target still blocked after bypass attempts:
echo "[COVERAGE GAP] Target ${TARGET_DOMAIN} blocked by ${WAF_TYPE} WAF after browser bypass + header bypass attempts. Likely requires: Indian IP range, mobile app proxy, or authenticated browser session." >> "${WORKDIR}/coverage-gaps.txt"

# Update state.json
# target_accessibility.TARGET.bypass_attempted = true
# target_accessibility.TARGET.bypass_result = "failed"|"partial"|"success"
```

**IMPORTANT:** Blocked targets reduce the ATTACK SURFACE for those specific targets — they do NOT reduce the number of attack agents spawned. All 13 attack agents run against accessible targets.

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
  "js_secrets": [],
  "js_api_endpoints": [],
  "js_hidden_params": [],
  "js_frameworks": {},
  "cloud_assets": [],
  "parameters": [],
  "findings": [],
  "validated_findings": [],
  "agent_outputs_dir": "/tmp/pentest-{ID}/agents/"
}
```

### Initialize Exploitation State

```bash
cat > "${WORKDIR}/exploitation-state.json" << 'EOFSTATE'
{
  "last_updated": "",
  "findings": [],
  "tech_stack_updates": {},
  "blocked_paths": []
}
EOFSTATE
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

## Phase 1a — Passive Recon (No Target HTTP)

**Purpose:** Enumerate enough of the attack surface to find the login URL, without alerting WAFs or rate-limiters on the target.

**Allowed tools (passive-only):** subfinder, crt.sh / ctfr (certificate transparency), DNS lookup (dig/host), WHOIS, GitHub dorks (token-restricted code search), historical data (gau, waybackurls), Shodan / Censys API queries.

**FORBIDDEN in this phase:** ANY direct HTTP(S) request to in-scope domains. ffuf, katana, nuclei, curl against the target, dev-browser navigation — all wait until Phase 1c.

### Outputs

Write to:
- `${WORKDIR}/passive/subdomains.txt` — deduped list of in-scope subdomains discovered passively
- `${WORKDIR}/passive/discovered_login_candidates.txt` — subdomains/paths that look like auth endpoints (`auth.*`, `login.*`, `sso.*`, `accounts.*`, paths like `/login`, `/signin`, `/oauth/authorize`, `/.well-known/openid-configuration`)
- `${WORKDIR}/passive/whois.txt`, `${WORKDIR}/passive/dns.txt` — supporting data

### Phase 1a → 1b Gate

`${WORKDIR}/passive/subdomains.txt` MUST exist and be non-empty. If subfinder + crt.sh return zero results, log to `coverage-gaps.txt` with the specific failure (DNS misconfig, rate limit, etc.) and AskUser before proceeding to Phase 1b — without subdomain enumeration the auth-acquire agent has no login URL candidates.

---

## Phase 1b — Auth Acquisition + Refresh Validation (MOVED EARLIER)

**Purpose:** Establish authenticated session BEFORE recon and attack. The whole point of v3. If auth doesn't hold, the rest of the pipeline is wasted — fail fast here.

### Step 1: No-credentials gate

Check `scope.yaml` for an `auth:` block (with `username`+`password`, OR pre-extracted `cookies`/`jwt`/`oauth_refresh_token`). If absent:

```bash
HAS_CREDS=$(jq -r '(.auth // {}) | has("username") or has("cookies") or has("jwt") or has("oauth_refresh_token")' "${WORKDIR}/scope.yaml")
if [ "$HAS_CREDS" != "true" ]; then
  jq '.auth.status = "unauthenticated"' "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" \
    && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  echo "[AUTH GAP] No credentials in scope.yaml — pipeline will run unauthenticated. IDOR/priv-esc/business-logic attack agents will report reduced coverage." >> "${WORKDIR}/coverage-gaps.txt"
  # MANDATORY: AskUserQuestion with 3 options:
  #   (a) Pause for me to provide creds now — orchestrator waits, re-reads scope.yaml on resume
  #   (b) Continue unauthenticated — proceed with auth.status = "unauthenticated"
  #   (c) Abort — Phase 5 cleanup, no report
fi
```

Record user decision in `state.json.auth.user_decision` with timestamp.

### Step 2: Spawn `auth-acquire` agent

Spawn the `auth-acquire` agent (prompt at `AgentPrompts/auth-acquire.md`) with template substitutions for `{{TARGET}}`, `{{ID}}`, `{{AGENT_RATE}}`. Per-domain probing and SSO chain capture happen inside the agent.

### Step 3: Parse return JSON, write to state.json

The agent returns a single fenced ```json block per the existing Agent Output Protocol. Extract it and write `auth.*` fields to `${WORKDIR}/state.json`.

### Step 4: Validate state.json schema

```bash
"${SKILL_DIR}/lib/validate-state-schema.sh" "${WORKDIR}/state.json" || {
  echo "[FATAL] state.json schema invalid after auth-acquire — cannot proceed" >> "${WORKDIR}/coverage-gaps.txt"
  exit 1
}
```

### Step 5: Per-domain partial gate

If any domain in `auth.per_domain_status[]` has `verified == false`, run **AskUserQuestion** (Failure 4 in the design):

> "N of M in-scope domains authenticated. <list> require separate creds. Options: (a) Provide creds for those now, (b) Proceed — those domains get unauth-only attacks logged as gap, (c) Drop those domains from scope for this run."

Don't block on this — soft warning, single AskUser, then continue.

### Step 6: Spawn the right background helpers based on `auth_strategy`

The auth-acquire agent writes `state.json.auth.auth_strategy` (one of `jwt-oauth`, `session-cookie`, `static`, `none`). Spawn the helper that matches — both `refresh-monitor.sh` and `session-warmer.sh` self-bail if started against the wrong strategy, but the orchestrator should still pick correctly to avoid wasted process slots.

```bash
STRATEGY=$(jq -r '.auth.auth_strategy' "${WORKDIR}/state.json")
case "$STRATEGY" in
  jwt-oauth)
    WORKDIR="${WORKDIR}" "${SKILL_DIR}/lib/refresh-monitor.sh" &
    echo $! > "${WORKDIR}/refresh-monitor.pid"
    ;;
  session-cookie)
    WORKDIR="${WORKDIR}" "${SKILL_DIR}/lib/session-warmer.sh" &
    echo $! > "${WORKDIR}/session-warmer.pid"
    ;;
  static|none)
    echo "[1b] auth_strategy=$STRATEGY — no background refresh helper needed"
    ;;
esac

# Stale-watcher always runs — it's the orchestrator's hook for AskUser on auth.stale=true,
# regardless of which helper sets that flag.
WORKDIR="${WORKDIR}" "${SKILL_DIR}/lib/stale-watcher.sh" &
echo $! > "${WORKDIR}/stale-watcher.pid"
```

These run for the entire pentest. Phase 5 cleanup kills them.

### Phase 1b → 1c Gate

`auth.status` MUST be one of: `verified`, `partial`, `unauthenticated`. If `failed`: do NOT proceed — go back to Step 2 with classified-failure AskUser path (Failure 2 in the design — wrong creds / MFA detected / captcha / login URL 404), or interactive dev-browser fallback. Max 3 retries per pentest, then hard-fail with abort recommended.

---

## Phase 1c — Active Authenticated Recon (4 Agents, Batched)

**Authenticated context required.** This phase reads `state.json.auth.jwts.access_token` and `state.json.auth.cookies` and passes them to recon agents R1-R4. Each agent should append `Authorization: Bearer $TOKEN` (or use the cookies via the per-domain `auth_artifact` selector) to all HTTP requests against in-scope domains. If `auth.status == "unauthenticated"`, run as before but log `[REDUCED COVERAGE]` to `${WORKDIR}/coverage-gaps.txt` — without auth, the active recon will only see the public surface (5-10× smaller endpoint count).

Passive enumeration (subdomains, certificate transparency, GitHub dorks, WHOIS) already happened in Phase 1a — this phase is for ffuf, katana, nuclei, JS source map analysis, GraphQL introspection, and any other tool that hits the live target.

**Purpose:** Map the authenticated attack surface comprehensively before testing.

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
      js_endpoints: (.[0].js_endpoints + (.[1].js_endpoints // []) | unique),
      findings: (.[0].findings + (.[1].findings // []))
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
echo "  Next: R3 fingerprinting + R4 JS analysis"
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

**Agent R4: JavaScript Source Analysis**
```
Read AgentPrompts/recon-r4-js-analysis.md
Inject: TARGET={target}, ID={pentest_id}
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Recon/Workflows/JsAnalysis.md`

### After R3 and R4 return:

```bash
# After Batch 2 (R3, R4):
for agent_file in "${WORKDIR}/agents/r3-results.json" "${WORKDIR}/agents/r4-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {
      subdomains: (.[0].subdomains + (.[1].subdomains // []) | unique),
      discovered_endpoints: (.[0].discovered_endpoints + (.[1].discovered_endpoints // []) | unique_by(.url)),
      tech_stack: (.[0].tech_stack * (.[1].tech_stack // {})),
      cloud_assets: (.[0].cloud_assets + (.[1].cloud_assets // []) | unique_by(.url)),
      js_endpoints: (.[0].js_endpoints + (.[1].js_endpoints // []) | unique),
      js_secrets: (.[0].js_secrets + (.[1].js_secrets // []) | unique),
      js_api_endpoints: (.[0].js_api_endpoints + (.[1].js_api_endpoints // []) | unique),
      js_hidden_params: (.[0].js_hidden_params + (.[1].js_hidden_params // []) | unique),
      js_frameworks: (.[0].js_frameworks * (.[1].js_frameworks // {})),
      findings: (.[0].findings + (.[1].findings // []))
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

echo "═══ Progress: Recon Batch 2/2 ══════════════════════"
echo "  Agents completed: R3, R4"
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
3. **Run WAF Accessibility Audit** (see WAF Bypass Protocol Step 1) — classify each target as accessible/blocked, identify WAF types, populate `target_accessibility` in state.json
4. **Run WAF Bypass Protocol Steps 2-3** on any blocked targets — attempt browser-based and header-based bypasses before proceeding
5. Display target accessibility summary:
   - Accessible targets: {list}
   - WAF-blocked targets: {list} (with WAF type and bypass attempt results)
   - **If 0 accessible targets:** AskUserQuestion — "All targets are WAF-blocked. Options: (a) Provide VPN/proxy through target's geo, (b) Provide authenticated browser cookies, (c) Proceed with limited external testing"
6. Update state.json status to `phase-1-complete`

**GATE CHECK:** Verify R1, R2, R3, R4 all produced results files. If any missing, follow Agent Failure Retry Protocol. Do NOT proceed until all 4 are attempted.

If any agent fails, follow the **Agent Failure Retry Protocol** above.

---

## Phase 2 — Attack (13 Agents, 7 Batches — ALL BATCHES MANDATORY)

**Purpose:** Systematic vulnerability discovery across all attack classes.

**Auth contract (v3):** Attack agents read fresh tokens from `state.json.auth.jwts.access_token` (kept current by `lib/refresh-monitor.sh` background loop) and per-domain auth-artifact selection from `state.json.auth.per_domain_status[<domain>].auth_artifact`. The prompts already say "read auth from state.json" generically — this contract makes the canonical paths explicit. No per-prompt edits needed; all 13 attack agents already comply with the generic guidance.

**BATCH PROGRESSION ENFORCEMENT (ZERO EXCEPTIONS):**
- ALL 7 batches (A+B, C+D, E+F, G+H, I+J, K+L, M) MUST be attempted. You cannot skip to reporting after batch 1.
- If a batch's agents find no results, that is NOT a reason to skip subsequent batches. Different agents test different vulnerability classes.
- WAF-blocked targets do NOT reduce the number of agents spawned. Agents test ACCESSIBLE targets. If 3 of 7 targets are accessible, all 13 agents run against those 3 targets.
- Inject the `target_accessibility` map from state.json into each agent prompt so agents know which targets to focus on and which WAF bypass techniques to try.
- If you feel like skipping a batch, STOP. That instinct is the exact failure mode this rule prevents.

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

### Inter-batch Health Check (before each batch — v3.2, M9)

Before spawning batch N>1, probe the primary auth-check URL. If the auth
plane has silently expired between batches, spawning the next batch wastes
its quota on 401/403/429 responses; break out to the stale-watcher path
instead.

```bash
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "$AUTH_CHECK_URL" \
  -H "Cookie: $COOKIE_STRING" -H "Authorization: Bearer $JWT" -m 5)
if [ "$HEALTH" = "401" ] || [ "$HEALTH" = "403" ] || [ "$HEALTH" = "429" ]; then
  jq --arg s "$HEALTH" \
    '.auth.stale = true | .auth.failure_reason = "inter_batch_health_check_failed_" + $s' \
    "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" \
    && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  # lib/stale-watcher.sh (v3.1 background loop) sees auth.stale=true and fires
  # AskUser for operator re-auth. Break out of the batch loop until it returns.
  break
fi
```

### Preliminary Report Streaming (after each batch — v3.2, M7)

Immediately after a batch's findings merge into state.json, stream any
P1/P2 browser-verified or OOB-verified findings to `preliminary-report.md`.
This means the operator can inspect high-severity hits mid-run without
waiting for Phase 4.

```bash
jq -r '.findings[]
  | select(.severity_estimate == "P1" or .severity_estimate == "P2")
  | select((.validation_evidence.browser_verified // false)
        or (.validation_evidence.oob_callback_received // false))
  | "## \(.id): \(.severity_estimate) — \(.class)\nEndpoint: \(.endpoint)\nImpact: \(.impact_demonstrated)\n"' \
  "${WORKDIR}/state.json" >> "${WORKDIR}/preliminary-report.md"
```

### Broker Compliance Gate (after each batch — v3.2)

After every attack batch returns and its results are merged into `state.json`,
verify each agent invoked `broker.py` (LightRAG technique fetch). Non-compliant
agents get their round-1 findings tagged and a single re-spawn with an
enforcement prefix. On second non-compliance the orchestrator proceeds and
logs `[BROKER INFRA ISSUE]` so the validator can demote those findings
(composability penalty applied programmatically in Phase 3).

```bash
# After batch X completes (adjust agent list per batch: batch1=attack-a,attack-b; batch2=attack-c,attack-d; etc.)
for agent_id in attack-a attack-b; do
  if ! "${SKILL_DIR}/lib/broker-compliance-check.sh" "$agent_id" 2>>"${WORKDIR}/coverage-gaps.txt"; then
    # Tag this agent's findings as round-1 (broker-non-compliant) before re-spawn
    LETTER=$(echo "$agent_id" | sed 's/attack-//' | tr '[:lower:]' '[:upper:]')
    jq --arg ag "$LETTER" '
      .findings |= map(
        if .agent == $ag and ((.discovery_round // 2) == 2)
        then .discovery_round = 1
        else .
        end
      )
    ' "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"

    # Re-spawn agent ONCE with enforcement prefix (see template below).
    # If the second run is also non-compliant, log and move on — validator will demote -1 tier.
    spawn_agent_with_enforcement "$agent_id"
  fi
done
```

**Enforcement prefix prompt** (prepended on re-spawn):

```
ENFORCEMENT NOTICE — your previous run did not invoke broker.py. This is round 2 of 2.
Your previous findings are preserved. You MUST run:
  python ~/.claude/skills/Security/KnowledgeBase/broker.py \
    --agent {{AGENT_ID}} --category {{CATEGORY}} \
    --waf {{WAF}} --tech-stack {{STACK}} --action get-techniques
AS THE FIRST tool call. Use the returned techniques. NEVER use hardcoded inline payloads.
At end of run, you MUST also call:
  python ~/.claude/skills/Security/KnowledgeBase/broker.py \
    --agent {{AGENT_ID}} --action log-coverage --workdir {{WORKDIR}} \
    --tried N --findings-count N
```

If round-2 is also non-compliant: append `[BROKER INFRA ISSUE] {{AGENT_ID}}` to
`${WORKDIR}/coverage-gaps.txt` and proceed with the next batch. The validator's
Phase 3 composability rule demotes round-1 findings by one tier (see
`AgentPrompts/validator.md § Reportability Test`).

### Batch 1 — High-value auth/access (spawn together):

**Agent A: Auth & Session Testing**
```
Read AgentPrompts/attack-a-auth.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/auth/auth-bypass.yaml`

**Agent B: Access Control / IDOR**
```
Read AgentPrompts/attack-b-idor.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/IdorPentest/SKILL.md` (16-layer attack matrix), `~/.claude/skills/Security/Payloads/access-control/idor.yaml`

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

echo "═══ Progress: Attack Batch 1/7 ══════════════════════"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 2 — Injection/SSRF (spawn together):

**Agent C: Injection (SQLi, XSS, SSTI, Command Injection)**
```
Read AgentPrompts/attack-c-injection.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/xss/xss.yaml`, `~/.claude/skills/Security/Payloads/injection/sqli.yaml`, `~/.claude/skills/Security/Payloads/server-side/ssti.yaml`

**Agent D: SSRF & Network**
```
Read AgentPrompts/attack-d-ssrf.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/server-side/ssrf.yaml`

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

echo "═══ Progress: Attack Batch 2/7 ══════════════════════"
echo "  Agents completed: C (injection), D (SSRF)"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 3 — Logic/API (spawn together):

**Agent E: Business Logic & Race Conditions**
```
Read AgentPrompts/attack-e-business-logic.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**References:** `~/.claude/skills/Security/Payloads/logic/business-logic.yaml`, `~/.claude/skills/Security/WebAssessment/SKILL.md` (Business Logic Checklist)

**Agent F: API Deep Dive**
```
Read AgentPrompts/attack-f-api.md
Inject: TARGET, ID, AGENT_RATE
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

echo "═══ Progress: Attack Batch 3/7 ══════════════════════"
echo "  Agents completed: E (business logic), F (API)"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 4 — File/WebSocket (spawn together):

**Agent G: File Upload & Deserialization**
```
Read AgentPrompts/attack-g-file-upload.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**Agent H: WebSocket & Real-time**
```
Read AgentPrompts/attack-h-websocket.md
Inject: TARGET, ID, AGENT_RATE
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

echo "═══ Progress: Attack Batch 4/7 ══════════════════════"
echo "  Agents completed: G (file upload), H (WebSocket)"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: I (client-side), J (protocol)"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 5 — Client-Side/Protocol (spawn together):

**Agent I: Client-Side Attacks (XSS deep, DOM clobbering, prototype pollution)**
```
Read AgentPrompts/attack-i-client-side.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**Agent J: Protocol Attacks (request smuggling, cache poisoning, host header)**
```
Read AgentPrompts/attack-j-protocol.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

### After Batch 5 returns:

```bash
for agent_file in "${WORKDIR}/agents/attack-i-results.json" "${WORKDIR}/agents/attack-j-results.json"; do
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

echo "═══ Progress: Attack Batch 5/7 ══════════════════════"
echo "  Agents completed: I (client-side), J (protocol)"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: K (config), L (deserialization)"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 6 — Config/Deserialization (spawn together):

**Agent K: Configuration & Access Control (CORS, CSRF, clickjacking, open redirect)**
```
Read AgentPrompts/attack-k-config.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

**Agent L: Deserialization & XXE**
```
Read AgentPrompts/attack-l-deserialization.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above.

### After Batch 6 returns:

```bash
for agent_file in "${WORKDIR}/agents/attack-k-results.json" "${WORKDIR}/agents/attack-l-results.json"; do
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

echo "═══ Progress: Attack Batch 6/7 ══════════════════════"
echo "  Agents completed: K (config), L (deserialization)"
echo "  Subdomains: ${SUB_COUNT} | Endpoints: ${ENDPOINT_COUNT}"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: M (race conditions)"
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
    # Token refresh handled by lib/refresh-monitor.sh — read fresh state.json.auth.jwts.access_token
  fi
fi
```

### Batch 7 — Race Conditions (spawn solo — needs full endpoint discovery):

**Agent M: Race Condition Testing (parallel timing, TOCTOU, double-spend)**
```
Read AgentPrompts/attack-m-race-condition.md
Inject: TARGET, ID, AGENT_RATE
Launch via Agent tool
```
Apply timeout per the **Agent Timeout Policy** above. Agent M runs last because it needs the complete endpoint map from all prior agents.

### After Batch 7 returns:

```bash
agent_file="${WORKDIR}/agents/attack-m-results.json"
if [ -f "$agent_file" ]; then
  jq -s '.[0] * {findings: (.[0].findings + (.[1].findings // []))}' \
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

echo "═══ Progress: Attack Batch 7/7 ══════════════════════"
echo "  Agents completed: M (race conditions)"
echo "  Findings: ${FINDING_COUNT} (${P1} P1, ${P2} P2, ${P3} P3)"
echo "  Next: Chain Evaluation (Phase 2c)"
echo "═══════════════════════════════════════════════════════════"
```

### Merge Exploitation State

After each attack agent batch, extract confirmed findings into exploitation-state.json:

```bash
for agent_file in "${WORKDIR}/agents/"attack-*-results.json; do
  AGENT_NAME=$(basename "$agent_file" | sed 's/-results.json//')
  if [ -f "$agent_file" ]; then
    jq --arg agent "$AGENT_NAME" '
      .findings // [] | map(select(.confirmed == true)) | map(. + {agent: $agent})
    ' "$agent_file" > /tmp/new-findings.json 2>/dev/null

    if [ -s /tmp/new-findings.json ] && [ "$(jq length /tmp/new-findings.json 2>/dev/null)" -gt 0 ]; then
      jq --slurpfile new /tmp/new-findings.json '
        .findings += $new[0] |
        .last_updated = now
      ' "${WORKDIR}/exploitation-state.json" > "${WORKDIR}/exploitation-state.tmp" \
        && mv "${WORKDIR}/exploitation-state.tmp" "${WORKDIR}/exploitation-state.json"
    fi
  fi
done
```

1. Read state.json — review merged findings from all 7 batches
2. Deduplicate findings using composite key `(normalized_path, parameter, vulnerability_class, payload_family)`:
   - **Normalize paths:** strip API version prefixes (`/api/v1/users` and `/api/v2/users` → `/api/users`)
   - **Same path + same parameter + same vuln class** = duplicate → keep higher severity
   - **Same path + different parameters + same vuln class** = distinct findings → keep both
   - **Different paths + same parameter + same vuln class + same response** = likely duplicate → merge, note both endpoints
3. Display attack summary: finding count by agent, severity distribution
4. Update state.json status to `phase-2b-complete`

If any agent fails, follow the **Agent Failure Retry Protocol** above.

---

## Phase 2.5 — Deep Re-attack Pass (v3.2)

**Purpose:** After the broad 7-batch sweep, route the most promising surviving
endpoints through a second, deeper attack pass aimed at upgrading P3/P4
surface findings to P1/P2 exploit proofs. This addresses the "spray-and-decide"
failure mode observed in the forensic audit where agents ran one payload per
param and moved on.

**Trigger gate:** Run Phase 2.5 if ANY of these are true after Phase 2:
- `findings | length > 0` AND no finding has `severity_estimate == "P1"` or `"P2"`
- `findings[] | select(.confirmed == true) | length < 3`
- At least one agent had a broker compliance failure (score the pass with the extra time we bought)

Otherwise skip straight to Phase 2c.

### Top-N candidate selection

```bash
# Round 1: take top 5 by score
CANDIDATES=$("${SKILL_DIR}/lib/score-candidates.sh" "${WORKDIR}/state.json" 0 5)
echo "$CANDIDATES" | jq -r '.[] | "[\(.score)] \(.method) \(.endpoint)"'
```

Each candidate carries its score and the matching signal booleans (has_5xx,
reflected, waf_passed, interesting_param, state_changing, is_authed). Cap:
**15 candidates total across all rounds (skip 0/5/10).**

### Per-candidate agent routing

For each candidate, route to the right attack agent based on its signals:

| Primary signal | Agent | Why |
|----------------|-------|-----|
| reflected | attack-c-injection | XSS / reflected injection deep dive |
| interesting_param + `?id=`, `?user=` | attack-b-idor | IDOR with enumeration |
| interesting_param + `?url=`, `?redirect=` | attack-d-ssrf | SSRF / open-redirect chain |
| state_changing + authed | attack-e-business-logic | mass assignment / auth bypass |
| has_5xx | attack-c-injection | error-based injection probing |
| default | attack-f-api | generic API deep probe |

Spawn agents in pairs (max 2 concurrent, same as Phase 2) with the broker
compliance gate active.

### Race auto-test for state-changing candidates (M6)

```bash
for cand in $(echo "$CANDIDATES" | jq -c '.[] | select(.state_changing)'); do
  url=$(echo "$cand" | jq -r '.endpoint')
  method=$(echo "$cand" | jq -r '.method')
  "${SKILL_DIR}/lib/race-test.sh" "$url" "$method" "${COOKIE_STRING}" \
    >> "${WORKDIR}/phase2.5-race-results.jsonl"
done
```

Any race hit (response variability indicating counter race) gets appended as
a `race_condition` finding.

### Evaluation gate (after round completes)

```bash
HIGH_SEV=$(jq '[.findings[] | select(.discovery_phase == "2.5" and (.severity_estimate == "P1" or .severity_estimate == "P2"))] | length' "${WORKDIR}/state.json")
if [ "$HIGH_SEV" -gt 0 ]; then
  echo "[Phase 2.5] round produced P1/P2 — stop escalating, proceed to Phase 2c"
  # break out of the rounds loop
fi
```

### 3-round escalation

If round 1 yielded zero P1/P2, run round 2 (skip 5, take 5) with the same
routing. If round 2 still empty, run round 3 (skip 10, take 5) — this is
the hard cap. Tag every Phase 2.5 finding with `discovery_phase: "2.5"` and
`discovery_round: 1|2|3` before merging into state.json; the validator
uses these fields in the composability rule.

### Exhaustion logging

If all 3 rounds end with no P1/P2, log `[PHASE 2.5 EXHAUSTED] 15 candidates
attempted, max severity P3` to `${WORKDIR}/coverage-gaps.txt` and proceed.
Phase 2.5 is best-effort, not a hard gate.

---

## Phase 2c — Chain Evaluation (Dynamic Dependency Graph)

**Purpose:** Evaluate exploitation state for chaining opportunities before validation.

After all attack agent batches complete, evaluate chain rules:

### Chain Rules

| Finding A | + Finding B | Chain Test |
|-----------|-------------|------------|
| open-redirect | oauth-misconfig | redirect_uri token theft → ATO |
| open-redirect | ssrf | redirect-to-internal network access |
| open-redirect | cors-misconfig | origin validation bypass via redirect |
| idor | info-leak | escalate to ATO via exposed PII |
| xss | csrf | stored attack chain |
| cors-misconfig | auth-bypass | cross-origin data theft |
| ssrf | cloud-metadata | cloud credential theft |
| race-condition | payment-flow | double-spend |
| jwt-alg-confusion | idor | forge token for other users |

### Chain Detection Logic

```bash
FINDINGS=$(jq -r '.findings[].type' "${WORKDIR}/exploitation-state.json" 2>/dev/null | sort -u)
CHAINS_FOUND=0

check_chain() {
  local type_a="$1" type_b="$2" chain_desc="$3"
  if echo "$FINDINGS" | grep -q "$type_a" && echo "$FINDINGS" | grep -q "$type_b"; then
    echo "[CHAIN DETECTED] $type_a + $type_b → $chain_desc"
    CHAINS_FOUND=$((CHAINS_FOUND+1))
    return 0
  fi
  return 1
}

check_chain "open-redirect" "oauth" "redirect_uri token theft"
check_chain "open-redirect" "ssrf" "redirect-to-internal"
check_chain "open-redirect" "cors" "origin validation bypass via redirect"
check_chain "idor" "info-leak" "escalate to ATO"
check_chain "xss" "csrf" "stored attack chain"
check_chain "cors" "auth" "cross-origin data theft"
check_chain "ssrf" "cloud" "cloud credential theft"
check_chain "race-condition" "payment" "double-spend"
check_chain "jwt" "idor" "forge token for other user"

echo "═══ Chain Evaluation: ${CHAINS_FOUND} chains detected ═══"
```

### Spawn Chain Agents

For each chain detected, spawn a focused chain-testing agent with:
- The two findings (endpoints, details) from exploitation-state.json
- The chain hypothesis to test
- Broker access for additional techniques

### Query LightRAG for Novel Chains

Beyond hardcoded rules, query the Knowledge Broker for creative chains:

```bash
FINDING_TYPES=$(jq -r '.findings[].type' "${WORKDIR}/exploitation-state.json" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
if [ -n "$FINDING_TYPES" ]; then
  python ~/.claude/skills/Security/KnowledgeBase/broker.py \
    --agent orchestrator --action chain-suggestions \
    --findings "$FINDING_TYPES"
fi
```

---

## Phase 3 — Validation (MANDATORY — CANNOT SKIP)

**Purpose:** Confirm exploitability, chain vulnerabilities, classify severity.

**THIS PHASE CANNOT BE SKIPPED UNDER ANY CIRCUMSTANCE.** Even if Phase 2b produced 0 high-severity findings, the validator agent still:
- Attempts its own discovery by probing endpoints from state.json
- Attempts vulnerability chaining (combining low-severity findings into high-severity chains)
- Confirms or rejects every finding with reproducible PoC
- Without this phase, the report contains UNVALIDATED findings — worthless for bounty submission

**If you are about to jump to Phase 4 without running the validator, STOP. You are about to produce an incomplete assessment.**

Spawn validator agent:
```
Read AgentPrompts/validator.md
Inject: TARGET, ID
Launch via Agent tool
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

**PRE-REPORT GATE:** Before generating the report, run the Pipeline Completion Check from the Phase Gate Protocol. If any agents are missing, go back and run them. Only proceed to report generation after the check passes or all missing agents are logged to coverage-gaps.txt with specific reasons.

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

#### Reportability audit (v3.2)
- {{Q1_status}} Q1 (class-aware evidence): {{evidence_summary}}
- {{Q2_status}} Q2 (not in program exclusions): {{class}} {{not_in_excluded ? "not in" : "IN"}} scope.yaml.excluded_findings
- {{Q3_status}} Q3 (impact demonstrated): {{impact_demonstrated || "MISSING"}}
- {{Q4_status}} Q4 (would a hunter submit this solo?): {{class_in_low_list ? ("low-class " + (in_chain ? "BUT in chain " + chain_id : (has_override_kw ? "BUT override keyword present: " + keyword : "solo — demoted P5"))) : "high-value class"}}
- Discovery: Phase {{discovery_phase}} round {{discovery_round}} ({{broker_compliant ? "broker-compliant" : "broker non-compliant — demoted -1 tier"}})

---
{repeat for each finding}

## Vulnerability Chain Analysis
{description of how findings chain together for increased impact}

## Methodology
Automated assessment using BugBountyHunter orchestrator with:
- 4 parallel recon agents (asset discovery, content discovery, fingerprinting, JS analysis)
- 13 parallel attack agents (auth, IDOR, injection, SSRF, business logic, API, file upload, WebSocket, client-side, protocol, config, deserialization, race conditions)
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

### Stop background helpers spawned in Phase 1b

Kill the refresh-monitor / session-warmer / stale-watcher background loops before scrubbing state. They hold no resources but should be terminated cleanly so future pentests in the same session don't see orphan processes.

```bash
for pidfile in "${WORKDIR}/refresh-monitor.pid" "${WORKDIR}/session-warmer.pid" "${WORKDIR}/stale-watcher.pid"; do
  if [ -f "$pidfile" ]; then
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
  fi
done
```



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
| DastAutomation | `~/.claude/skills/DastAutomation/SKILL.md` | R3 agent (vuln scanning), WAF bypass (detection + payload selection) |
| ApiSecurity | `~/.claude/skills/ApiSecurity/SKILL.md` | F agent (API Top 10) |
| IdorPentest | `~/.claude/skills/IdorPentest/SKILL.md` | B agent (16-layer matrix) |
| ImpactValidator | `~/.claude/skills/Security/ImpactValidator/SKILL.md` | Validator agent |
| Payloads | `~/.claude/skills/Security/Payloads/` | C, D, E agents (attack payloads) |
| 403 Bypass | `~/.claude/skills/Security/Payloads/bypass/403-bypass.yaml` | WAF Bypass Protocol (header injection, path manipulation) |
| XSS WAF Bypass | `~/.claude/skills/Security/Payloads/xss/xss.yaml` | WAF Bypass Protocol (Akamai, Cloudflare, Imperva, AWS WAF sections) |

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
  "target_accessibility": {
    "example.com": {"status": 200, "waf": "none", "accessible": true, "bypass_attempted": false},
    "blocked.com": {"status": 403, "waf": "akamai", "accessible": false, "bypass_attempted": true, "bypass_result": "failed"}
  },
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
