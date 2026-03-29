# BugBountyHunter Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 16 architecture findings to make BugBountyHunter reliable and safe for production bug bounty engagements.

**Architecture:** All changes are to markdown skill files — SKILL.md (orchestrator) and AgentPrompts/*.md (agent instructions). No runtime code. Changes modify how Claude Code agents behave during engagements by rewriting their prompt instructions.

**Tech Stack:** Claude Code skills (markdown), bash (utility scripts)

---

## Phase 1 — Stop the Bleeding (Production Reliability)

### Task 1: Fix State File Race Conditions (C2)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:108-132` (state.json init)
- Modify: `skills/BugBountyHunter/SKILL.md:143-195` (Phase 1 recon)
- Modify: `skills/BugBountyHunter/SKILL.md:247-336` (Phase 2b attack)
- Modify: `skills/BugBountyHunter/AgentPrompts/recon-r1-assets.md:109-112`
- Modify: `skills/BugBountyHunter/AgentPrompts/recon-r2-content.md` (output section)
- Modify: `skills/BugBountyHunter/AgentPrompts/recon-r3-fingerprint.md` (output section)
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-a-auth.md:142-160`
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-b-idor.md:170-188`
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-c-injection.md:183-200`
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-d-ssrf.md:173-191`
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-e-business-logic.md` (output section)
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-f-api.md` (output section)
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-g-file-upload.md` (output section)
- Modify: `skills/BugBountyHunter/AgentPrompts/attack-h-websocket.md` (output section)

**Step 1: Update state.json initialization to create agent output directory**

In `SKILL.md` Phase 0, after the `mkdir -p "${WORKDIR}"` line, add:

```bash
# Create per-agent output directory
mkdir -p "${WORKDIR}/agents"
```

And add to the initial state.json a note:

```json
{
  "id": "pentest-{ID}",
  "target": "target.com",
  "status": "phase-0-scope",
  "agent_outputs_dir": "/tmp/pentest-{ID}/agents/",
  ...
}
```

**Step 2: Update all agent prompts — agents write to their own file, not state.json**

In EVERY agent prompt file, change the behavioral rule from:

```
5. Write findings to /tmp/pentest-{{ID}}/state.json
```

To:

```
5. Write findings to /tmp/pentest-{{ID}}/agents/AGENT_ID-results.json (e.g., r1-results.json, attack-a-results.json)
6. Write each finding IMMEDIATELY upon discovery — do not batch. One JSON object per finding, appended to your results file.
7. You may READ state.json for recon data and auth tokens, but NEVER write to it. Only the orchestrator writes to state.json.
```

Where `AGENT_ID` matches each agent's identifier: `r1`, `r2`, `r3`, `attack-a` through `attack-h`, `validator`.

**Step 3: Update SKILL.md orchestrator — merge after each batch**

In Phase 1, after "Wait for Batch 1 to return", replace "merge results into state.json" with:

```markdown
### After Batch 1 returns:
1. Read `/tmp/pentest-{{ID}}/agents/r1-results.json` and `/tmp/pentest-{{ID}}/agents/r2-results.json`
2. Merge into state.json using jq:
   ```bash
   # Merge R1 subdomains
   jq -s '.[0] * {subdomains: (.[0].subdomains + .[1].subdomains | unique)}' \
     "${WORKDIR}/state.json" "${WORKDIR}/agents/r1-results.json" > "${WORKDIR}/state.tmp" \
     && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"

   # Merge R2 endpoints
   jq -s '.[0] * {discovered_endpoints: (.[0].discovered_endpoints + .[1].discovered_endpoints | unique_by(.url))}' \
     "${WORKDIR}/state.json" "${WORKDIR}/agents/r2-results.json" > "${WORKDIR}/state.tmp" \
     && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
   ```
3. Only THEN spawn Batch 2 (R3).
```

Apply the same merge pattern after each attack batch, merging findings:

```bash
# After each attack batch, merge findings from both agents
for agent_file in "${WORKDIR}/agents/attack-{X}-results.json" "${WORKDIR}/agents/attack-{Y}-results.json"; do
  if [ -f "$agent_file" ]; then
    jq -s '.[0] * {findings: (.[0].findings + .[1].findings)}' \
      "${WORKDIR}/state.json" "$agent_file" > "${WORKDIR}/state.tmp" \
      && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"
  fi
done
```

**Step 4: Update validator prompt — read from state.json (orchestrator-merged), write to own file**

In `AgentPrompts/validator.md`, update the output section to write to `/tmp/pentest-{{ID}}/agents/validator-results.json` instead of directly to state.json's `validated_findings`.

**Step 5: Verify all 12 agent prompt files have the new behavioral rules**

Read each file and confirm rules 5-7 are updated. Confirm no agent prompt still says "Write findings to state.json".

**Step 6: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md skills/BugBountyHunter/AgentPrompts/*.md
git commit -m "fix(C2): separate agent output files to prevent state.json race conditions"
```

---

### Task 2: Add Graduated Retry Strategy (C3)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:143-195` (Phase 1 retry section)
- Modify: `skills/BugBountyHunter/SKILL.md:247-336` (Phase 2b retry section)

**Step 1: Replace the ECONNRESET handling sections**

In SKILL.md, replace both "On ECONNRESET failure" sections (after Phase 1 and Phase 2b) with this unified retry protocol:

```markdown
### On Agent Failure (ECONNRESET or any spawn error):

Follow this graduated retry protocol. Do NOT abandon an agent — its coverage matters.

**Retry 1:** Wait 15 seconds. Retry the failed agent ALONE (no parallel agents).
**Retry 2:** Wait 30 seconds. Retry with a reduced prompt — remove Reference lines and tool descriptions, keep only the mission, methodology steps, and behavioral rules.
**Retry 3:** Wait 60 seconds. Final retry with minimal prompt — mission and behavioral rules only.
**Give up:** Log the gap:
```bash
echo "[COVERAGE GAP] Agent {AGENT_ID} failed after 4 attempts. The following test categories were NOT covered: {agent's mission summary}" >> "${WORKDIR}/coverage-gaps.txt"
```
Include coverage-gaps.txt in the final report. The user must know what was skipped.

**CRITICAL:** Between retries, verify your API connection works before spawning:
```bash
curl -s -o /dev/null -w "%{http_code}" https://api.anthropic.com/v1/messages
# If this returns 000 or fails, the network is down — wait longer, don't waste retries
```
```

**Step 2: Update Phase 1 to reference the retry protocol**

Replace the current "On ECONNRESET failure" block at line ~193 with:

```markdown
If any recon agent fails, follow the **Agent Failure Retry Protocol** above.
```

**Step 3: Update Phase 2b to reference the retry protocol**

Replace the current "On ECONNRESET failure" block at line ~335 with:

```markdown
If any attack agent fails, follow the **Agent Failure Retry Protocol** above.
```

**Step 4: Add coverage-gaps.txt to Phase 4 reporting**

In Phase 4, add after the report generation:

```markdown
### Coverage Gaps

If `/tmp/pentest-{ID}/coverage-gaps.txt` exists, append to the report:

```markdown
## Coverage Gaps

The following test categories could not be completed due to agent failures:

{contents of coverage-gaps.txt}

These areas require manual testing or a re-run.
```
```

**Step 5: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "fix(C3): graduated retry strategy with coverage gap tracking"
```

---

### Task 3: Add Adaptive Agent Timeouts (C4)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:143-195` (Phase 1)
- Modify: `skills/BugBountyHunter/SKILL.md:247-336` (Phase 2b)
- Modify: `skills/BugBountyHunter/SKILL.md:338-365` (Phase 3)

**Step 1: Add timeout guidance section to SKILL.md**

After the "Behavioral Rules" section (before Phase 0), add:

```markdown
## Agent Timeout Policy

Agents are autonomous but not infinite. Apply these timeouts:

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
  echo "[TIMEOUT WARNING] Agent ${AGENT_ID} idle for ${IDLE_SECONDS}s"
fi
```

**On timeout:** Do NOT discard work. The agent writes findings incrementally, so partial results are already in its output file. Merge what exists and log the gap:
```bash
echo "[TIMEOUT] Agent ${AGENT_ID} timed out at ${ELAPSED}min. Partial results merged. Uncovered endpoints: ~${REMAINING}" >> "${WORKDIR}/coverage-gaps.txt"
```
```

**Step 2: Update Phase 1 and Phase 2b batch instructions**

After each "Launch via Agent tool" instruction, add:

```markdown
Set agent timeout to {BASE_TIMEOUT} minutes. If the agent output file shows no new data for 3 consecutive minutes, consider the agent stalled.
```

**Step 3: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "fix(C4): adaptive agent timeouts with progress monitoring"
```

---

### Task 4: Add Auth Verification After Login (H4) and Between Batches (H1)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:196-244` (Phase 2)
- Modify: `skills/BugBountyHunter/SKILL.md:247-336` (Phase 2b — between batches)

**Step 1: Add auth verification to Phase 2**

After the dev-browser login script and state.json update, add:

```markdown
### Verify Authentication

After extracting auth artifacts, verify the session actually works:

```bash
# Find an endpoint that requires auth (from recon, or common paths)
AUTH_CHECK_URLS=("https://{{TARGET}}/api/me" "https://{{TARGET}}/api/user" "https://{{TARGET}}/api/profile" "https://{{TARGET}}/api/account" "https://{{TARGET}}/dashboard")

AUTH_VERIFIED=false
for url in "${AUTH_CHECK_URLS[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$url" \
    -H "Authorization: Bearer ${JWT}" \
    -H "Cookie: ${COOKIE_STRING}")
  if [ "$STATUS" = "200" ] || [ "$STATUS" = "302" ]; then
    AUTH_VERIFIED=true
    echo "[AUTH OK] Verified at $url (HTTP $STATUS)"
    break
  fi
done

if [ "$AUTH_VERIFIED" = false ]; then
  echo "[AUTH FAILED] Could not verify authentication on any endpoint"
  echo "Possible causes: wrong selectors, CAPTCHA, MFA, session not created"
  # Ask user before proceeding with unauthenticated testing
fi
```

Update state.json: `"auth": { "authenticated": true, "verified": true, "verified_at": "URL" }`
```

**Step 2: Add auth re-verification between attack batches**

In Phase 2b, after each "Wait for Batch N → merge findings" step, add:

```markdown
### Auth Health Check

Before spawning next batch, verify auth is still valid:

```bash
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${AUTH_CHECK_URL}" \
  -H "Authorization: Bearer ${JWT}" \
  -H "Cookie: ${COOKIE_STRING}")

if [ "$STATUS" = "401" ] || [ "$STATUS" = "403" ]; then
  echo "[AUTH EXPIRED] Token/session expired between batches. Re-authenticating..."
  # Re-run Phase 2 authentication
  # Update state.json with fresh tokens
  # Continue with next batch using new tokens
fi
```
```

**Step 3: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "fix(H1,H4): auth verification after login and between attack batches"
```

---

## Phase 2 — Safety and Correctness

### Task 5: Fix eval Command Injection in Validator (C1)

**Files:**
- Modify: `skills/BugBountyHunter/AgentPrompts/validator.md:40-65`

**Step 1: Replace the eval-based reproduction loop**

Replace the current Step 2 code block in validator.md:

```bash
# DANGEROUS — DO NOT USE:
# result=$(eval "$poc" 2>/dev/null)
```

With controlled execution that rebuilds commands from structured fields:

```markdown
### Step 2: Reproduce Each Finding

For each finding, reconstruct the request from its structured fields. Do NOT execute the `poc_curl` field directly — it may contain unsanitized target data.

**Safe reproduction method:**

1. Read the finding's structured fields: `endpoint`, `method`, `payload`, and auth from state.json
2. Build a fresh curl command from these fields:

```bash
# Build curl from structured fields — NEVER eval the poc_curl string directly
ENDPOINT=$(echo "$FINDING" | jq -r '.endpoint')
METHOD=$(echo "$FINDING" | jq -r '.method')
PAYLOAD=$(echo "$FINDING" | jq -r '.payload')

# Validate endpoint is in scope before executing
check_scope "$ENDPOINT" || continue

# Execute controlled request
result=$(curl -s -X "$METHOD" "$ENDPOINT" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" 2>/dev/null)
```

3. Compare result against the finding's `response_summary`
4. If the structured reproduction fails, you may fall back to the `poc_curl` field ONLY after validating it:
   - Must start with `curl `
   - Must not contain `;`, `|`, `$()`, `` ` ``, `&&`, `||`, `>`, `<` outside of quoted strings
   - Must target an in-scope domain
   - If validation fails, mark finding as `reproduction_method: "manual_review_required"`
```

**Step 2: Verify validator.md no longer contains `eval`**

Read the file. Grep for `eval`. Should return zero matches.

**Step 3: Commit**

```bash
git add skills/BugBountyHunter/AgentPrompts/validator.md
git commit -m "fix(C1): replace eval with controlled curl execution in validator"
```

---

### Task 6: Add Scope Enforcement (H3)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:52-140` (Phase 0 scope)
- Modify: `skills/BugBountyHunter/AgentPrompts/recon-r1-assets.md:10-15` (behavioral rules)
- Modify: All other agent prompts (same behavioral rules section)

**Step 1: Add domain allowlist generation to Phase 0**

After scope.yaml generation in Phase 0, add:

```markdown
### Generate Explicit Domain Allowlist

Resolve scope globs into an explicit domain list for agents:

```bash
# Convert scope globs to explicit allowlist
# Start with the target domain
echo "{{TARGET}}" > "${WORKDIR}/scope-allowlist.txt"

# Expand known subdomains from recon (updated after Phase 1)
# For now, add the base patterns
for pattern in $(cat "${WORKDIR}/scope.yaml" | grep -A100 'in_scope:' | grep '^ *-' | sed 's/.*- *"\(.*\)"/\1/'); do
  echo "$pattern" >> "${WORKDIR}/scope-allowlist.txt"
done
```

After Phase 1 recon completes, update the allowlist with discovered subdomains that match scope patterns.
```

**Step 2: Add scope-check function to every agent prompt**

In every agent prompt's Behavioral Rules section, add:

```markdown
N. **Scope enforcement:** Before EVERY HTTP request, validate the target domain:
   ```bash
   check_scope() {
     local url="$1"
     local domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
     if ! grep -qFx "$domain" /tmp/pentest-{{ID}}/scope-allowlist.txt && \
        ! grep -q "$domain" /tmp/pentest-{{ID}}/scope.yaml; then
       echo "[SCOPE BLOCKED] $domain is NOT in scope — skipping"
       return 1
     fi
   }
   # Call before every curl/request:
   check_scope "$URL" || continue
   ```
   If scope check fails, do NOT send the request. Log and skip.
```

**Step 3: Verify all 12 agent prompts have the scope-check function**

Read each file, confirm the function is present.

**Step 4: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md skills/BugBountyHunter/AgentPrompts/*.md
git commit -m "fix(H3): explicit scope allowlist with check_scope function in all agents"
```

---

### Task 7: Add Per-Agent Rate Limiting (H2)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:247-260` (Phase 2b intro)
- Modify: All attack agent prompts (behavioral rules)

**Step 1: Add rate limit calculation to Phase 2b**

Before spawning attack agents, add:

```markdown
### Calculate Per-Agent Rate Limits

```bash
TOTAL_RATE=$(cat "${WORKDIR}/scope.yaml" | grep 'rate_limit:' | awk '{print $2}')
AGENTS_PER_BATCH=2
AGENT_RATE=$((TOTAL_RATE / AGENTS_PER_BATCH))
echo "Per-agent rate limit: ${AGENT_RATE} req/s (total: ${TOTAL_RATE}, agents: ${AGENTS_PER_BATCH})"
```

Inject `AGENT_RATE` into each agent prompt alongside TARGET and ID.
```

**Step 2: Update all attack agent behavioral rules**

Change rule 3 in every attack agent prompt from:

```
3. Respect rate limits from scope.yaml
```

To:

```
3. Respect your rate limit of {{AGENT_RATE}} requests per second. This is your share of the total program rate limit ({{TOTAL_RATE}} req/s ÷ {{AGENTS_PER_BATCH}} parallel agents). Add `sleep` between requests if needed: `sleep $(echo "scale=2; 1/{{AGENT_RATE}}" | bc)` between each request.
```

**Step 3: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md skills/BugBountyHunter/AgentPrompts/attack-*.md
git commit -m "fix(H2): per-agent rate limiting based on total scope limit ÷ parallel agents"
```

---

### Task 8: Fix Finding Deduplication (H5)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:327-332` (post-attack dedup)

**Step 1: Replace the dedup instruction**

Replace:

```markdown
2. Deduplicate findings by endpoint + vulnerability class
```

With:

```markdown
2. Deduplicate findings using composite key: `(normalized_path, parameter, vulnerability_class, payload_family)`

   **Dedup rules:**
   - Normalize paths: strip API version prefixes (`/api/v1/users` and `/api/v2/users` → `/api/users`)
   - Same path + same parameter + same vuln class = duplicate (keep the one with higher severity)
   - Same path + DIFFERENT parameters + same vuln class = NOT duplicates (both are valid findings)
   - Different paths + same parameter + same vuln class + same response pattern = likely duplicate (merge, note both endpoints)

   ```bash
   # Dedup using jq
   jq '[.findings | group_by(.endpoint | gsub("/v[0-9]+/"; "/") | split("?")[0] + ":" + .class + ":" + (.payload | split(" ")[0]))[] | sort_by(.severity_estimate)[0]]' \
     "${WORKDIR}/state.json"
   ```
```

**Step 2: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "fix(H5): smarter dedup using normalized path + parameter + vuln class"
```

---

## Phase 3 — Polish

### Task 9: Add Progress Feedback (H6)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md` (after each batch merge)

**Step 1: Add status output after every batch**

After each batch merge section in Phase 1 and Phase 2b, add:

```markdown
### Progress Report

```bash
FINDING_COUNT=$(jq '.findings | length' "${WORKDIR}/state.json")
P1_COUNT=$(jq '[.findings[] | select(.severity_estimate == "P1")] | length' "${WORKDIR}/state.json")
P2_COUNT=$(jq '[.findings[] | select(.severity_estimate == "P2")] | length' "${WORKDIR}/state.json")
P3_COUNT=$(jq '[.findings[] | select(.severity_estimate == "P3")] | length' "${WORKDIR}/state.json")

echo "═══ Progress: Batch {N}/{TOTAL} complete ═══════════════"
echo "Agents: {AGENT_IDS} finished"
echo "Findings: ${FINDING_COUNT} total (${P1_COUNT} P1, ${P2_COUNT} P2, ${P3_COUNT} P3)"
echo "Next: {NEXT_AGENTS}"
echo "═══════════════════════════════════════════════════════"
```
```

**Step 2: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "feat(H6): progress feedback after each agent batch"
```

---

### Task 10: Template Variable Escaping (M1)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md:22-48` (input parsing)

**Step 1: Add input sanitization after parameter extraction**

After the input parsing section, add:

```markdown
### Input Sanitization

Escape special characters in parsed inputs before injecting into agent prompts:

```bash
# URL-encode target for use in curl commands
TARGET_ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('{{TARGET}}', safe=':/'))")

# Escape credentials for shell safety
CREDS_USER=$(echo "$CREDS" | cut -d: -f1 | sed "s/'/'\\\\''/g")
CREDS_PASS=$(echo "$CREDS" | cut -d: -f2 | cut -d@ -f1 | sed "s/'/'\\\\''/g")

# Validate target is a valid domain/URL (no shell metacharacters)
if echo "{{TARGET}}" | grep -qP '[;&|$`><]'; then
  echo "[ERROR] Target contains shell metacharacters — aborting for safety"
  exit 1
fi
```

Agent prompts receive `{{TARGET_ENCODED}}` for use in curl commands and `{{TARGET}}` for display only.
```

**Step 2: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md
git commit -m "fix(M1): sanitize template variables to prevent shell injection"
```

---

### Task 11: Engagement Cleanup, TechniqueFetcher Fallback, README Fix (M2, M3, M5)

**Files:**
- Modify: `skills/BugBountyHunter/SKILL.md` (after Phase 4)
- Modify: `skills/TechniqueFetcher/SKILL.md` (add fallback)
- Modify: `README.md:57`

**Step 1: Add Phase 5 — Cleanup to SKILL.md**

After Phase 4, add:

```markdown
## Phase 5 — Cleanup

After report is delivered:

```bash
# Scrub auth tokens from state.json
jq '.auth = {"authenticated": false, "scrubbed": true} | del(.auth.cookies, .auth.tokens, .auth.csrf_token)' \
  "${WORKDIR}/state.json" > "${WORKDIR}/state.tmp" && mv "${WORKDIR}/state.tmp" "${WORKDIR}/state.json"

# Remove individual agent output files (findings are merged into state.json)
rm -f "${WORKDIR}/agents/"*-results.json

echo "[CLEANUP] Auth tokens scrubbed. Agent output files removed."
echo "[CLEANUP] Report preserved at: ${WORKDIR}/report.md"
echo "[CLEANUP] State preserved at: ${WORKDIR}/state.json (tokens scrubbed)"
```

Offer: "Delete engagement directory entirely? (${WORKDIR})"
```

**Step 2: Add fallback to TechniqueFetcher**

In `skills/TechniqueFetcher/SKILL.md`, after the Workflow section, add:

```markdown
## Fallback Behavior

If any step fails (WebSearch unavailable, nuclei not installed, network error):

1. Log the failure: `"[TechniqueFetcher] Step N failed: {reason}. Proceeding with static payloads."`
2. Return a partial result with whatever succeeded
3. Set a flag in the output: `"fallback": true, "missing": ["disclosed_reports", "fresh_techniques"]`
4. The orchestrator and attack agents MUST still proceed — static payloads in `skills/Payloads/` are comprehensive enough for a solid engagement

**NEVER block the pipeline because intelligence gathering failed.**
```

**Step 3: Fix README placeholder**

In `README.md`, replace:

```
git clone https://github.com/YOUR_USERNAME/bug-bounty-hunter.git
```

With:

```
git clone <your-fork-url>
cd bug-bounty-hunter
```

**Step 4: Commit**

```bash
git add skills/BugBountyHunter/SKILL.md skills/TechniqueFetcher/SKILL.md README.md
git commit -m "fix(M2,M3,M5): engagement cleanup, TechniqueFetcher fallback, README fix"
```

---

## Verification

After all tasks are complete, verify the full set of changes:

1. **Grep for `eval`** in all skill files — should return zero matches
2. **Grep for `Write findings to.*state.json`** in agent prompts — should return zero matches (agents write to their own files)
3. **Grep for `YOUR_USERNAME`** in README — should return zero matches
4. **Read SKILL.md** and confirm: retry protocol exists, timeout policy exists, auth verification exists, progress reporting exists, cleanup phase exists
5. **Read each agent prompt** and confirm: scope-check function exists, per-agent rate limit exists, own-file output rule exists
6. **Run `git log --oneline`** and confirm 11 clean commits matching the plan
