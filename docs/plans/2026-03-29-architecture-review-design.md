# BugBountyHunter Architecture Review

**Date:** 2026-03-29
**Scope:** Full architecture review — reliability, security, methodology, code quality
**Context:** Tool hit ECONNRESET failures in production. Root cause partially traced to xvpn MTU/stability issues, but tool-side resilience needs hardening.

---

## Findings Summary

| ID | Severity | Title | Phase Affected |
|----|----------|-------|----------------|
| C1 | Critical | `eval "$poc"` command injection in validator | Phase 3 |
| C2 | Critical | State file race conditions — no locking | Phase 1, 2b |
| C3 | Critical | ECONNRESET retry strategy insufficient | Phase 1, 2b |
| C4 | Critical | No agent timeout or hang detection | All phases |
| H1 | High | No token refresh — sessions die mid-engagement | Phase 2b |
| H2 | High | Rate limiting is honor system only | Phase 2b |
| H3 | High | Scope enforcement is trust-based | Phase 1, 2b |
| H4 | High | No auth verification after login | Phase 2 |
| H5 | High | Finding deduplication too naive | Phase 2b |
| H6 | High | No progress feedback during long runs | All phases |
| M1 | Medium | Template variables break on special characters | All phases |
| M2 | Medium | No engagement cleanup — tokens in /tmp | Phase 4 |
| M3 | Medium | TechniqueFetcher has no fallback | Phase 2b |
| M4 | Medium | No graceful shutdown | All phases |
| M5 | Medium | install.sh has placeholder YOUR_USERNAME | Setup |
| M6 | Medium | Cloud asset enumeration is pattern-based only | Phase 1 |

---

## Critical Findings

### C1. `eval "$poc"` Command Injection in Validator

**File:** `AgentPrompts/validator.md:56`
**Risk:** The validator reproduces findings by running `result=$(eval "$poc" 2>/dev/null)`. The `poc_curl` field is written by attack agents from data influenced by target responses. If a target returns crafted data that gets embedded in the PoC, `eval` executes arbitrary commands. Security tool with a command injection vulnerability.

**Fix:** Replace `eval` with controlled execution. Build curl commands from the finding's structured fields (endpoint, method, headers, payload) rather than executing a raw string. At minimum, validate the `poc_curl` field only contains `curl` commands before executing.

### C2. State File Race Conditions

**File:** `SKILL.md` (state management throughout)
**Risk:** Multiple agents in a batch read and write the same `state.json` concurrently. Agent R1 and R2 run in parallel — if both read the same version, the last writer overwrites the other's data.

**Fix:** Each agent writes to its own output file (`/tmp/pentest-ID/r1-results.json`, `/tmp/pentest-ID/r2-results.json`). The orchestrator merges results into state.json after each batch completes. Agents only READ state.json, never write to it directly.

### C3. ECONNRESET Retry Strategy Insufficient

**File:** `SKILL.md:147, 251, 335`
**Risk:** Single retry after 10-second wait. No exponential backoff, no circuit breaker. During API instability or VPN issues, all retries fail and agent coverage is silently lost.

**Fix:** Implement graduated retry:
1. Attempt 1: 2 agents parallel
2. On failure: wait 15s, retry failed agent alone
3. On 2nd failure: wait 30s, retry with reduced prompt
4. On 3rd failure: wait 60s, final retry
5. On 4th failure: skip agent, log coverage gap in report, continue pipeline

### C4. No Agent Timeout or Hang Detection

**File:** `SKILL.md` (all agent spawn sections)
**Risk:** Agents with no timeout can hang forever (infinite crawl, slow sqlmap, unresponsive endpoint). Entire pipeline stalls.

**Fix:** Adaptive timeout with progress monitoring:
- **Proportional base:** `max(10min, endpoint_count * 5s)`
- **Activity-based extension:** Check state.json mtime every 3 min. If agent wrote new data, extend 3 min.
- **Hard ceiling:** 30 min attack agents, 45 min validator.
- **On timeout:** Read intermediate findings (agent must write incrementally), log coverage gap.
- **New behavioral rule for all agents:** "Write each finding to your output file IMMEDIATELY upon discovery — do not batch."

---

## High Findings

### H1. No Token Refresh

**File:** `SKILL.md:196-244` (Phase 2)
**Risk:** Auth tokens extracted once in Phase 2. JWTs expire in 15-30 min. By Batch 3-4 (30+ min in), attack agents use dead tokens, get 401s, report zero findings without flagging auth as the reason.

**Fix:** Orchestrator verifies auth between batches:
```bash
STATUS=$(curl -s -o /dev/null -w "%{http_code}" TARGET/api/me -H "Authorization: Bearer $TOKEN")
# If 401 → re-run Phase 2, update state.json, continue
```

### H2. Rate Limiting is Honor System Only

**File:** All agent prompts
**Risk:** Each agent told to respect `rate_limit: 10 req/s`. Two parallel agents = 20 req/s. Can trigger WAF blocks or IP bans mid-engagement.

**Fix:** Inject per-agent rate limit: `agent_rate = scope.rate_limit / active_agent_count`. Add to agent prompt: "Your rate limit is N req/s."

### H3. Scope Enforcement is Trust-Based

**File:** All agent prompts
**Risk:** Agents told to check scope but no guardrail if they don't. Out-of-scope testing can result in platform bans.

**Fix:** Orchestrator provides pre-built allowlist of exact domains (not globs) extracted from scope.yaml. Agent prompts include the explicit list. Add a scope-check bash function to each agent template.

### H4. No Auth Verification After Login

**File:** `SKILL.md:196-244`
**Risk:** Phase 2 runs dev-browser login but never verifies it worked. Silent login failures (wrong selectors, CAPTCHA, MFA) mean all attack agents run unauthenticated.

**Fix:** After auth extraction, test a protected endpoint. If 401, retry or ask user before proceeding.

### H5. Finding Deduplication Too Naive

**File:** `SKILL.md:329`
**Risk:** Dedup by endpoint + vuln class merges distinct vulnerabilities (different parameters on same endpoint) and keeps duplicates (same vuln on versioned endpoints).

**Fix:** Dedup key: `(normalized_path, parameter, vuln_class, payload_family)`.

### H6. No Progress Feedback

**File:** `SKILL.md` pipeline
**Risk:** 30-60 min engagements with no intermediate status. User can't tell if pipeline is working or stuck.

**Fix:** After each batch: `[Batch 2/4] Agents C,D done | 3 findings (1 P2, 2 P3) | Next: E,F`

---

## Medium Findings

### M1. Template Variable Injection
Target domains with `/`, `?`, `&` or credentials with `$`, `'`, `&` break when injected into `{{TARGET}}` / `{{ID}}` placeholders in bash commands.
**Fix:** URL-encode target in curl commands. Quote all variable expansions.

### M2. No Engagement Cleanup
`/tmp/pentest-*` accumulates. Auth tokens sit unencrypted.
**Fix:** Add cleanup phase. At minimum, scrub auth tokens from state.json after reporting.

### M3. TechniqueFetcher No Fallback
If WebSearch fails, attack agents get no fresh intelligence and don't know it.
**Fix:** Log "TechniqueFetcher failed — using static payloads only" and continue.

### M4. No Graceful Shutdown
User cancel leaves orphan agents and half-written state.
**Fix:** Document that partial results are in `/tmp/pentest-ID/state.json`. Agents writing incrementally (C4 fix) mitigates data loss.

### M5. Placeholder in README
`git clone https://github.com/YOUR_USERNAME/bug-bounty-hunter.git` never replaced.
**Fix:** Replace or use relative instructions.

### M6. Cloud Enumeration is Basic
Pattern-based S3/Azure/GCP checks miss non-obvious bucket names.
**Fix:** Add wordlist-based permutation using SecLists cloud wordlists.

---

## What's Strong (Keep As-Is)

- 5-phase pipeline architecture
- 16-layer IDOR attack matrix (more thorough than most manual pentesters)
- 10 vulnerability chain patterns with step-by-step PoCs
- 20-item bounty filter with exception criteria
- Report template optimized for triager acceptance
- "Never stop for things you can do yourself" behavioral rules
- Payload databases with WAF-specific bypasses
- ImpactValidator's 3-question framework (exploitable? chainable? bounty-worthy?)

---

## Implementation Priority

**Phase 1 — Stop the bleeding (fix production failures):**
1. C2: Separate agent output files (state race conditions)
2. C4: Incremental finding writes + adaptive timeouts
3. C3: Graduated retry strategy
4. H1: Auth verification between batches
5. H4: Auth verification after login

**Phase 2 — Safety and correctness:**
6. C1: Replace `eval "$poc"` with controlled execution
7. H3: Explicit scope allowlist
8. H2: Per-agent rate limiting
9. H5: Better deduplication

**Phase 3 — Polish:**
10. H6: Progress feedback
11. M1-M6: Template escaping, cleanup, fallbacks, README fix
