# Layer 1 Smoke Test Results

**Date:** 2026-04-18
**Branch:** master
**Environment:** Linux 6.19.9-arch1-1, jq 1.7+, Python 3, bash

## Results

| Test | Status | Wall Time | Notes |
|------|--------|-----------|-------|
| `test_state_schema.sh` | ✅ PASS | <1s | Good fixture validates; bad fixture (missing `expires_at`) correctly rejected |
| `test_refresh_monitor.sh` | ✅ PASS | ~90s | Refresh-monitor fired 3 refreshes in window; `state.json.access_token` updated to `new.token.3`; `refresh_count = 3` |
| `test_refresh_failure.sh` | ✅ PASS | ~62s | refresh-monitor caught 401 from `/fail-token`, set `auth.stale=true`, incremented `refresh_failure_count=1`, exited cleanly |
| `test_stale_watcher.sh` | ✅ PASS | ~25s | Watcher correctly waited while `stale=false`, then flipped `auth.status` to `stale` and wrote `needs-attention.signal` after `stale=true` |
| `broker.py` round-trip | ✅ PASS | <2s | Returned **65 YAML techniques** for injection+cloudflare+node tech-stack |
| `test_atomic_write.sh` | ✅ PASS | <1s | 100 concurrent jq+mv writes — final state.json valid JSON, no truncation |

## Layer 1 Gate: GREEN

All preconditions met to proceed to Layer 2 (juice-shop component test, scheduled by Alvaro for a separate session).

## Out-of-scope notes (queued for Fix #6 in second design doc)

- **LightRAG works** — `deep-dive` action returns hybrid semantic search results from the 462MB graph (HackTricks, PayloadsAllTheThings, HowToHunt) with relevance scores. The earlier "0 LightRAG results" was a misdiagnosis — the `get-techniques` action is YAML-only by design; LightRAG is reached via the `deep-dive` action. Both knowledge layers are now confirmed operational.
- **First Phase 6 attempt (combined sequence)** exited 144 silently — likely sandbox interaction with `pkill -f`. Working around by running each test in its own bash invocation (which is also closer to how a real pentester would iterate).

## Commits in Phase 6

- Layer 1 smoke pass complete after commit `650da3f` (Phase 5 done).

---

## v3.2 additions (2026-04-18)

All 5 new smoke tests pass, and every v3.1 test still passes (regression
check confirmed in the Phase 10.1 Layer 1 run).

| New test | Status | Notes |
|----------|--------|-------|
| `test_score_candidates.sh` | ✅ PASS | Ranks 20-finding corpus, returns top 5 / next 5 / empty on overflow; scores sorted descending |
| `test_broker_compliance.sh` | ✅ PASS | Missing `broker-log/<agent>.json` → exit 1; present → exit 0 |
| `test_evidence_rules.sh` | ✅ PASS | All 4 evidence-pattern branches (browser, oob/timing, response-body, server-state) applied correctly to representative findings |
| `test_chain_patterns_sso.sh` | ✅ PASS | state-good.json fixture contains all 3 V-001 indicators for the OAuth state-parameter pattern |
| `test_race_detection.sh` | ✅ PASS | ThreadingHTTPServer mock with 10ms TOCTOU window — 20 parallel POSTs yield `allowed_count=20 > MAX=10`, race flagged |

### Layer 1 v3.2 Gate: GREEN

All 10 smoke tests (5 v3.1 + 5 v3.2) pass in a single run. Ready for
Layer 2 component test (juice-shop) and Layer 3 e2e (23andme re-run),
both user-driven per the implementation plan.

