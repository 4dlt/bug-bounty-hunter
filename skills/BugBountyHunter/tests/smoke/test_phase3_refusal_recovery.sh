#!/usr/bin/env bash
# C4 smoke test — Phase 3 orchestrator detects agent refusals and routes
# conservatively instead of treating refused output as a valid verdict.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ORCH="$SKILL_DIR/lib/phase3-debate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/findings"

# Case 1: advocate-argument.json contains a refusal string (not valid JSON, OR valid JSON
# whose only content is a refusal message) → ADVOCATE_REFUSAL close
mkdir -p "$TMP/findings/F-1"
echo '{"id":"F-1","class":"xss_reflected"}' > "$TMP/findings/F-1/finding.json"
# Simulated refusal: agent returned prose instead of structured JSON
echo "I apologize, but I cannot assist with this request. Providing exploit-related content would violate Anthropic's usage policies." > "$TMP/findings/F-1/advocate-argument.json"
# Triager will never run here; orchestrator should close before reading it

# Case 2: advocate is valid JSON but triager output is a refusal → TRIAGER_REFUSAL close
mkdir -p "$TMP/findings/F-2"
echo '{"id":"F-2","class":"csrf"}' > "$TMP/findings/F-2/finding.json"
cat > "$TMP/findings/F-2/advocate-argument.json" <<'JSON'
{"id":"F-2","class":"csrf","canonical_class":"csrf","severity":"P3",
 "impact_demonstrated":"Victim forced to perform state-changing action via attacker origin",
 "bounty_estimate":{"low":800,"high":1500},
 "precedent_url":"https://hackerone.com/reports/CSRF_EXAMPLE",
 "reporter_submission_draft":"..."}
JSON
# Refusal in triager output
echo "I'm unable to help with this." > "$TMP/findings/F-2/triager-verdict.json"

# Case 3: advocate is valid JSON but the JSON payload contains refusal language → ADVOCATE_REFUSAL
mkdir -p "$TMP/findings/F-3"
echo '{"id":"F-3","class":"xss_stored"}' > "$TMP/findings/F-3/finding.json"
cat > "$TMP/findings/F-3/advocate-argument.json" <<'JSON'
{"error":"I cannot provide this content","refusal_detected":true}
JSON
echo '{"verdict":"ACCEPT","close_code":"ACCEPT","cited_evidence":{},"confidence":"high"}' > "$TMP/findings/F-3/triager-verdict.json"

# Seed state.json
cat > "$TMP/state.json" <<'JSON'
{"findings":[
  {"id":"F-1","class":"xss_reflected"},
  {"id":"F-2","class":"csrf"},
  {"id":"F-3","class":"xss_stored"}
]}
JSON

WORKDIR="$TMP" bash "$ORCH"

# Assertions
jq -e '.triager_closed | any(.id == "F-1" and .close_code == "ADVOCATE_REFUSAL")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-1 advocate refusal (plain-text) should close as ADVOCATE_REFUSAL"; jq '.triager_closed' "$TMP/state.json"; exit 1; }

jq -e '.triager_closed | any(.id == "F-2" and .close_code == "TRIAGER_REFUSAL_CONSERVATIVE_CLOSE")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-2 triager refusal should close as TRIAGER_REFUSAL_CONSERVATIVE_CLOSE"; exit 1; }

jq -e '.triager_closed | any(.id == "F-3" and .close_code == "ADVOCATE_REFUSAL")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-3 advocate refusal (JSON payload) should close as ADVOCATE_REFUSAL"; exit 1; }

# No refused finding should end up validated
jq -e '.validated_findings == []' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: no refused finding should be validated"; jq '.validated_findings' "$TMP/state.json"; exit 1; }

# Audit log must have a refusal_detected event (separate from debate_decision)
grep -q 'refusal_detected' "$TMP/audit-log.jsonl" \
  || { echo "FAIL: audit-log must record refusal_detected events"; exit 1; }

echo "PASS: Phase 3 refusal recovery — ADVOCATE_REFUSAL + TRIAGER_REFUSAL_CONSERVATIVE_CLOSE"
