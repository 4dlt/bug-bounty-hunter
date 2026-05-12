#!/usr/bin/env bash
# C3 smoke test — Phase 3 debate orchestrator applies the decision rule
# correctly: ACCEPT requires precedent + non-low confidence; tie-break
# routes to triager_closed.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ORCH="$SKILL_DIR/lib/phase3-debate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

test -x "$ORCH" || { echo "FAIL: $ORCH missing or not executable"; exit 1; }

# Seed state.json with 4 findings representing each decision branch
mkdir -p "$TMP/findings"

# Finding 1: Clean ACCEPT (advocate has precedent, triager says ACCEPT high confidence) → validated_findings
mkdir -p "$TMP/findings/F-1"
echo '{"id":"F-1","class":"xss_reflected"}' > "$TMP/findings/F-1/finding.json"
cat > "$TMP/findings/F-1/advocate-argument.json" <<'JSON'
{"id":"F-1","class":"xss_reflected","canonical_class":"xss_reflected","severity":"P3",
 "impact_demonstrated":"Arbitrary JS execution in victim browser",
 "bounty_estimate":{"low":800,"high":1500},
 "precedent_url":"https://hackerone.com/reports/XSS_EXAMPLE",
 "reporter_submission_draft":"# Summary\nReflected XSS..."}
JSON
cat > "$TMP/findings/F-1/triager-verdict.json" <<'JSON'
{"verdict":"ACCEPT","close_code":"ACCEPT","cited_evidence":{"kind":"all_rules_verified","explanation":"Advocate followed all 4 rules; artifacts support claimed impact"},"confidence":"high"}
JSON

# Finding 2: Triager close with INFORMATIVE_NO_IMPACT → triager_closed
mkdir -p "$TMP/findings/F-2"
echo '{"id":"F-2","class":"oauth_state"}' > "$TMP/findings/F-2/finding.json"
cat > "$TMP/findings/F-2/advocate-argument.json" <<'JSON'
{"id":"F-2","class":"oauth_state","canonical_class":"oauth_state","severity":"P3",
 "impact_demonstrated":"could chain to XSS",
 "bounty_estimate":null,
 "precedent_url":null,
 "reporter_submission_draft":"..."}
JSON
cat > "$TMP/findings/F-2/triager-verdict.json" <<'JSON'
{"verdict":"INFORMATIVE_NO_IMPACT","close_code":"INFORMATIVE_NO_IMPACT",
 "cited_evidence":{"kind":"advocate_impact_is_hypothetical","quote":"could chain to XSS","location":"advocate-argument.json field: impact_demonstrated","explanation":"Rule 1 violation: speculation not demonstration"},
 "confidence":"high"}
JSON

# Finding 3: ACCEPT with low confidence → tie-break to INFORMATIVE_NO_IMPACT
mkdir -p "$TMP/findings/F-3"
echo '{"id":"F-3","class":"info_disclosure"}' > "$TMP/findings/F-3/finding.json"
cat > "$TMP/findings/F-3/advocate-argument.json" <<'JSON'
{"id":"F-3","class":"info_disclosure","canonical_class":"info_disclosure","severity":"P4",
 "impact_demonstrated":"ambiguous evidence",
 "bounty_estimate":null,
 "precedent_url":null,
 "reporter_submission_draft":"..."}
JSON
cat > "$TMP/findings/F-3/triager-verdict.json" <<'JSON'
{"verdict":"ACCEPT","close_code":"ACCEPT","cited_evidence":{"kind":"uncertain","explanation":"borderline"},"confidence":"low"}
JSON

# Finding 4: ACCEPT high confidence BUT bounty_estimate non-null with precedent_url null → rule 3 violation → close
mkdir -p "$TMP/findings/F-4"
echo '{"id":"F-4","class":"csrf"}' > "$TMP/findings/F-4/finding.json"
cat > "$TMP/findings/F-4/advocate-argument.json" <<'JSON'
{"id":"F-4","class":"csrf","canonical_class":"csrf","severity":"P3",
 "impact_demonstrated":"forced state change on victim session",
 "bounty_estimate":{"low":500,"high":1200},
 "precedent_url":null,
 "reporter_submission_draft":"..."}
JSON
cat > "$TMP/findings/F-4/triager-verdict.json" <<'JSON'
{"verdict":"ACCEPT","close_code":"ACCEPT","cited_evidence":{"kind":"all_rules_verified","explanation":"Advocate followed all rules"},"confidence":"high"}
JSON

# Seed state.json with the 4 findings as if they came from Phase 2.9
cat > "$TMP/state.json" <<JSON
{"findings":[
  {"id":"F-1","class":"xss_reflected"},
  {"id":"F-2","class":"oauth_state"},
  {"id":"F-3","class":"info_disclosure"},
  {"id":"F-4","class":"csrf"}
]}
JSON

WORKDIR="$TMP" bash "$ORCH"

# Assertions
jq -e '.validated_findings | any(.id == "F-1")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-1 should be validated"; jq . "$TMP/state.json"; exit 1; }

jq -e '.triager_closed | any(.id == "F-2" and .close_code == "INFORMATIVE_NO_IMPACT")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-2 should be triager_closed INFORMATIVE_NO_IMPACT"; exit 1; }

jq -e '.triager_closed | any(.id == "F-3" and .close_code == "INFORMATIVE_NO_IMPACT")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-3 (low-confidence ACCEPT) should be rewritten to INFORMATIVE_NO_IMPACT"; exit 1; }

jq -e '.triager_closed | any(.id == "F-4" and .close_code == "ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-4 (bounty set but precedent null) should be closed as rule-3 violation"; jq '.triager_closed' "$TMP/state.json"; exit 1; }

# Counts: 1 validated, 3 closed
VC=$(jq '.validated_findings | length' "$TMP/state.json")
TC=$(jq '.triager_closed | length' "$TMP/state.json")
[[ "$VC" == "1" && "$TC" == "3" ]] \
  || { echo "FAIL: expected 1 validated + 3 closed; got $VC + $TC"; exit 1; }

# Audit log must have an entry per debate decision
test -f "$TMP/audit-log.jsonl" || { echo "FAIL: audit-log.jsonl missing"; exit 1; }
PH3_LINES=$(grep -c '"phase":"3"' "$TMP/audit-log.jsonl" || true)
[[ "$PH3_LINES" -ge 4 ]] || { echo "FAIL: expected >=4 phase 3 audit events, got $PH3_LINES"; exit 1; }

echo "PASS: Phase 3 debate orchestrator — accept/close/tiebreak/rule-3 enforcement"
