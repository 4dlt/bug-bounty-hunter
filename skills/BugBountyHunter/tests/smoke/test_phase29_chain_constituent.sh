#!/usr/bin/env bash
# E3 smoke test — Phase 2.9 auto-discards chains whose constituents are rejected.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$SKILL_DIR/lib/phase29-gate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/scope.yaml" <<'YAML'
target: test.example
excluded_findings: []
YAML

mkdir -p "$TMP/findings"

# F-A-001: xss_reflected WITH artifacts → survives
mkdir -p "$TMP/findings/F-A-001"
echo '{"id":"F-A-001","agent":"A","class":"xss_reflected","claimed_severity":"P3"}' > "$TMP/findings/F-A-001/finding.json"
echo "<html></html>" > "$TMP/findings/F-A-001/browser-poc.html"
echo "{}" > "$TMP/findings/F-A-001/replay.har"
printf '\x89PNG\r\n\x1a\n' > "$TMP/findings/F-A-001/alert-fired.png"

# F-B-003: insecure_cookie_attribute → program-excluded, rejected at B1
mkdir -p "$TMP/findings/F-B-003"
echo '{"id":"F-B-003","agent":"B","class":"insecure_cookie_attribute","claimed_severity":"P4"}' > "$TMP/findings/F-B-003/finding.json"

# F-C-005: xss_reflected WITH artifacts → survives
mkdir -p "$TMP/findings/F-C-005"
echo '{"id":"F-C-005","agent":"C","class":"xss_reflected","claimed_severity":"P3"}' > "$TMP/findings/F-C-005/finding.json"
echo "<html></html>" > "$TMP/findings/F-C-005/browser-poc.html"
echo "{}" > "$TMP/findings/F-C-005/replay.har"
printf '\x89PNG\r\n\x1a\n' > "$TMP/findings/F-C-005/alert-fired.png"

# Pre-seed state.json with chain_findings[]:
#  - C-001 references F-A-001 + F-B-003 (F-B-003 will be rejected) → chain auto-discards
#  - C-002 references F-A-001 + F-C-005 (both will survive) → chain survives
cat > "$TMP/state.json" <<'JSON'
{
  "chain_findings": [
    {"id":"C-001","title":"XSS + cookie chain","constituents":["F-A-001","F-B-003"],"severity":"P2"},
    {"id":"C-002","title":"XSS + XSS chain","constituents":["F-A-001","F-C-005"],"severity":"P2"}
  ]
}
JSON

WORKDIR="$TMP" bash "$GATE"

# C-001 must be discarded as CHAIN_CONSTITUENT_REJECTED
jq -e '.artifact_discarded | any(.id == "C-001" and .reason == "CHAIN_CONSTITUENT_REJECTED")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: C-001 should be CHAIN_CONSTITUENT_REJECTED"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

# C-001 discard entry must name the rejected constituent
jq -e '.artifact_discarded[] | select(.id == "C-001") | .rejected_constituents | index("F-B-003") != null' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: C-001 discard entry must list F-B-003 as rejected_constituents"; exit 1; }

# C-002 must survive (still in chain_findings)
jq -e '.chain_findings | any(.id == "C-002")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: C-002 should still be in chain_findings"; exit 1; }

# C-001 must NOT still be in chain_findings (removed after discard)
jq -e '.chain_findings | all(.id != "C-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: C-001 should be removed from chain_findings"; exit 1; }

# Audit log has a chain_constituent_rejected event
grep -q 'CHAIN_CONSTITUENT_REJECTED' "$TMP/audit-log.jsonl" \
  || { echo "FAIL: audit-log missing CHAIN_CONSTITUENT_REJECTED"; exit 1; }

echo "PASS: Phase 2.9 chain-constituent rejection rule"
