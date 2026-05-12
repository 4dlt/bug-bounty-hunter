#!/usr/bin/env bash
# E2 smoke test — Phase 2 merge collects per-finding dirs into state.json.findings[].
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MERGE="$SKILL_DIR/lib/phase2-merge.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

test -x "$MERGE" || { echo "FAIL: $MERGE missing or not executable"; exit 1; }

mkdir -p "$TMP/findings/F-A-001" "$TMP/findings/F-B-003" "$TMP/findings/F-X-002"
echo '{"id":"F-A-001","agent":"A","class":"xss_reflected","claimed_severity":"P3"}' > "$TMP/findings/F-A-001/finding.json"
echo '{"id":"F-B-003","agent":"B","class":"idor","claimed_severity":"P2"}' > "$TMP/findings/F-B-003/finding.json"
echo '{"id":"F-X-002","agent":"X","class":"info_disclosure","claimed_severity":"P4"}' > "$TMP/findings/F-X-002/finding.json"

# Edge: directory with no finding.json should be skipped
mkdir -p "$TMP/findings/F-EMPTY"

# Edge: directory with malformed finding.json should be skipped (not crash the merge)
mkdir -p "$TMP/findings/F-BAD"
echo 'not valid json' > "$TMP/findings/F-BAD/finding.json"

WORKDIR="$TMP" bash "$MERGE"

# Only 3 well-formed findings should end up in state.json
COUNT=$(jq '.findings | length' "$TMP/state.json")
[[ "$COUNT" == "3" ]] || { echo "FAIL: expected 3 findings, got $COUNT"; jq . "$TMP/state.json"; exit 1; }

# All 3 ids present
for id in F-A-001 F-B-003 F-X-002; do
  jq -e --arg id "$id" '.findings | any(.id == $id)' "$TMP/state.json" > /dev/null \
    || { echo "FAIL: $id missing from merged state"; exit 1; }
done

# F-BAD should NOT be in state.json and merge should have logged the skip
jq -e '.findings | all(.id != "F-BAD")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-BAD (malformed) should be skipped"; exit 1; }

# Idempotency: second run produces the same content
WORKDIR="$TMP" bash "$MERGE"
COUNT2=$(jq '.findings | length' "$TMP/state.json")
[[ "$COUNT2" == "3" ]] || { echo "FAIL: idempotency — second run changed count"; exit 1; }

# Audit log has a merge event
grep -q '"event":"phase2_merge"' "$TMP/audit-log.jsonl" \
  || { echo "FAIL: audit-log missing phase2_merge event"; exit 1; }

echo "PASS: Phase 2 merge — 3 good findings merged, malformed skipped, idempotent"
