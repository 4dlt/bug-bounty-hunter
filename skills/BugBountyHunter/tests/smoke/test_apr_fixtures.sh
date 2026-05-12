#!/usr/bin/env bash
# A4 smoke test — Golden fixtures present + expected.yaml defines each disposition.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FIXDIR="$SKILL_DIR/tests/fixtures/golden/apr-2026-23andme"
EXPECTED="$FIXDIR/expected.yaml"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"

test -d "$FIXDIR" || { echo "FAIL: fixture directory missing"; exit 1; }
test -f "$EXPECTED" || { echo "FAIL: expected.yaml missing"; exit 1; }

# All 10 finding fixtures present and parse as JSON
IDS=(F-K-001 F-K-003 F-J-001 F-F002 F-I-001 F-A-001 F-A-002 F-A-003 F-A-004 F-E-001)
for id in "${IDS[@]}"; do
  test -s "$FIXDIR/$id.json" || { echo "FAIL: $id.json missing or empty"; exit 1; }
  jq -e --arg id "$id" '.id == $id' "$FIXDIR/$id.json" > /dev/null \
    || { echo "FAIL: $id.json does not contain id=$id"; exit 1; }
  jq -e '.class and .severity' "$FIXDIR/$id.json" > /dev/null \
    || { echo "FAIL: $id.json missing class or severity"; exit 1; }
done

# expected.yaml has an entry per fixture id
EJ=$("$YAML2JSON" < "$EXPECTED")
for id in "${IDS[@]}"; do
  echo "$EJ" | jq -e --arg id "$id" '.expectations[$id]' > /dev/null \
    || { echo "FAIL: expected.yaml missing expectations.$id"; exit 1; }
done

# Each expectation has either phase_2_9 or phase_3 key (where the finding is expected to resolve)
for id in "${IDS[@]}"; do
  echo "$EJ" | jq -e --arg id "$id" '
    .expectations[$id] | (.phase_2_9 != null or .phase_3 != null)
  ' > /dev/null || { echo "FAIL: expectations.$id must set phase_2_9 or phase_3"; exit 1; }
done

# At least 4 fixtures should be phase_2_9 discards (F-K-001, F-K-003, F-J-001, F-A-004).
# F-F002 intentionally routes to Phase 3 because its source class
# 'security_misconfiguration' is too broad to alias onto info_disclosure.
DISCARD_COUNT=$(echo "$EJ" | jq '[.expectations | to_entries[] | select(.value.phase_2_9 == "artifact_discarded")] | length')
[[ "$DISCARD_COUNT" -ge 4 ]] || { echo "FAIL: expected >=4 phase_2_9 discards, got $DISCARD_COUNT"; exit 1; }

# scope.yaml was extracted from the Apr-18 run and is load-bearing for regression:
# if its excluded_findings list drifts, F-K-001/F-K-003 PROGRAM_EXCLUDED_CLASS stops firing
# for the right reason. Assert the specific exclusions are present.
test -f "$FIXDIR/scope.yaml" || { echo "FAIL: fixture scope.yaml missing"; exit 1; }
grep -qxF '  - low_impact_missing_headers' "$FIXDIR/scope.yaml" \
  || { echo "FAIL: fixture scope.yaml missing low_impact_missing_headers in excluded_findings"; exit 1; }
grep -q 'excluded_findings:' "$FIXDIR/scope.yaml" \
  || { echo "FAIL: fixture scope.yaml missing excluded_findings section"; exit 1; }
grep -q 'out_of_scope:' "$FIXDIR/scope.yaml" \
  || { echo "FAIL: fixture scope.yaml missing out_of_scope section"; exit 1; }

echo "PASS: 10 fixtures + expected.yaml dispositions + scope.yaml exclusions"
