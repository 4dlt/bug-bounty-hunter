#!/usr/bin/env bash
# F1 smoke test — validate-state-schema.sh requires v3.2-patch fields.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
VAL="$SKILL_DIR/lib/validate-state-schema.sh"
FIX="$SKILL_DIR/tests/fixtures/state-good.json"

test -x "$VAL" || { echo "FAIL: validate-state-schema.sh not executable"; exit 1; }
test -f "$FIX" || { echo "FAIL: fixture state-good.json missing"; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Augment the fixture with all required v3.2-patch fields → PASS
jq '. + {
  artifact_discarded: [],
  triager_closed: [],
  validated_findings: [],
  pipeline_mode: "partial_idor",
  account_count: 1
}' "$FIX" > "$TMP/good-with-v32-fields.json"

bash "$VAL" "$TMP/good-with-v32-fields.json" > /dev/null \
  || { echo "FAIL: valid state.json with v3.2 fields should pass"; exit 1; }

# Missing artifact_discarded → FAIL (must use del() because the fixture already has it)
jq '{triager_closed: [], pipeline_mode: "no_auth", account_count: 0} as $add | . + $add | del(.artifact_discarded)' "$FIX" > "$TMP/no-artifact-discarded.json"
if bash "$VAL" "$TMP/no-artifact-discarded.json" > /dev/null 2>&1; then
  echo "FAIL: missing artifact_discarded should be rejected"; exit 1
fi

# Missing triager_closed → FAIL
jq '{artifact_discarded: [], pipeline_mode: "no_auth", account_count: 0} as $add | . + $add | del(.triager_closed)' "$FIX" > "$TMP/no-triager-closed.json"
if bash "$VAL" "$TMP/no-triager-closed.json" > /dev/null 2>&1; then
  echo "FAIL: missing triager_closed should be rejected"; exit 1
fi

# Wrong type (artifact_discarded as object not array) → FAIL
jq '. + {artifact_discarded: {}, triager_closed: [], pipeline_mode: "no_auth", account_count: 0}' "$FIX" > "$TMP/wrong-type.json"
if bash "$VAL" "$TMP/wrong-type.json" > /dev/null 2>&1; then
  echo "FAIL: artifact_discarded as object should be rejected"; exit 1
fi

# Invalid pipeline_mode enum → FAIL
jq '. + {artifact_discarded: [], triager_closed: [], pipeline_mode: "nonsense", account_count: 0}' "$FIX" > "$TMP/bad-mode.json"
if bash "$VAL" "$TMP/bad-mode.json" > /dev/null 2>&1; then
  echo "FAIL: invalid pipeline_mode enum should be rejected"; exit 1
fi

echo "PASS: state schema v3.2 — required fields + enum + type validation"
