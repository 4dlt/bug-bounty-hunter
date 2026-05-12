#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/../../lib"
FIXTURE_DIR="$SCRIPT_DIR/../fixtures"

# Test 1: good fixture should validate
if "$LIB_DIR/validate-state-schema.sh" "$FIXTURE_DIR/state-good.json"; then
  echo "[PASS] state-good.json validated"
else
  echo "[FAIL] state-good.json should have validated"
  exit 1
fi

# Test 2: bad fixture (missing expires_at) should fail validation
if "$LIB_DIR/validate-state-schema.sh" "$FIXTURE_DIR/state-bad-missing-expires.json" 2>/dev/null; then
  echo "[FAIL] state-bad-missing-expires.json should have failed validation"
  exit 1
else
  echo "[PASS] state-bad-missing-expires.json correctly rejected"
fi

echo "ALL SCHEMA TESTS PASSED"
