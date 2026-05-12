#!/usr/bin/env bash
# Smoke test for lib/broker-compliance-check.sh (Phase 2 post-batch gate).
# Verifies exit 1 when broker-log/<agent>.json is missing, exit 0 when present.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB="$SCRIPT_DIR/../../lib"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
mkdir -p "$TMPDIR/broker-log"

# Test 1: missing log file → non-compliant (exit 1)
set +e
WORKDIR="$TMPDIR" "$LIB/broker-compliance-check.sh" attack-c 2>/dev/null
RC=$?
set -e
if [ "$RC" = "1" ]; then
  echo "[PASS] missing log → exit 1"
else
  echo "[FAIL] expected 1, got $RC"
  exit 1
fi

# Test 2: present log file → compliant (exit 0)
echo '{"agent":"attack-c","techniques_received":50}' > "$TMPDIR/broker-log/attack-c.json"
set +e
WORKDIR="$TMPDIR" "$LIB/broker-compliance-check.sh" attack-c
RC=$?
set -e
if [ "$RC" = "0" ]; then
  echo "[PASS] present log → exit 0"
else
  echo "[FAIL] expected 0, got $RC"
  exit 1
fi

echo "ALL BROKER COMPLIANCE TESTS PASSED"
