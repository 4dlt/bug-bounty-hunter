#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
V3_ROOT="$SCRIPT_DIR/../.."
LIB="$V3_ROOT/lib"
FIXTURE="$V3_ROOT/tests/fixtures"

# Setup: temp workdir
WORKDIR=$(mktemp -d -t v3-refresh-fail-test-XXXXXX)
cleanup() {
  rc=$?
  kill "$MOCK_PID" 2>/dev/null || true
  kill "$MON_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
  rm -f /tmp/mock-refresh-counter.txt
  exit $rc
}
trap cleanup EXIT

# Start mock refresh server
python3 "$FIXTURE/mock-refresh-server.py" &
MOCK_PID=$!
sleep 1

# Sanity: mock is up
if ! curl -s -o /dev/null -X POST http://127.0.0.1:18080/fail-token; then
  echo "[FAIL] Mock server failed to start"
  exit 1
fi

# Seed state.json: expires_at 30s in future, refresh_endpoint at /fail-token
jq --arg exp "$(date -u -d '+30 seconds' +'%Y-%m-%dT%H:%M:%SZ')" \
   '.auth.expires_at = $exp | .auth.refresh_endpoint = "http://127.0.0.1:18080/fail-token"' \
   "$FIXTURE/state-good.json" > "$WORKDIR/state.json"

# Start refresh-monitor in background
WORKDIR="$WORKDIR" "$LIB/refresh-monitor.sh" &
MON_PID=$!

# Wait 60s — refresh-monitor wakes after 30s, sees expires_at within 60s, calls fail endpoint, exits
sleep 60

# Assert 1: refresh-monitor process has exited
if kill -0 "$MON_PID" 2>/dev/null; then
  echo "[FAIL] refresh-monitor still running after refresh failure (expected to exit)"
  exit 1
else
  echo "[PASS] refresh-monitor exited as expected"
fi

# Assert 2: state.json.auth.stale == true
STALE=$(jq -r '.auth.stale' "$WORKDIR/state.json")
if [ "$STALE" = "true" ]; then
  echo "[PASS] auth.stale = true"
else
  echo "[FAIL] auth.stale = $STALE (expected true)"
  exit 1
fi

# Assert 3: failure_reason contains 'invalid_grant'
REASON=$(jq -r '.auth.failure_reason' "$WORKDIR/state.json")
if echo "$REASON" | grep -q "invalid_grant"; then
  echo "[PASS] failure_reason contains invalid_grant: $REASON"
else
  echo "[FAIL] failure_reason missing invalid_grant: $REASON"
  exit 1
fi

# Assert 4: refresh_failure_count incremented
RFC=$(jq -r '.auth.refresh_failure_count' "$WORKDIR/state.json")
if [ "$RFC" = "1" ]; then
  echo "[PASS] refresh_failure_count = 1"
else
  echo "[FAIL] refresh_failure_count = $RFC (expected 1)"
  exit 1
fi

echo "REFRESH FAILURE SMOKE TEST PASSED"
