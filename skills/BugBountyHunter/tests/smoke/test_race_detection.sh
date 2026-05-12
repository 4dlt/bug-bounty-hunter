#!/usr/bin/env bash
# Smoke test for lib/race-test.sh (Phase 2.5 M6 race auto-test).
# Spins up mock-race-server.py (ThreadingHTTPServer with MAX=10, 10ms
# check-apply window). Fires 20 parallel POSTs via race-test.sh — more
# than MAX so if the race wins, allowed_count exceeds 10.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB="$SCRIPT_DIR/../../lib"
FIXTURES="$SCRIPT_DIR/../fixtures"

PORT=${PORT:-8765}

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

python3 "$FIXTURES/mock-race-server.py" "$PORT" &
SERVER_PID=$!

# Wait for server to be ready (max 3s)
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$PORT/counter" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

# Reset counter
curl -s "http://127.0.0.1:$PORT/reset" >/dev/null

# Run race-test.sh against /increment with MAX_ALLOWED_LIMIT=10
RESULT=$("$LIB/race-test.sh" "http://127.0.0.1:$PORT/increment" POST "" 10)

echo "=== race-test.sh output ==="
echo "$RESULT" | jq .

DETECTED=$(echo "$RESULT" | jq -r '.race_detected')
ALLOWED_COUNT=$(echo "$RESULT" | jq -r '.allowed_count')

if [ "$DETECTED" != "true" ]; then
  echo "[FAIL] race not detected (allowed_count=$ALLOWED_COUNT, expected >10)"
  exit 1
fi

if [ "$ALLOWED_COUNT" -le 10 ] 2>/dev/null; then
  echo "[FAIL] allowed_count did not exceed MAX (got $ALLOWED_COUNT)"
  exit 1
fi

echo "[PASS] race detected: allowed_count=$ALLOWED_COUNT > 10"
echo "RACE DETECTION TEST PASSED"
