#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
V3_ROOT="$SCRIPT_DIR/../.."
LIB="$V3_ROOT/lib"
FIXTURE="$V3_ROOT/tests/fixtures"

# Setup: temp workdir
WORKDIR=$(mktemp -d -t v3-refresh-test-XXXXXX)
trap "kill \$MOCK_PID 2>/dev/null; kill \$MON_PID 2>/dev/null; rm -rf $WORKDIR; rm -f /tmp/mock-refresh-counter.txt" EXIT

# Start mock refresh server
python3 "$FIXTURE/mock-refresh-server.py" &
MOCK_PID=$!
sleep 1

# Verify mock server is up
if ! curl -s -o /dev/null -X POST http://127.0.0.1:18080/test 2>/dev/null; then
  echo "[FAIL] Mock server failed to start"
  exit 1
fi
# Reset counter (the POST above counted as 1)
rm -f /tmp/mock-refresh-counter.txt

# Seed state.json with expires_at 30s in future, refresh_endpoint pointing at mock
jq --arg exp "$(date -u -d '+30 seconds' +'%Y-%m-%dT%H:%M:%SZ')" \
   '.auth.expires_at = $exp | .auth.refresh_endpoint = "http://127.0.0.1:18080/token"' \
   "$FIXTURE/state-good.json" > "$WORKDIR/state.json"

# Start refresh-monitor in background
WORKDIR="$WORKDIR" "$LIB/refresh-monitor.sh" &
MON_PID=$!

# Wait 90s for refresh to fire (it triggers when expires_at - now <= 60s)
sleep 90

# Verify mock server saw at least 1 refresh request
COUNT=$(cat /tmp/mock-refresh-counter.txt 2>/dev/null || echo 0)
if [ "$COUNT" -ge 1 ]; then
  echo "[PASS] refresh-monitor fired $COUNT refresh(es)"
else
  echo "[FAIL] refresh-monitor did not fire (counter: $COUNT)"
  exit 1
fi

# Verify state.json access_token was updated
NEW_TOKEN=$(jq -r '.auth.jwts.access_token' "$WORKDIR/state.json")
if [[ "$NEW_TOKEN" == new.token.* ]]; then
  echo "[PASS] state.json access_token updated to: $NEW_TOKEN"
else
  echo "[FAIL] access_token not updated, got: $NEW_TOKEN"
  exit 1
fi

# Verify refresh_count incremented
RC=$(jq -r '.auth.refresh_count' "$WORKDIR/state.json")
if [ "$RC" -ge 1 ]; then
  echo "[PASS] refresh_count = $RC"
else
  echo "[FAIL] refresh_count = $RC"
  exit 1
fi

echo "REFRESH MONITOR SMOKE TEST PASSED"
