#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
V3_ROOT="$SCRIPT_DIR/../.."
LIB="$V3_ROOT/lib"
FIXTURE="$V3_ROOT/tests/fixtures"

WORKDIR=$(mktemp -d -t v3-stale-test-XXXXXX)
WATCHER_PID=""
cleanup() {
  rc=$?
  [ -n "$WATCHER_PID" ] && kill "$WATCHER_PID" 2>/dev/null || true
  rm -rf "$WORKDIR"
  exit "$rc"
}
trap cleanup EXIT

# Seed state.json with stale=false initially
cp "$FIXTURE/state-good.json" "$WORKDIR/state.json"

# Start stale-watcher
WORKDIR="$WORKDIR" "$LIB/stale-watcher.sh" &
WATCHER_PID=$!
sleep 5

# Assertion 1: no signal file yet (stale was false)
if [ -f "$WORKDIR/needs-attention.signal" ]; then
  echo "[FAIL] needs-attention.signal created prematurely"
  exit 1
fi
echo "[PASS] no signal yet (stale=false)"

# Now flip stale to true (simulates refresh-monitor failure)
jq '.auth.stale = true | .auth.failure_reason = "invalid_grant: token revoked"' \
  "$WORKDIR/state.json" > "$WORKDIR/state.tmp" && mv "$WORKDIR/state.tmp" "$WORKDIR/state.json"

# Watcher polls every 10s — wait 15s for it to notice
sleep 15

# Assertion 2: signal file exists with correct content
if [ ! -f "$WORKDIR/needs-attention.signal" ]; then
  echo "[FAIL] needs-attention.signal not created after stale=true"
  exit 1
fi
SIGNAL=$(cat "$WORKDIR/needs-attention.signal")
if echo "$SIGNAL" | grep -q "REFRESH_FAILED:invalid_grant"; then
  echo "[PASS] signal content correct: $SIGNAL"
else
  echo "[FAIL] signal content wrong: $SIGNAL"
  exit 1
fi

# Assertion 3: state.json.auth.status flipped to "stale"
STATUS=$(jq -r '.auth.status' "$WORKDIR/state.json")
if [ "$STATUS" = "stale" ]; then
  echo "[PASS] auth.status flipped to stale"
else
  echo "[FAIL] auth.status = $STATUS (expected stale)"
  exit 1
fi

# Assertion 4: watcher exited cleanly
if kill -0 "$WATCHER_PID" 2>/dev/null; then
  echo "[FAIL] stale-watcher still running after firing"
  exit 1
fi
echo "[PASS] stale-watcher exited after firing"

echo "STALE WATCHER SMOKE TEST PASSED"
