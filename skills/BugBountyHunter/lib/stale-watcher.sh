#!/usr/bin/env bash
# Polls $WORKDIR/state.json every 10s. When auth.stale flips to true,
# flips auth.status to "stale", writes needs-attention.signal with
# failure_reason, and exits. Orchestrator main loop watches the signal
# file to know when to trigger AskUser for re-auth.

set -u
: "${WORKDIR:?WORKDIR env var required}"
STATE="$WORKDIR/state.json"
SIGNAL="$WORKDIR/needs-attention.signal"

while true; do
  if [ -f "$STATE" ] && [ "$(jq -r '.auth.stale // false' "$STATE")" = "true" ]; then
    jq '.auth.status = "stale"' "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
    reason=$(jq -r '.auth.failure_reason // "unknown"' "$STATE")
    echo "REFRESH_FAILED:$reason" > "$SIGNAL"
    exit 0
  fi
  sleep 10
done
