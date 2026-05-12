#!/usr/bin/env bash
# Background loop that preemptively refreshes JWT/OAuth access tokens before
# they expire. Single-writer for: jwts.access_token, expires_at,
# last_refreshed_at, refresh_count, stale, failure_reason,
# refresh_failure_count.
#
# Auth-strategy gate: this script is only meaningful for auth_strategy ==
# "jwt-oauth". For session-cookie, static, or none strategies, exits
# immediately so the orchestrator can spawn the right helper instead.

set -u
: "${WORKDIR:?WORKDIR env var required}"
STATE="$WORKDIR/state.json"

# Bail early if not the strategy we handle
if [ -f "$STATE" ]; then
  strategy=$(jq -r '.auth.auth_strategy // "none"' "$STATE" 2>/dev/null)
  if [ "$strategy" != "jwt-oauth" ]; then
    echo "[refresh-monitor] auth_strategy=$strategy is not jwt-oauth — exiting (use session-warmer.sh for session-cookie targets)" >&2
    exit 0
  fi
fi

while true; do
  if [ ! -f "$STATE" ]; then
    sleep 30
    continue
  fi

  expires_at=$(jq -r '.auth.expires_at // empty' "$STATE" 2>/dev/null)
  if [ -z "$expires_at" ]; then
    sleep 30
    continue
  fi

  now_epoch=$(date -u +%s)
  exp_epoch=$(date -u -d "$expires_at" +%s 2>/dev/null || echo 0)
  seconds_left=$((exp_epoch - now_epoch))

  if [ "$seconds_left" -le 60 ]; then
    refresh_endpoint=$(jq -r '.auth.refresh_endpoint' "$STATE")
    refresh_token=$(jq -r '.auth.jwts.refresh_token' "$STATE")
    body_template=$(jq -r '.auth.refresh_body_template' "$STATE")
    body=${body_template//\{\{REFRESH_TOKEN\}\}/$refresh_token}

    refresh_response=$(curl -s -X POST "$refresh_endpoint" -d "$body" 2>/dev/null || echo "")

    if echo "$refresh_response" | jq -e '.access_token' >/dev/null 2>&1; then
      # Success path — atomic write of updated fields
      jq --argjson new "$refresh_response" \
        '.auth.jwts.access_token = $new.access_token
         | .auth.expires_at = ((now + $new.expires_in) | strftime("%Y-%m-%dT%H:%M:%SZ"))
         | .auth.last_refreshed_at = (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
         | .auth.refresh_count = (.auth.refresh_count + 1)' \
        "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
    else
      # Failure path — set stale flag, exit so stale-watcher can trigger AskUser
      reason=$(echo "$refresh_response" | head -c 200)
      jq --arg reason "$reason" \
        '.auth.stale = true
         | .auth.failure_reason = $reason
         | .auth.refresh_failure_count = (.auth.refresh_failure_count + 1)' \
        "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
      exit 1
    fi
  fi
  sleep 30
done
