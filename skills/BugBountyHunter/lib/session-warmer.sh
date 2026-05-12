#!/usr/bin/env bash
# Background loop for session-cookie auth strategies. Periodically GETs the
# primary domain with the captured cookies to (a) trigger server-side session
# extension where supported and (b) detect session expiry.
#
# Same single-writer contract as refresh-monitor.sh: writes auth.last_refreshed_at,
# auth.refresh_count, auth.stale, auth.failure_reason, auth.refresh_failure_count
# only.
#
# Auth-strategy gate: only runs for auth_strategy == "session-cookie".

set -u
: "${WORKDIR:?WORKDIR env var required}"
STATE="$WORKDIR/state.json"

if [ -f "$STATE" ]; then
  strategy=$(jq -r '.auth.auth_strategy // "none"' "$STATE" 2>/dev/null)
  if [ "$strategy" != "session-cookie" ]; then
    echo "[session-warmer] auth_strategy=$strategy is not session-cookie — exiting (use refresh-monitor.sh for jwt-oauth targets)" >&2
    exit 0
  fi
fi

# Build a Cookie header string from state.json cookies (filter to primary_domain)
build_cookie_header() {
  jq -r '
    .auth.cookies as $all
    | .auth.primary_domain as $pd
    | $all | map(select(.domain == $pd or .domain == "." + $pd or ($pd | endswith(.domain | sub("^\\."; "")))))
    | map("\(.name)=\(.value)") | join("; ")
  ' "$STATE"
}

while true; do
  if [ ! -f "$STATE" ]; then
    sleep 60
    continue
  fi

  expires_at=$(jq -r '.auth.expires_at // empty' "$STATE" 2>/dev/null)
  primary=$(jq -r '.auth.primary_domain // empty' "$STATE" 2>/dev/null)
  if [ -z "$expires_at" ] || [ -z "$primary" ]; then
    sleep 60
    continue
  fi

  now_epoch=$(date -u +%s)
  exp_epoch=$(date -u -d "$expires_at" +%s 2>/dev/null || echo 0)
  seconds_left=$((exp_epoch - now_epoch))

  # If session has more than 1 hour left, sleep an hour and check again.
  # If less than 1 hour, send a keepalive every 60s to maximize chance of server-side extension.
  if [ "$seconds_left" -gt 3600 ]; then
    sleep 3600
    continue
  fi

  cookie_header=$(build_cookie_header)
  if [ -z "$cookie_header" ]; then
    echo "[session-warmer] no cookies to send for $primary — marking stale" >&2
    jq '.auth.stale = true | .auth.failure_reason = "no_cookies_in_state" | .auth.refresh_failure_count = (.auth.refresh_failure_count + 1)' \
      "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
    exit 1
  fi

  # Keepalive — GET the primary domain root, follow no redirects, just see what comes back
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://${primary}/" \
    -H "Cookie: $cookie_header" \
    -H "X-HackerOne-Research: ${H1_USER:-4dlt}" \
    -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    -m 10 2>/dev/null || echo "000")

  case "$status" in
    200|302|303|304)
      # Healthy — log a soft "refresh" (it's a keepalive, not a token rotation)
      jq '.auth.last_refreshed_at = (now | strftime("%Y-%m-%dT%H:%M:%SZ"))
         | .auth.refresh_count = (.auth.refresh_count + 1)' \
        "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
      ;;
    401|403)
      # Session rejected — set stale, exit so stale-watcher triggers AskUser
      jq --arg s "$status" \
        '.auth.stale = true
         | .auth.failure_reason = "session_keepalive_rejected_http_" + $s
         | .auth.refresh_failure_count = (.auth.refresh_failure_count + 1)' \
        "$STATE" > "$STATE.tmp" && mv "$STATE.tmp" "$STATE"
      exit 1
      ;;
    *)
      # Network error or unexpected status — log but don't kill the loop
      echo "[session-warmer] unexpected status=$status, will retry" >&2
      ;;
  esac

  sleep 60
done
