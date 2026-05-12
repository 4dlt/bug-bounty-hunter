#!/usr/bin/env bash
# Usage: race-test.sh <url> <method> [cookie-string] [max-allowed-limit]
#
# Fires N parallel requests against the endpoint and emits a JSON summary
# to stdout. Detection heuristic (both conditions flag a race):
#   1. Multiple distinct response bodies (TOCTOU producing divergent state)
#   2. Count of "allowed: true" responses > the endpoint's rate cap
#      (more accepted increments than the server thinks it permitted)
#
# The 4th arg `max-allowed-limit` defaults to 10 (matches mock-race-server).
# Real-world callers (SKILL.md Phase 2.5) should set it from rate_limit
# configured in scope.yaml or the observed HTTP 429 boundary.
#
# Output fields:
#   endpoint, method, total_requests, distinct_bodies, allowed_count,
#   max_allowed_limit, race_detected, sample_bodies

set -u
URL="${1:?url required}"
METHOD="${2:-POST}"
COOKIE="${3:-}"
MAX_ALLOWED_LIMIT="${4:-10}"
PARALLEL=20
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Fire N requests in parallel; each response body to its own file.
for i in $(seq 1 "$PARALLEL"); do
  (
    curl -s -o "$TMP/resp-$i" -X "$METHOD" "$URL" \
      ${COOKIE:+-H "Cookie: $COOKIE"} \
      -m 5 || true
  ) &
done
wait

# Distinct-body count: one line per response file, then sort -u.
DISTINCT=$(for f in "$TMP"/resp-*; do
  [ -s "$f" ] || continue
  tr -d '\n' < "$f"
  echo
done | sort -u | wc -l)

# Count responses with `allowed: true` (JSON field, mock server shape).
ALLOWED_COUNT=$(for f in "$TMP"/resp-*; do
  jq -r 'select(.allowed == true) | "1"' "$f" 2>/dev/null
done | wc -l)

# Race heuristic: allowed_count exceeded the stated limit.
RACE_DETECTED=false
if [ "$ALLOWED_COUNT" -gt "$MAX_ALLOWED_LIMIT" ]; then
  RACE_DETECTED=true
fi

# Sample first 3 unique bodies (200 chars max each).
SAMPLE=$(for f in "$TMP"/resp-*; do
  [ -s "$f" ] || continue
  tr -d '\n' < "$f"
  echo
done | sort -u | head -3 \
  | jq -R -s -c 'split("\n") | map(select(length > 0)) | map(.[0:200])')

jq -n \
  --arg url "$URL" \
  --arg method "$METHOD" \
  --argjson total "$PARALLEL" \
  --argjson distinct "$DISTINCT" \
  --argjson allowed "$ALLOWED_COUNT" \
  --argjson limit "$MAX_ALLOWED_LIMIT" \
  --argjson detected "$RACE_DETECTED" \
  --argjson sample "$SAMPLE" \
  '{
    endpoint: $url,
    method: $method,
    total_requests: $total,
    distinct_bodies: $distinct,
    allowed_count: $allowed,
    max_allowed_limit: $limit,
    race_detected: $detected,
    sample_bodies: $sample
  }'
