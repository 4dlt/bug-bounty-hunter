#!/usr/bin/env bash
# Usage: score-candidates.sh <state.json path> <skip> <take>
#
# Ranks endpoints in .findings[] by signal score and returns the requested
# slice as a JSON array. Scoring signals (see v3.2 design §4 Component 2):
#   has_5xx            +3   response_summary matches HTTP 5xx
#   reflected          +4   response_summary matches reflection markers
#   waf_passed         +2   .confirmed == true
#   interesting_param  +3   URL contains id/user/q/redirect/url/etc
#   state_changing     +2   method is POST/PUT/PATCH/DELETE
#   is_authed          +2   session present (always true in orchestrator context)
#
# Per-endpoint dedup: when multiple findings share (endpoint, method), the
# highest-scoring one wins. Output sorted descending by score; pagination is
# skip/take after sort.

set -e
STATE="$1"
SKIP="${2:-0}"
TAKE="${3:-5}"

if [ -z "$STATE" ] || [ ! -f "$STATE" ]; then
  echo "[ERROR] state file not found: $STATE" >&2
  exit 1
fi

jq --argjson skip "$SKIP" --argjson take "$TAKE" '
  [.findings[]? | select(.endpoint != null) | {
    endpoint,
    method: (.method // "GET"),
    has_5xx: ((.response_summary // "") | test("HTTP 5[0-9][0-9]")),
    reflected: ((.response_summary // "") | test("reflect|echoed back|appears in body|<img|<script"; "i")),
    waf_passed: (.confirmed // false),
    interesting_param: (.endpoint | test("[?&](id|user|q|redirect|url|path|file|search|next|callback|return)="; "i")),
    state_changing: ((.method // "GET") | test("POST|PUT|PATCH|DELETE")),
    is_authed: true
  }]
  | map(. + {
    score: (
      (if .has_5xx then 3 else 0 end) +
      (if .reflected then 4 else 0 end) +
      (if .waf_passed then 2 else 0 end) +
      (if .interesting_param then 3 else 0 end) +
      (if .state_changing then 2 else 0 end) +
      (if .is_authed then 2 else 0 end)
    )
  })
  | group_by({endpoint, method})
  | map(max_by(.score))
  | sort_by(-.score)
  | .[$skip:$skip+$take]
' "$STATE"
