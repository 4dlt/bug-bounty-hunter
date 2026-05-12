#!/usr/bin/env bash
# Phase 0 account-mode detector.
#
# Reads: $WORKDIR/scope.yaml
# Writes: $WORKDIR/pipeline-mode.json — {mode, account_count, scope_yaml_fingerprint}
#
# 4 modes:
#   no_auth              — scope.yaml has no auth section; IDOR/BOLA classes must be skipped entirely
#   partial_idor         — 1 account; cross-tenant claims auto-reject at Phase 2.9
#                           (attack agents must use idor_auth_logic for authorization-logic bugs)
#   full_idor            — 2+ accounts; cross-tenant artifacts can be produced
#   self_signup_promoted — 1 account + self_signup_allowed:true in scope.yaml
#                           (the pipeline can register a second test account; treat as full_idor)
#
# Consumed by:
#   lib/phase29-gate.sh (B4 cross-tenant guard)
#   AgentPrompts/attack-*.md (mode gets injected into attack-agent prompts by the orchestrator
#                              so agents know which class labels are permitted)
set -euo pipefail

: "${WORKDIR:?WORKDIR required}"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"
SCOPE="$WORKDIR/scope.yaml"

test -f "$SCOPE" || { echo "detect-account-mode: $SCOPE missing" >&2; exit 1; }

SCOPE_JSON=$("$YAML2JSON" < "$SCOPE")

# Count auth entries: scalar {username, password} → 1; list → length; null/absent → 0.
AUTH_COUNT=$(echo "$SCOPE_JSON" | jq '
  if .auth == null then 0
  elif (.auth | type) == "object" and (.auth.username or .auth.password) then 1
  elif (.auth | type) == "array" then (.auth | length)
  else 0
  end
')

SELF_SIGNUP=$(echo "$SCOPE_JSON" | jq -r '.self_signup_allowed // false')

if [[ "$AUTH_COUNT" -ge 2 ]]; then
  MODE="full_idor"
elif [[ "$AUTH_COUNT" == "1" && "$SELF_SIGNUP" == "true" ]]; then
  MODE="self_signup_promoted"
elif [[ "$AUTH_COUNT" == "1" ]]; then
  MODE="partial_idor"
else
  MODE="no_auth"
fi

# SHA-256 fingerprint of scope.yaml so consumers can detect drift
FP=$(sha256sum "$SCOPE" | awk '{print $1}')

jq -n \
  --arg mode "$MODE" \
  --argjson count "$AUTH_COUNT" \
  --arg fp "$FP" \
  --arg detected_at "$(date -u +%FT%TZ)" \
  '{mode:$mode, account_count:$count, scope_yaml_fingerprint:$fp, detected_at:$detected_at}' \
  > "$WORKDIR/pipeline-mode.json"
