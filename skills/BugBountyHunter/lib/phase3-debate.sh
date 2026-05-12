#!/usr/bin/env bash
# Phase 3 debate orchestrator — applies the Advocate ⇆ Triager decision rule.
#
# Reads:
#   - $WORKDIR/state.json .findings[] (survivors from Phase 2.9)
#   - $WORKDIR/findings/<id>/advocate-argument.json (written by Advocate agent)
#   - $WORKDIR/findings/<id>/triager-verdict.json  (written by Triager agent)
#
# Writes:
#   - $WORKDIR/state.json with .validated_findings[] and .triager_closed[] merged
#   - $WORKDIR/audit-log.jsonl with a "debate_decision" event per finding
#
# Orchestrator does NOT spawn the Advocate/Triager agents — that's the caller's
# responsibility (SKILL.md Phase 3 section tells Claude to spawn them via Task
# tool for each finding, then run this script). If either output file is
# missing, the finding routes to triager_closed with a specific reason so no
# finding silently survives without both agents having weighed in.
#
# Decision rule:
#   ACCEPT verdict + high/medium confidence + precedent rule compliance →
#     validated_findings[]
#   Low-confidence ACCEPT → rewritten to INFORMATIVE_NO_IMPACT (tie-break: close)
#   Rule-3 violation (bounty set, precedent null) → close regardless of verdict
#   Any non-ACCEPT verdict → triager_closed[] with close_code preserved
#   Missing advocate or triager file → triager_closed[] with specific reason
#
# Ties go to close. Always.
set -euo pipefail

: "${WORKDIR:?WORKDIR required}"
test -f "$WORKDIR/state.json" || { echo "phase3-debate: $WORKDIR/state.json missing" >&2; exit 1; }

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"

audit_log_ph3() {
  local event="$1" id="$2" decision="$3" close_code="${4:-}" confidence="${5:-}"
  local line
  line=$(jq -cn \
    --arg ts "$(date -u +%FT%TZ)" \
    --arg event "$event" \
    --arg id "$id" \
    --arg decision "$decision" \
    --arg close_code "$close_code" \
    --arg confidence "$confidence" \
    '{ts:$ts, phase:"3", event:$event, id:$id, decision:$decision, close_code:$close_code, confidence:$confidence}')
  printf '%s\n' "$line" >> "$WORKDIR/audit-log.jsonl"
}

# Refusal detector: returns 0 (refusal detected) or 1 (valid output).
# Checks for two patterns:
#   1. File is not valid JSON (agent returned prose/refusal text instead of structured output)
#   2. File is valid JSON but its payload contains refusal language
# Both advocate and triager output files are subject to this check. Production callers
# should re-spawn the agent with a neutral-methodology prompt on first refusal (per
# the v3.2 Refusal Recovery Protocol); this orchestrator handles the SECOND refusal
# (file exists, still refused) by routing to a conservative close.
is_refusal() {
  local file="$1"
  # Path 1: not valid JSON → refusal
  if ! jq empty "$file" 2>/dev/null; then
    return 0
  fi
  # Path 2: valid JSON but content matches refusal signatures
  if jq -e '
    (.. | strings? | test("(?i)(I cannot|I'\''m unable|cannot assist|violates.*usage polic|I apologize.*but|refusal_detected)"))
    or (.refusal_detected // false)
    or (.error | type == "string" and test("(?i)(cannot|unable|refuse|policy)"))
  ' "$file" > /dev/null 2>&1; then
    return 0
  fi
  return 1
}

VALIDATED="[]"
CLOSED="[]"

# Iterate over Phase 2.9 survivors
IDS=$(jq -r '.findings[]?.id // empty' "$WORKDIR/state.json")

while IFS= read -r ID; do
  [[ -z "$ID" ]] && continue
  DIR="$WORKDIR/findings/$ID"
  ADV_FILE="$DIR/advocate-argument.json"
  TRI_FILE="$DIR/triager-verdict.json"

  # Advocate-side checks first (missing then refusal), then triager-side checks.
  # Order matters: a refused advocate with a missing triager must surface as
  # ADVOCATE_REFUSAL, not TRIAGER_UNAVAILABLE.
  if [[ ! -f "$ADV_FILE" ]]; then
    CLOSED=$(jq --arg id "$ID" \
      '. + [{id:$id, close_code:"ADVOCATE_UNAVAILABLE", cited_evidence:{kind:"missing_file", explanation:"advocate-argument.json not found — agent did not complete. Conservative close."}}]' \
      <<<"$CLOSED")
    audit_log_ph3 "debate_decision" "$ID" "close" "ADVOCATE_UNAVAILABLE" ""
    continue
  fi
  if is_refusal "$ADV_FILE"; then
    CLOSED=$(jq --arg id "$ID" \
      '. + [{id:$id, close_code:"ADVOCATE_REFUSAL", cited_evidence:{kind:"refusal_after_retry", explanation:"Advocate output file contains refusal content (not valid structured JSON, or JSON payload includes refusal language). Second refusal after Refusal Recovery Protocol; conservative close."}}]' \
      <<<"$CLOSED")
    REFUSAL_LINE=$(jq -cn --arg ts "$(date -u +%FT%TZ)" --arg id "$ID" --arg agent "advocate" \
      '{ts:$ts, phase:"3", event:"refusal_detected", id:$id, agent:$agent}')
    printf '%s\n' "$REFUSAL_LINE" >> "$WORKDIR/audit-log.jsonl"
    audit_log_ph3 "debate_decision" "$ID" "close" "ADVOCATE_REFUSAL" ""
    continue
  fi
  if [[ ! -f "$TRI_FILE" ]]; then
    CLOSED=$(jq --arg id "$ID" \
      '. + [{id:$id, close_code:"TRIAGER_UNAVAILABLE_CONSERVATIVE_CLOSE", cited_evidence:{kind:"missing_file", explanation:"triager-verdict.json not found — agent did not complete. Conservative close."}}]' \
      <<<"$CLOSED")
    audit_log_ph3 "debate_decision" "$ID" "close" "TRIAGER_UNAVAILABLE_CONSERVATIVE_CLOSE" ""
    continue
  fi
  if is_refusal "$TRI_FILE"; then
    CLOSED=$(jq --arg id "$ID" \
      '. + [{id:$id, close_code:"TRIAGER_REFUSAL_CONSERVATIVE_CLOSE", cited_evidence:{kind:"refusal_after_retry", explanation:"Triager output file contains refusal content. Second refusal; conservative close."}}]' \
      <<<"$CLOSED")
    REFUSAL_LINE=$(jq -cn --arg ts "$(date -u +%FT%TZ)" --arg id "$ID" --arg agent "triager" \
      '{ts:$ts, phase:"3", event:"refusal_detected", id:$id, agent:$agent}')
    printf '%s\n' "$REFUSAL_LINE" >> "$WORKDIR/audit-log.jsonl"
    audit_log_ph3 "debate_decision" "$ID" "close" "TRIAGER_REFUSAL_CONSERVATIVE_CLOSE" ""
    continue
  fi

  VERDICT=$(jq -r '.verdict // .close_code // "UNDEFINED"' "$TRI_FILE")
  CONFIDENCE=$(jq -r '.confidence // "low"' "$TRI_FILE")
  CLOSE_CODE=$(jq -r '.close_code // .verdict' "$TRI_FILE")
  CITED=$(jq '.cited_evidence // {}' "$TRI_FILE")

  # Advocate Rule 3 check: bounty non-null requires precedent non-null.
  ADV_BOUNTY=$(jq '.bounty_estimate' "$ADV_FILE")
  ADV_PRECEDENT=$(jq -r '.precedent_url' "$ADV_FILE")
  if [[ "$ADV_BOUNTY" != "null" && "$ADV_PRECEDENT" == "null" ]]; then
    CLOSED=$(jq --arg id "$ID" --arg reason "ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT" \
      --argjson bounty "$ADV_BOUNTY" \
      '. + [{id:$id, close_code:$reason, cited_evidence:{kind:"advocate_rule_3_violation", bounty:$bounty, precedent_url:null, explanation:"Advocate set bounty_estimate without matched precedent_url. Rule 3 requires precedent citation; no precedent means bounty_estimate must be null."}}]' \
      <<<"$CLOSED")
    audit_log_ph3 "debate_decision" "$ID" "close" "ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT" "$CONFIDENCE"
    continue
  fi

  # Tie-break: low-confidence ACCEPT → rewritten to INFORMATIVE_NO_IMPACT
  if [[ "$VERDICT" == "ACCEPT" && "$CONFIDENCE" == "low" ]]; then
    CLOSED=$(jq --arg id "$ID" \
      --argjson cited "$CITED" \
      '. + [{id:$id, close_code:"INFORMATIVE_NO_IMPACT", cited_evidence:($cited + {kind:"low_confidence_accept_rewritten", explanation:"Triager accepted with low confidence; orchestrator tie-break rewrites to INFORMATIVE_NO_IMPACT. Ties go to close."})}]' \
      <<<"$CLOSED")
    audit_log_ph3 "debate_decision" "$ID" "close" "INFORMATIVE_NO_IMPACT" "low"
    continue
  fi

  # ACCEPT with medium/high confidence → validated
  if [[ "$VERDICT" == "ACCEPT" ]]; then
    ADV=$(cat "$ADV_FILE")
    VALIDATED=$(jq --argjson adv "$ADV" --arg conf "$CONFIDENCE" \
      '. + [($adv + {phase_3_confidence:$conf})]' \
      <<<"$VALIDATED")
    audit_log_ph3 "debate_decision" "$ID" "validate" "ACCEPT" "$CONFIDENCE"
    continue
  fi

  # Any non-ACCEPT verdict → close with the triager's close_code and cited_evidence
  CLOSED=$(jq --arg id "$ID" --arg cc "$CLOSE_CODE" --argjson cited "$CITED" \
    '. + [{id:$id, close_code:$cc, cited_evidence:$cited}]' \
    <<<"$CLOSED")
  audit_log_ph3 "debate_decision" "$ID" "close" "$CLOSE_CODE" "$CONFIDENCE"
done <<<"$IDS"

# Merge into state.json
jq --argjson v "$VALIDATED" --argjson c "$CLOSED" \
  '. + {validated_findings: $v, triager_closed: $c}' \
  "$WORKDIR/state.json" > "$WORKDIR/state.json.tmp"
mv "$WORKDIR/state.json.tmp" "$WORKDIR/state.json"
