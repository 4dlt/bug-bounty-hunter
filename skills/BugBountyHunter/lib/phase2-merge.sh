#!/usr/bin/env bash
# Phase 2 merge — collect all $WORKDIR/findings/<id>/finding.json into
# $WORKDIR/state.json.findings[]. Runs after all attack agents complete,
# before Phase 2.9. Skips directories without finding.json and skips
# malformed JSON files with a warning to the audit log.
#
# Replaces the legacy "cat agents/<letter>-results.json | jq -s .findings" pattern.
# Attack agents no longer write to agents/*-results.json — see AgentPrompts/attack-*.md
# "Output Protocol v3.2" sections.
set -euo pipefail

: "${WORKDIR:?WORKDIR required}"

test -d "$WORKDIR/findings" || { echo "phase2-merge: $WORKDIR/findings does not exist" >&2; exit 1; }

MERGED="[]"
SKIPPED=0
MALFORMED_IDS=()

for d in "$WORKDIR"/findings/*/; do
  [[ -d "$d" ]] || continue
  fj="$d/finding.json"
  dir_name=$(basename "$d")
  if [[ ! -f "$fj" ]]; then
    SKIPPED=$((SKIPPED+1))
    continue
  fi
  if ! F=$(jq . "$fj" 2>/dev/null); then
    MALFORMED_IDS+=("$dir_name")
    SKIPPED=$((SKIPPED+1))
    continue
  fi
  MERGED=$(jq --argjson f "$F" '. + [$f]' <<<"$MERGED")
done

if [[ ! -f "$WORKDIR/state.json" ]]; then echo '{}' > "$WORKDIR/state.json"; fi
jq --argjson m "$MERGED" '. + {findings: $m}' "$WORKDIR/state.json" > "$WORKDIR/state.json.tmp"
mv "$WORKDIR/state.json.tmp" "$WORKDIR/state.json"

# Audit-log entry
MALFORMED_JSON=$(printf '%s\n' "${MALFORMED_IDS[@]+"${MALFORMED_IDS[@]}"}" | jq -R . | jq -s .)
LINE=$(jq -cn \
  --arg ts "$(date -u +%FT%TZ)" \
  --argjson merged "$(echo "$MERGED" | jq 'length')" \
  --argjson skipped "$SKIPPED" \
  --argjson malformed "$MALFORMED_JSON" \
  '{ts:$ts, phase:"2", event:"phase2_merge", merged:$merged, skipped:$skipped, malformed_ids:$malformed}')
printf '%s\n' "$LINE" >> "$WORKDIR/audit-log.jsonl"
