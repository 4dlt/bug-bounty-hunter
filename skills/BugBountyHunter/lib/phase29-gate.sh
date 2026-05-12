#!/usr/bin/env bash
# Phase 2.9 mechanical gate — NO LLM calls.
#
# Reads:
#   - $WORKDIR/findings/<id>/finding.json   (emitted per-finding by attack agents)
#   - $WORKDIR/scope.yaml                    (program-level rules; optional for B1)
#   - $WORKDIR/pipeline-mode.json            (account-mode gate; used in B4)
#   - config/ArtifactMatrix.yaml             (program_excluded_classes + class_aliases)
#   - config/PublicSafeList.yaml             (used in B3)
#
# Writes:
#   - $WORKDIR/state.json                    (.artifact_discarded[] + .findings[])
#   - $WORKDIR/audit-log.jsonl               (appended — one line per decision; used in B5)
#
# Decision branches (layered in B1 → B5; this file currently implements B1):
#   B1: class in program_excluded_classes → artifact_discarded PROGRAM_EXCLUDED_CLASS
#   B2: class requires artifacts and they're missing → MISSING_ARTIFACT
#   B3: info_disclosure with only public-safe content → PUBLIC_BY_DESIGN
#   B4: cross_tenant class in partial_idor mode → UNPROVABLE_SINGLE_ACCOUNT
#   B5: chain constituent rejected → CHAIN_CONSTITUENT_REJECTED
#
# Idempotency: safe to re-run. Already-processed findings keep their disposition.
set -euo pipefail

: "${WORKDIR:?WORKDIR required}"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"
MATRIX="$SKILL_DIR/config/ArtifactMatrix.yaml"
SAFE_LIST="$SKILL_DIR/config/PublicSafeList.yaml"

test -d "$WORKDIR/findings" || { echo "phase29-gate: $WORKDIR/findings does not exist" >&2; exit 1; }
test -x "$YAML2JSON"         || { echo "phase29-gate: $YAML2JSON not executable" >&2; exit 1; }
test -f "$MATRIX"            || { echo "phase29-gate: $MATRIX missing" >&2; exit 1; }
test -f "$SAFE_LIST"         || { echo "phase29-gate: $SAFE_LIST missing" >&2; exit 1; }

MATRIX_JSON=$("$YAML2JSON" < "$MATRIX")
SAFE_LIST_JSON=$("$YAML2JSON" < "$SAFE_LIST")

# Pipeline mode (from Phase 0). Default to "full_idor" if the mode file is absent
# — a conservative backward-compat default that does NOT auto-reject cross-tenant
# claims. Phase 0 (D1) writes this file; older workflows without it are not penalized.
PIPELINE_MODE="full_idor"
if [[ -f "$WORKDIR/pipeline-mode.json" ]]; then
  PIPELINE_MODE=$(jq -r '.mode // "full_idor"' "$WORKDIR/pipeline-mode.json")
fi

# B3 matcher: emit the id of the first matching safe-by-design pattern, or "null".
# File-size rule: only auto-reject when content size < 1024 bytes (short dumps that
# are likely single-purpose exposures of a public-by-design token). Larger files are
# kept because mixed content is too risky to auto-reject.
public_safe_match() {
  local content_file="$1"
  [[ -f "$content_file" ]] || { echo "null"; return; }
  local size
  size=$(wc -c < "$content_file")
  if [[ "$size" -ge 1024 ]]; then
    echo "null"; return
  fi
  python3 - "$content_file" "$SAFE_LIST_JSON" <<'PY'
import json, re, sys
with open(sys.argv[1]) as f:
    content = f.read()
data = json.loads(sys.argv[2])
for entry in data.get("known_safe_by_design", []):
    if re.search(entry["pattern"], content, re.MULTILINE):
        print(json.dumps({"match": entry["id"]}))
        sys.exit(0)
print("null")
PY
}

# Collect all finding JSONs from per-finding directories.
# Use an intermediate array so the shell doesn't choke on spaces.
FINDING_FILES=()
for d in "$WORKDIR"/findings/*/; do
  [[ -d "$d" ]] || continue
  fj="$d/finding.json"
  [[ -f "$fj" ]] && FINDING_FILES+=("$fj")
done

DISCARDED="[]"
SURVIVING="[]"

# Per-decision audit logging. B5 emits one JSONL line per finding with either
# "discard" or "survive" event so a later auditor can reconstruct the mechanical
# gate's reasoning without re-running it.
audit_log() {
  local event="$1" id="$2" reason="${3:-}" extra="${4:-}"
  # Build the line via jq so quoting, newlines, and nested JSON are handled safely.
  local line
  if [[ -n "$extra" ]]; then
    line=$(jq -cn \
      --arg ts "$(date -u +%FT%TZ)" \
      --arg event "$event" \
      --arg id "$id" \
      --arg reason "$reason" \
      --argjson extra "$extra" \
      '{ts:$ts, phase:"2.9", event:$event, id:$id, reason:$reason, extra:$extra}')
  else
    line=$(jq -cn \
      --arg ts "$(date -u +%FT%TZ)" \
      --arg event "$event" \
      --arg id "$id" \
      --arg reason "$reason" \
      '{ts:$ts, phase:"2.9", event:$event, id:$id, reason:$reason}')
  fi
  printf '%s\n' "$line" >> "$WORKDIR/audit-log.jsonl"
}

for fj in "${FINDING_FILES[@]}"; do
  F=$(cat "$fj")
  ID=$(echo "$F" | jq -r '.id // empty')
  RAW_CLASS=$(echo "$F" | jq -r '.class // empty')

  if [[ -z "$ID" || -z "$RAW_CLASS" ]]; then
    # Malformed finding — discard defensively with MALFORMED_INPUT
    DISCARDED=$(jq --argjson f "$F" \
      '. + [($f + {reason:"MALFORMED_INPUT", reason_detail:"finding.json missing required id or class field"})]' <<<"$DISCARDED")
    continue
  fi

  # Resolve class via class_aliases map (fine-grained attack-agent class →
  # canonical ArtifactMatrix class). Falls through to raw class if no alias.
  CANONICAL_CLASS=$(echo "$MATRIX_JSON" | jq -r --arg c "$RAW_CLASS" \
    '.class_aliases[$c] // $c')

  # B1: program-excluded-class branch.
  # A class in ArtifactMatrix.program_excluded_classes is unconditionally
  # rejected at Phase 2.9 — these are the canonical "never worth reporting"
  # classes the matrix opines on (missing_security_headers, insecure cookies,
  # permissive CSP on API hosts, clickjacking, rate-limiting, etc.).
  EXCLUDED=$(echo "$MATRIX_JSON" | jq --arg c "$CANONICAL_CLASS" \
    '.program_excluded_classes | index($c) != null')
  if [[ "$EXCLUDED" == "true" ]]; then
    DISCARDED=$(jq \
      --arg id "$ID" \
      --arg rc "$RAW_CLASS" \
      --arg cc "$CANONICAL_CLASS" \
      '. + [{id:$id, class:$rc, canonical_class:$cc, reason:"PROGRAM_EXCLUDED_CLASS", reason_detail:("class \($cc) is in ArtifactMatrix.program_excluded_classes — never worth reporting in this program")}]' \
      <<<"$DISCARDED")
    audit_log "discard" "$ID" "$(echo "$DISCARDED" | jq -r '.[-1].reason')"
    continue
  fi

  # B4: cross-tenant mode guard.
  # If pipeline is in partial_idor mode (only 1 account available), reject any finding
  # whose canonical class is in matrix.cross_tenant_classes — cross-tenant claims are
  # structurally unprovable with a single account. Attack agents in partial_idor mode
  # should have used idor_auth_logic instead; if they claim idor/bola here, the claim
  # is mis-framed. Reason: UNPROVABLE_SINGLE_ACCOUNT.
  if [[ "$PIPELINE_MODE" == "partial_idor" ]]; then
    IS_CROSS_TENANT=$(echo "$MATRIX_JSON" | jq --arg c "$CANONICAL_CLASS" \
      '.cross_tenant_classes | index($c) != null')
    if [[ "$IS_CROSS_TENANT" == "true" ]]; then
      DISCARDED=$(jq \
        --arg id "$ID" \
        --arg rc "$RAW_CLASS" \
        --arg cc "$CANONICAL_CLASS" \
        '. + [{id:$id, class:$rc, canonical_class:$cc, reason:"UNPROVABLE_SINGLE_ACCOUNT", reason_detail:"pipeline mode is partial_idor (1 account); cross-tenant claims for idor/bola cannot be demonstrated. Attack agent should use idor_auth_logic for single-account authorization bugs."}]' \
        <<<"$DISCARDED")
      audit_log "discard" "$ID" "UNPROVABLE_SINGLE_ACCOUNT"
      continue
    fi
  fi

  # B3: public-safe-list branch (before B2 so info_disclosure with only a public-safe
  # secret fires as PUBLIC_BY_DESIGN — more informative than the generic missing-artifact
  # reason. Only applies when exfiltrated-secret.txt exists; if it doesn't, B2 handles it.)
  if [[ "$CANONICAL_CLASS" == "info_disclosure" ]]; then
    FINDING_DIR=$(dirname "$fj")
    SECRET_FILE="$FINDING_DIR/exfiltrated-secret.txt"
    if [[ -f "$SECRET_FILE" ]]; then
      MATCH=$(public_safe_match "$SECRET_FILE")
      if [[ "$MATCH" != "null" ]]; then
        MATCH_ID=$(echo "$MATCH" | jq -r '.match')
        DISCARDED=$(jq \
          --arg id "$ID" \
          --arg rc "$RAW_CLASS" \
          --arg cc "$CANONICAL_CLASS" \
          --arg m "$MATCH_ID" \
          '. + [{id:$id, class:$rc, canonical_class:$cc, reason:"PUBLIC_BY_DESIGN", match:$m, reason_detail:("exfiltrated-secret.txt matches known-safe-by-design pattern: \($m)")}]' \
          <<<"$DISCARDED")
        audit_log "discard" "$ID" "PUBLIC_BY_DESIGN" "$(jq -n --arg m "$MATCH_ID" '{match:$m}')"
        continue
      fi
    fi
  fi

  # B2: missing-artifact branch.
  # If the canonical class has a classes[CLASS].required_artifacts list, every
  # file in that list must exist in the finding directory. Classes with an
  # alternate_artifacts set accept EITHER all required OR all alternate files.
  # Classes not in matrix.classes (including unknown/novel) fall through —
  # Phase 3 handles them via NOVEL_CLASS_NEEDS_REVIEW path.
  CLASS_SPEC=$(echo "$MATRIX_JSON" | jq --arg c "$CANONICAL_CLASS" '.classes[$c] // null')
  if [[ "$CLASS_SPEC" != "null" ]]; then
    FINDING_DIR=$(dirname "$fj")
    REQUIRED=$(echo "$CLASS_SPEC" | jq -r '.required_artifacts[]? // empty')
    ALTERNATE=$(echo "$CLASS_SPEC" | jq -r '.alternate_artifacts[]? // empty')
    REJECTION_REASON=$(echo "$CLASS_SPEC" | jq -r '.rejection_reason // "MISSING_ARTIFACT"')

    MISSING_REQUIRED=()
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      [[ -f "$FINDING_DIR/$f" ]] || MISSING_REQUIRED+=("$f")
    done <<<"$REQUIRED"

    if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
      # Primary set is incomplete — try the alternate set if one exists.
      HAS_FULL_ALTERNATE=false
      if [[ -n "$ALTERNATE" ]]; then
        HAS_FULL_ALTERNATE=true
        while IFS= read -r f; do
          [[ -z "$f" ]] && continue
          if [[ ! -f "$FINDING_DIR/$f" ]]; then HAS_FULL_ALTERNATE=false; break; fi
        done <<<"$ALTERNATE"
      fi

      if [[ "$HAS_FULL_ALTERNATE" != "true" ]]; then
        MISSING_JSON=$(printf '%s\n' "${MISSING_REQUIRED[@]}" | jq -R . | jq -s .)
        DISCARDED=$(jq \
          --arg id "$ID" \
          --arg rc "$RAW_CLASS" \
          --arg cc "$CANONICAL_CLASS" \
          --arg reason "$REJECTION_REASON" \
          --argjson missing "$MISSING_JSON" \
          '. + [{id:$id, class:$rc, canonical_class:$cc, reason:$reason, reason_detail:("required artifacts missing for class \($cc); alternate set was also incomplete or absent"), missing_artifacts:$missing}]' \
          <<<"$DISCARDED")
        audit_log "discard" "$ID" "$REJECTION_REASON" "$MISSING_JSON"
        continue
      fi
      # else: alternate set satisfied, fall through to survive
    fi
  fi

  # Survives all B1-B4 branches → passes through.
  SURVIVING=$(jq --argjson f "$F" '. + [$f]' <<<"$SURVIVING")
  audit_log "survive" "$ID" "passed_phase_2_9"
done

# E3: Chain-constituent rejection. If state.json.chain_findings[] references a
# finding that was just discarded, the chain itself must auto-discard — a chain
# cannot be stronger than its strongest proven link.
if [[ -f "$WORKDIR/state.json" ]]; then
  # Build the set of surviving finding ids for fast lookup
  SURV_IDS=$(echo "$SURVIVING" | jq -r '[.[].id] | sort | unique')

  # Collect chains whose constituents are all survivors
  CHAINS_EXISTING=$(jq '.chain_findings // []' "$WORKDIR/state.json")
  SURVIVING_CHAINS="[]"
  while IFS= read -r chain_line; do
    [[ -z "$chain_line" || "$chain_line" == "null" ]] && continue
    CHAIN=$(echo "$chain_line" | jq '.')
    CHAIN_ID=$(echo "$CHAIN" | jq -r '.id // empty')
    [[ -z "$CHAIN_ID" ]] && continue
    CONSTS=$(echo "$CHAIN" | jq -r '.constituents[]?')
    REJECTED=()
    while IFS= read -r c; do
      [[ -z "$c" ]] && continue
      if ! echo "$SURV_IDS" | jq -e --arg c "$c" 'index($c) != null' > /dev/null; then
        REJECTED+=("$c")
      fi
    done <<<"$CONSTS"

    if [[ ${#REJECTED[@]} -gt 0 ]]; then
      # One or more constituents got rejected — discard this chain
      REJ_JSON=$(printf '%s\n' "${REJECTED[@]}" | jq -R . | jq -s .)
      DISCARDED=$(jq --arg id "$CHAIN_ID" --argjson rc "$REJ_JSON" --argjson chain "$CHAIN" \
        '. + [{id:$id, reason:"CHAIN_CONSTITUENT_REJECTED", reason_detail:"one or more chain constituents were rejected at Phase 2.9; a chain cannot be stronger than its strongest proven link", rejected_constituents:$rc, chain_detail:$chain}]' \
        <<<"$DISCARDED")
      audit_log "discard" "$CHAIN_ID" "CHAIN_CONSTITUENT_REJECTED" "$REJ_JSON"
    else
      SURVIVING_CHAINS=$(jq --argjson c "$CHAIN" '. + [$c]' <<<"$SURVIVING_CHAINS")
    fi
  done < <(echo "$CHAINS_EXISTING" | jq -c '.[]')
else
  SURVIVING_CHAINS="[]"
fi

# Merge into state.json. Replace whole arrays (idempotent: re-running with same
# findings directory yields the same arrays).
if [[ ! -f "$WORKDIR/state.json" ]]; then echo '{}' > "$WORKDIR/state.json"; fi
jq --argjson d "$DISCARDED" --argjson s "$SURVIVING" --argjson ch "$SURVIVING_CHAINS" \
  '. + {artifact_discarded: $d, findings: $s, chain_findings: $ch}' \
  "$WORKDIR/state.json" > "$WORKDIR/state.json.tmp"
mv "$WORKDIR/state.json.tmp" "$WORKDIR/state.json"

# Audit-log placeholder: B5 will add per-decision entries here.
# For now, emit a single phase-transition marker so B5 can detect prior runs.
TS=$(date -u +%FT%TZ)
printf '{"ts":"%s","phase":"2.9","event":"gate_run","discarded_count":%d,"surviving_count":%d}\n' \
  "$TS" \
  "$(echo "$DISCARDED" | jq 'length')" \
  "$(echo "$SURVIVING" | jq 'length')" \
  >> "$WORKDIR/audit-log.jsonl"
