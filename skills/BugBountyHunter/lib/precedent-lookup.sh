#!/usr/bin/env bash
# Usage: precedent-lookup.sh --program <name> --class <class> --severity <P1-P5> \
#                            [--allow-placeholder] [--scope-yaml <path>]
# Also accepts --program=<name>, --class=<class>, --severity=<sev> forms.
#
# Emits a JSON object matching the best precedent, or the literal string "null".
#
# Lookup order:
#   1. Exact program + class + severity (with closed_as == "resolved", not placeholder unless opted in)
#   2. Fallback: program = "generic" + class + severity (same filters)
#   3. scope.yaml reward_grid — if --scope-yaml is passed and the file has a
#      reward_grid.tiers[$SEV] entry, use that as a last-resort precedent.
#      Programs that publish explicit bounty tables (most YesWeHack, Bugcrowd,
#      some H1) count as precedent for THIS engagement via the program's rules.
#   4. Otherwise: null
#
# Filters applied at every stage:
#   - closed_as must be "resolved" (duplicate/informative/NAR are anti-evidence — not precedents)
#   - placeholder rows are rejected unless --allow-placeholder is passed (stubs are not citable
#     facts and would re-enable hallucinated bounties if the Advocate consumed them)
#
# The Advocate agent MUST cite a non-null result (without --allow-placeholder) to populate
# bounty_estimate. No cite means bounty stays null.
#
# reward_grid schema in scope.yaml:
#   reward_grid:
#     source: "https://program-rules-url"   # citation URL for the grid itself
#     asset_value: high                     # the asset tier for this target
#     tiers:
#       P1: {low: 5000, high: 5000}
#       P2: {low: 2000, high: 2000}
#       P3: {low: 400,  high: 400}
#       P4: {low: 100,  high: 100}
#     currency: "EUR"
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$SKILL_DIR/data/HackerOnePrecedents.jsonl"

PROG="" CLASS="" SEV="" ALLOW_PLACEHOLDER=false SCOPE_YAML=""
while [[ $# -gt 0 ]]; do
  arg="$1"
  case "$arg" in
    --program=*)    PROG="${arg#*=}";    shift ;;
    --class=*)      CLASS="${arg#*=}";   shift ;;
    --severity=*)   SEV="${arg#*=}";     shift ;;
    --scope-yaml=*) SCOPE_YAML="${arg#*=}"; shift ;;
    --program)      PROG="${2:-}";       shift 2 ;;
    --class)        CLASS="${2:-}";      shift 2 ;;
    --severity)     SEV="${2:-}";        shift 2 ;;
    --scope-yaml)   SCOPE_YAML="${2:-}"; shift 2 ;;
    --allow-placeholder) ALLOW_PLACEHOLDER=true; shift ;;
    *) echo "precedent-lookup.sh: unknown arg $arg" >&2; exit 2 ;;
  esac
done

if [[ -z "$PROG" || -z "$CLASS" || -z "$SEV" ]]; then
  echo "precedent-lookup.sh: --program, --class, --severity all required" >&2
  exit 2
fi

test -f "$DATA" || { echo "precedent-lookup.sh: $DATA missing" >&2; exit 3; }

# Stage 1+2: public disclosure index lookup (exact program → generic fallback)
RESULT=$(grep -Ev '^#|^[[:space:]]*$' "$DATA" | jq -s \
  --arg p "$PROG" --arg c "$CLASS" --arg s "$SEV" --argjson allow_ph "$ALLOW_PLACEHOLDER" '
  map(select(
    .closed_as == "resolved"
    and ($allow_ph or (.placeholder // false) == false)
  )) as $usable |

  ($usable | map(select(.program == $p and .class == $c and .severity == $s))) as $exact |
  ($usable | map(select(.program == "generic" and .class == $c and .severity == $s))) as $generic |

  (if ($exact | length) > 0 then $exact[0]
   elif ($generic | length) > 0 then $generic[0]
   else null end)
')

# Stage 3: scope.yaml reward_grid fallback. Only consulted when stages 1+2
# missed AND --scope-yaml points at a readable file with a reward_grid.tiers
# entry for the requested severity. A published reward grid is a valid
# precedent per the program's own rules.
if [[ "$RESULT" == "null" && -n "$SCOPE_YAML" && -f "$SCOPE_YAML" ]]; then
  YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"
  SCOPE_JSON=$("$YAML2JSON" < "$SCOPE_YAML" 2>/dev/null || echo 'null')
  GRID_RESULT=$(echo "$SCOPE_JSON" | jq --arg p "$PROG" --arg s "$SEV" '
    if .reward_grid? and .reward_grid.tiers?[$s]? then
      {
        program: $p,
        class: null,
        severity: $s,
        bounty: .reward_grid.tiers[$s].high,
        bounty_low: .reward_grid.tiers[$s].low,
        bounty_high: .reward_grid.tiers[$s].high,
        currency: (.reward_grid.currency // "USD"),
        url: (.reward_grid.source // "program-rules"),
        closed_as: "reward_grid_published",
        placeholder: false,
        notes: ("from scope.yaml.reward_grid (asset_value=" + (.reward_grid.asset_value // "default") + ")")
      }
    else null end
  ')
  if [[ "$GRID_RESULT" != "null" ]]; then
    RESULT="$GRID_RESULT"
  fi
fi

echo "$RESULT"
