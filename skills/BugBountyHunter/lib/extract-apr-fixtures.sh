#!/usr/bin/env bash
# A4 — Extract the 10 validated findings from the 2026-04-18 23andme run into
# golden fixtures under tests/fixtures/golden/apr-2026-23andme/.
# These serve as regression inputs for Phase 2.9 + Phase 3 tests (T1 suite).
#
# Source is a one-time snapshot — idempotent to re-run. If the source file is
# missing (/tmp cleaned), the script refuses to overwrite existing fixtures.
set -euo pipefail

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${APR_FIXTURE_SOURCE:-/tmp/pentest-20260418-035000-v3/state.json}"
DEST="$SKILL_DIR/tests/fixtures/golden/apr-2026-23andme"

mkdir -p "$DEST"

if [[ ! -f "$SRC" ]]; then
  # Source gone (e.g., /tmp cleaned). Refuse to clobber existing fixtures.
  if compgen -G "$DEST/F-*.json" > /dev/null; then
    echo "extract-apr-fixtures.sh: source $SRC missing but fixtures already extracted — nothing to do" >&2
    exit 0
  fi
  echo "extract-apr-fixtures.sh: source $SRC missing and no pre-extracted fixtures found" >&2
  exit 1
fi

for id in F-K-001 F-K-003 F-J-001 F-F002 F-I-001 F-A-001 F-A-002 F-A-003 F-A-004 F-E-001; do
  jq --arg id "$id" '.validated_findings[] | select(.id == $id)' "$SRC" > "$DEST/$id.json"
  [[ -s "$DEST/$id.json" ]] || { echo "extract-apr-fixtures.sh: $id not found in $SRC" >&2; exit 2; }
done

# Also snapshot the scope.yaml the Apr-18 run used so regression tests can seed
# scope-excluded filtering without fabricating one. Source: the run workdir.
SCOPE_SRC="${APR_FIXTURE_SCOPE:-/tmp/pentest-20260418-035000-v3/scope.yaml}"
if [[ -f "$SCOPE_SRC" ]]; then
  cp "$SCOPE_SRC" "$DEST/scope.yaml"
fi

echo "extract-apr-fixtures.sh: wrote 10 fixtures + scope.yaml to $DEST"
