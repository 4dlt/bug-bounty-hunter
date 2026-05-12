#!/usr/bin/env bash
# Verifies every class mentioned in config/EvidenceRules.yaml is reachable via
# ArtifactMatrix — either directly (in .classes), via alias (in .class_aliases),
# or explicitly excluded (in .program_excluded_classes).
# This prevents silent class-drift between the two configs during the transition
# period where EvidenceRules.yaml is still consulted by legacy code paths.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"
MATRIX="$SKILL_DIR/config/ArtifactMatrix.yaml"
EVIDENCE="$SKILL_DIR/config/EvidenceRules.yaml"

MJ=$("$YAML2JSON" < "$MATRIX")
EJ=$("$YAML2JSON" < "$EVIDENCE")

# Collect every class name referenced in EvidenceRules (union of all 4 buckets)
EVIDENCE_CLASSES=$(echo "$EJ" | jq -r 'to_entries | map(.value) | add | .[]' | sort -u)

# Collect every class name ArtifactMatrix can resolve (classes keys + alias keys + excluded list)
RESOLVABLE=$(echo "$MJ" | jq -r '
  (.classes | keys) +
  (.class_aliases // {} | keys) +
  (.program_excluded_classes // [])
  | .[]' | sort -u)

MISSING=$(comm -23 <(echo "$EVIDENCE_CLASSES") <(echo "$RESOLVABLE"))
if [[ -n "$MISSING" ]]; then
  echo "FAIL: EvidenceRules classes not reachable via ArtifactMatrix (.classes / .class_aliases / .program_excluded_classes):"
  echo "$MISSING" | sed 's/^/  - /'
  exit 1
fi

echo "PASS: all EvidenceRules classes reachable via ArtifactMatrix"
