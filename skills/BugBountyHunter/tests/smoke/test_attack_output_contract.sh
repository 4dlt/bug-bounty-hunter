#!/usr/bin/env bash
# E1 smoke test — every attack-*.md has the new per-finding directory output contract.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PROMPT_DIR="$SKILL_DIR/AgentPrompts"

FAIL_COUNT=0
for p in "$PROMPT_DIR"/attack-*.md; do
  name=$(basename "$p")
  for marker in \
    "Output Protocol v3.2" \
    "findings/<id>/" \
    "finding.json" \
    "ArtifactMatrix.yaml" \
    "SUPERSEDES"; do
    if ! grep -qF "$marker" "$p"; then
      echo "FAIL: $name missing marker: $marker"
      FAIL_COUNT=$((FAIL_COUNT+1))
    fi
  done
done

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "FAIL: $FAIL_COUNT markers missing across attack prompts"
  exit 1
fi

echo "PASS: all attack-*.md have the v3.2 per-finding output contract"
