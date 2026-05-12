#!/usr/bin/env bash
# C1 smoke test — Advocate agent prompt contains all 4 hard rules.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
P="$SKILL_DIR/AgentPrompts/advocate.md"

test -f "$P" || { echo "FAIL: advocate.md missing"; exit 1; }

# 4 hard rules must be present verbatim (lowercase-insensitive substring match)
for phrase in \
  "cannot claim impact not present in artifacts" \
  "cannot assign severity above P4 for source-only" \
  "cannot populate bounty_estimate without a matched precedent" \
  "must downgrade severity one tier"; do
  grep -qiF "$phrase" "$P" || { echo "FAIL: missing rule phrase: $phrase"; exit 1; }
done

# Required output fields in the JSON schema description
for field in class severity cwe impact_demonstrated bounty_estimate precedent_url reporter_submission_draft artifacts_cited; do
  grep -qF "\"$field\"" "$P" || { echo "FAIL: output schema missing field: $field"; exit 1; }
done

# Must reference the precedent-lookup script (not a free-form lookup)
grep -qF 'precedent-lookup.sh' "$P" || { echo "FAIL: advocate.md must reference lib/precedent-lookup.sh"; exit 1; }

# Must reference ArtifactMatrix class cap (P4 source-only)
grep -qiF "SKILL.md Rule 13" "$P" || grep -qiF "source-only" "$P" \
  || { echo "FAIL: advocate.md must reference source-only P4 cap"; exit 1; }

# No precedent → bounty null contract stated explicitly
grep -qiF "bounty_estimate to null" "$P" || grep -qiF "bounty stays null" "$P" \
  || { echo "FAIL: advocate.md must state null-precedent means null bounty"; exit 1; }

echo "PASS: advocate prompt has 4 hard rules + output schema + precedent contract"
