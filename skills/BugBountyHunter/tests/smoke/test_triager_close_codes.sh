#!/usr/bin/env bash
# C2 smoke test — Triager agent prompt has 10 close codes + cited_evidence contract.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
P="$SKILL_DIR/AgentPrompts/triager.md"

test -f "$P" || { echo "FAIL: triager.md missing"; exit 1; }

# All 10 close codes must appear
for code in \
  OUT_OF_SCOPE \
  INFORMATIVE_NO_IMPACT \
  DUPLICATE \
  NOT_REPRODUCIBLE \
  PUBLIC_BY_DESIGN \
  MISSING_CROSS_TENANT_PROOF \
  SELF_INFLICTED \
  LOW_IMPACT_HEADER \
  PARTIAL_REMEDIATION_DUPLICATE \
  ACCEPT; do
  grep -qF "$code" "$P" || { echo "FAIL: triager.md missing close code: $code"; exit 1; }
done

# Role prompt must frame the Triager as adversarial (key design decision)
grep -qiF "closing junk" "$P" || grep -qiF "skeptical" "$P" \
  || { echo "FAIL: triager role must frame as adversarial"; exit 1; }

# Tie-break rule must be documented (conservative close)
grep -qiF "tie" "$P" && grep -qiF "close" "$P" \
  || { echo "FAIL: triager must document tie-break rule toward close"; exit 1; }

# Output schema fields
for field in verdict close_code cited_evidence confidence; do
  grep -qF "\"$field\"" "$P" || { echo "FAIL: output schema missing field: $field"; exit 1; }
done

# Must require specific evidence per close code (not free-form)
grep -qiF "cited_evidence" "$P" \
  || { echo "FAIL: triager must require cited_evidence per close code"; exit 1; }

echo "PASS: triager prompt — 10 close codes + adversarial role + tie-break + schema"
