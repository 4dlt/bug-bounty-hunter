#!/usr/bin/env bash
# Usage:
#   echo '{finding_json}' | evidence-rule-check.sh
#   evidence-rule-check.sh <finding.json>
#
# Reads a single finding from stdin (or the path argument), looks up its
# .class in config/EvidenceRules.yaml, applies the matching Q1 evidence
# check, and prints "PASS" or "FAIL" to stdout. Classes not listed in the
# rules file fall back to the binary browser_verified check. Used by the
# validator agent's Reportability Test.

set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RULES="$SCRIPT_DIR/../config/EvidenceRules.yaml"

fallback_browser_check() {
  if echo "$1" | jq -e '.validation_evidence.browser_verified == true' >/dev/null 2>&1; then
    echo "PASS"
  else
    echo "FAIL"
  fi
}

# Read finding JSON
if [ $# -gt 0 ] && [ -f "$1" ]; then
  FINDING=$(cat "$1")
else
  FINDING=$(cat)
fi

if [ ! -f "$RULES" ]; then
  echo "[FALLBACK] EvidenceRules.yaml missing — using binary browser_verified" >&2
  fallback_browser_check "$FINDING"
  exit 0
fi

CLASS=$(echo "$FINDING" | jq -r '.class // empty')

# Determine which evidence rule applies to this class
RULE=$(python3 - "$RULES" "$CLASS" <<'PY'
import sys, yaml
rules = yaml.safe_load(open(sys.argv[1]))
cls = sys.argv[2]
for rule_name, classes in (rules or {}).items():
    if isinstance(classes, list) and cls in classes:
        print(rule_name)
        sys.exit(0)
print("unknown")
PY
)

case "$RULE" in
  browser_required)
    if echo "$FINDING" | jq -e '.validation_evidence.browser_verified == true' >/dev/null 2>&1; then
      echo "PASS"
    else
      echo "FAIL"
    fi
    ;;
  oob_or_timing_required)
    if echo "$FINDING" | jq -e '.validation_evidence.oob_callback_received == true or ((.validation_evidence.timing_differential_ms // 0) >= 3000)' >/dev/null 2>&1; then
      echo "PASS"
    else
      echo "FAIL"
    fi
    ;;
  response_body_proof)
    if echo "$FINDING" | jq -e '((.validation_evidence.response_excerpt // "") | length) > 0' >/dev/null 2>&1; then
      echo "PASS"
    else
      echo "FAIL"
    fi
    ;;
  server_state_proof)
    if echo "$FINDING" | jq -e '.validation_evidence.before_after_state != null' >/dev/null 2>&1; then
      echo "PASS"
    else
      echo "FAIL"
    fi
    ;;
  *)
    fallback_browser_check "$FINDING"
    ;;
esac
