#!/usr/bin/env bash
# Smoke test for lib/evidence-rule-check.sh (validator Q1 helper).
# Exercises 4 representative classes across all 4 evidence-pattern categories:
#   xss_stored            → browser_required
#   ssrf                  → oob_or_timing_required
#   source_map_exposed    → response_body_proof

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB="$SCRIPT_DIR/../../lib"

XSS_NO_BROWSER='{"class":"xss_stored","validation_evidence":{"browser_verified":false}}'
XSS_BROWSER='{"class":"xss_stored","validation_evidence":{"browser_verified":true}}'
SSRF_OOB='{"class":"ssrf","validation_evidence":{"oob_callback_received":true}}'
SOURCE_MAP_NO_EXCERPT='{"class":"source_map_exposed","validation_evidence":{"response_excerpt":""}}'

check() {
  local expected="$1" label="$2" input="$3"
  local result
  result=$(echo "$input" | "$LIB/evidence-rule-check.sh")
  if [ "$result" = "$expected" ]; then
    echo "[PASS] $label → $expected"
  else
    echo "[FAIL] $label expected $expected, got $result"
    exit 1
  fi
}

check FAIL "xss without browser"        "$XSS_NO_BROWSER"
check PASS "xss with browser"            "$XSS_BROWSER"
check PASS "ssrf with OOB"               "$SSRF_OOB"
check FAIL "source_map without excerpt"  "$SOURCE_MAP_NO_EXCERPT"

echo "ALL EVIDENCE RULE TESTS PASSED"
