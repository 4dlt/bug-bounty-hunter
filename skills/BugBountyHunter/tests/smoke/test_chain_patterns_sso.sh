#!/usr/bin/env bash
# Smoke test for the V-001 OAuth state-parameter chain pattern (M4).
# Verifies that state-good.json's sso_chain contains all 3 leak indicators
# required by ChainPatterns.yaml to auto-promote this class of finding to P2.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FIXTURE="$SCRIPT_DIR/../fixtures/state-good.json"

# Flatten leaks_detected across all sso_chain hops and deduplicate.
LEAKS=$(jq '[.auth.sso_chain[].leaks_detected[]] | unique' "$FIXTURE")

EXPECTED=(
  "referrer-policy: unsafe-url"
  "origin_uri in state parameter"
  "OAuth code in URL"
)

ALL_PRESENT=true
for needle in "${EXPECTED[@]}"; do
  if ! echo "$LEAKS" | jq -e --arg n "$needle" 'index($n) != null' >/dev/null; then
    echo "[FAIL] missing V-001 indicator: $needle"
    ALL_PRESENT=false
  fi
done

if $ALL_PRESENT; then
  echo "[PASS] V-001 SSO pattern indicators all present in fixture"
  echo "SSO PATTERN TEST PASSED"
  exit 0
fi

exit 1
