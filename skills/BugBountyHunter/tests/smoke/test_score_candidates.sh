#!/usr/bin/env bash
# Smoke test for lib/score-candidates.sh (Phase 2.5 candidate scorer).
# Validates round-1 top-N selection, round-2 offset skip, descending sort, and
# empty-tail behavior when skip exceeds total.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB="$SCRIPT_DIR/../../lib"
FIXTURE="$SCRIPT_DIR/../fixtures/state-with-findings.json"

# Test 1: round-1 returns top 5
TOP5=$("$LIB/score-candidates.sh" "$FIXTURE" 0 5 | jq 'length')
if [ "$TOP5" != "5" ]; then
  echo "[FAIL] expected 5 candidates, got $TOP5"
  exit 1
fi
echo "[PASS] round 1 returns 5 candidates"

# Test 2: round-2 returns next 5 (skip 5, take 5)
NEXT5=$("$LIB/score-candidates.sh" "$FIXTURE" 5 5 | jq 'length')
if [ "$NEXT5" != "5" ]; then
  echo "[FAIL] expected 5 candidates in round 2, got $NEXT5"
  exit 1
fi
echo "[PASS] round 2 returns next 5"

# Test 3: scores monotonically decrease
SCORES=$("$LIB/score-candidates.sh" "$FIXTURE" 0 10 | jq -r '.[].score')
PREV=999
for s in $SCORES; do
  if [ "$s" -gt "$PREV" ]; then
    echo "[FAIL] scores not sorted descending ($s > $PREV)"
    exit 1
  fi
  PREV="$s"
done
echo "[PASS] scores sorted descending"

# Test 4: returns empty when skip exceeds total
EMPTY=$("$LIB/score-candidates.sh" "$FIXTURE" 100 5 | jq 'length')
if [ "$EMPTY" != "0" ]; then
  echo "[FAIL] expected 0 candidates when skipping 100, got $EMPTY"
  exit 1
fi
echo "[PASS] empty when skip exceeds total"

echo "ALL SCORE CANDIDATES TESTS PASSED"
