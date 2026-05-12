#!/usr/bin/env bash
# Spawn 5 concurrent processes, each doing 20 jq+mv writes against a single
# state.json. Verifies that mv-on-same-fs atomicity holds — the file is never
# half-written or corrupted, even under contention. Some interleavings will
# overwrite each other (expected — single-writer-per-field is what eliminates
# write loss in production code, not lock-free CAS).

set -e
WORKDIR=$(mktemp -d -t v3-atomic-test-XXXXXX)
trap "rm -rf $WORKDIR" EXIT

echo '{"counter": 0}' > "$WORKDIR/state.json"

for i in $(seq 1 5); do
  (
    for j in $(seq 1 20); do
      jq ".counter = ($i * 100 + $j)" "$WORKDIR/state.json" > "$WORKDIR/state.tmp.$i" \
        && mv "$WORKDIR/state.tmp.$i" "$WORKDIR/state.json"
    done
  ) &
done
wait

if jq -e . "$WORKDIR/state.json" >/dev/null; then
  FINAL=$(jq -r '.counter' "$WORKDIR/state.json")
  echo "[PASS] state.json valid JSON after 100 concurrent writes (final counter: $FINAL)"
  echo "ATOMIC WRITE RACE TEST PASSED"
else
  echo "[FAIL] state.json corrupted after concurrent writes:"
  cat "$WORKDIR/state.json"
  exit 1
fi
