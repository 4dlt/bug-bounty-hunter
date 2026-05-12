#!/usr/bin/env bash
# Usage: spawn-verifier.sh <finding.json-path>
#        OR: echo <finding.json> | spawn-verifier.sh
#
# Called by the validator agent's Reportability Test when Q1 fails, as a
# last-chance recovery before the finding is discarded. Spawns the verifier
# subagent (AgentPrompts/verifier.md) via the orchestrator's Agent tool
# with the finding on stdin, then reads verifier-results.json and echoes
# "PASS" if `.verified == true`, "FAIL" otherwise.
#
# IMPORTANT: Agent tool dispatch is an orchestrator capability — this script
# cannot spawn subagents on its own. When invoked WITHOUT an orchestrator
# context (e.g., direct bash run from a smoke test), this is a stub that
# returns "FAIL" and logs a notice. The validator agent invocation happens
# inside the orchestrator's tool-calling loop; the orchestrator passes the
# Agent tool handle via the env var $ORCHESTRATOR_AGENT_TOOL (set by
# SKILL.md Phase 3). In stub mode that var is empty.

set -u

# Read finding JSON
if [ $# -gt 0 ] && [ -f "$1" ]; then
  FINDING=$(cat "$1")
  FID=$(echo "$FINDING" | jq -r '.id // "unknown"')
elif [ -p /dev/stdin ] || [ ! -t 0 ]; then
  FINDING=$(cat)
  FID=$(echo "$FINDING" | jq -r '.id // "unknown"')
else
  echo "[spawn-verifier] no finding input — pass a path or pipe stdin" >&2
  echo "FAIL"
  exit 0
fi

if [ -z "${ORCHESTRATOR_AGENT_TOOL:-}" ]; then
  echo "[spawn-verifier] stub mode — no orchestrator Agent tool available; finding $FID cannot be re-verified here" >&2
  echo "FAIL"
  exit 0
fi

# Orchestrator-context path: write finding to a handoff file and signal the
# orchestrator to spawn the verifier agent (the orchestrator reads
# $WORKDIR/verifier/queue/<fid>.json and invokes the Agent tool).
: "${WORKDIR:?WORKDIR required when not in stub mode}"
QUEUE_DIR="$WORKDIR/verifier/queue"
RESULT_DIR="$WORKDIR/verifier/results"
mkdir -p "$QUEUE_DIR" "$RESULT_DIR"

echo "$FINDING" > "$QUEUE_DIR/${FID}.json"

# Wait for orchestrator to process (3 min max — matches verifier's time budget)
for i in $(seq 1 180); do
  if [ -f "$RESULT_DIR/${FID}.json" ]; then
    if jq -e '.verified == true' "$RESULT_DIR/${FID}.json" >/dev/null 2>&1; then
      echo "PASS"
    else
      echo "FAIL"
    fi
    exit 0
  fi
  sleep 1
done

echo "[spawn-verifier] timeout waiting for verifier result for $FID" >&2
echo "FAIL"
