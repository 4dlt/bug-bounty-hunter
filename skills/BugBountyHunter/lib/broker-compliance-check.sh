#!/usr/bin/env bash
# Usage: WORKDIR=/path broker-compliance-check.sh <agent_id>
#
# Post-batch gate used by SKILL.md Phase 2. Exits 0 if the named attack agent
# logged a broker.py invocation for this run (WORKDIR/broker-log/<agent>.json
# exists), exits 1 otherwise. On non-compliance the orchestrator tags the
# agent's round-1 findings and re-spawns the agent once with an enforcement
# prompt prefix (see SKILL.md § Broker Compliance Gate).

set -u
: "${WORKDIR:?WORKDIR required}"
AGENT_ID="${1:?agent id required}"
BROKER_LOG="$WORKDIR/broker-log/${AGENT_ID}.json"

if [ -f "$BROKER_LOG" ]; then
  exit 0
else
  echo "[broker-gate] $AGENT_ID did not call broker.py — non-compliant" >&2
  exit 1
fi
