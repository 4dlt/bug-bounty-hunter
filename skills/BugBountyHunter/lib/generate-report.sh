#!/usr/bin/env bash
# Phase 4 report generator — reads $WORKDIR/state.json and writes
# $WORKDIR/report.md. Only sums bounty_estimate values for validated findings
# that carry a non-null precedent_url. Findings without precedent are listed
# as "bounty unknown — no precedent matched".
#
# The report has four sections:
#   1. Executive Summary
#   2. Validated Findings (with reporter_submission_draft inline)
#   3. Bounty Totals (precedent-cited only)
#   4. Triager-Closed Findings + Artifact-Discarded Findings (with reasons)
#
# No invented aggregate ranges. If no validated findings have precedent,
# the bounty total is "$0 (no precedent-cited findings)" and all bounty
# signals are labeled "bounty unknown".
set -euo pipefail

: "${WORKDIR:?WORKDIR required}"
STATE="$WORKDIR/state.json"
test -f "$STATE" || { echo "generate-report: $STATE missing" >&2; exit 1; }

OUT="$WORKDIR/report.md"
TARGET=$(jq -r '.target // "<unknown>"' "$STATE")
ENGAGEMENT=$(jq -r '.engagement_id // "<unknown>"' "$STATE")
MODE=$(jq -r '.pipeline_mode // "unknown"' "$STATE")
ACCT=$(jq -r '.account_count // 0' "$STATE")

# Compute bounty totals using only precedent-cited validated findings
TOTAL_LOW=$(jq '[.validated_findings[]? | select(.precedent_url != null and .bounty_estimate != null) | .bounty_estimate.low // 0] | add // 0' "$STATE")
TOTAL_HIGH=$(jq '[.validated_findings[]? | select(.precedent_url != null and .bounty_estimate != null) | .bounty_estimate.high // 0] | add // 0' "$STATE")
N_PRECEDENT=$(jq '[.validated_findings[]? | select(.precedent_url != null and .bounty_estimate != null)] | length' "$STATE")
N_UNKNOWN=$(jq '[.validated_findings[]? | select(.precedent_url == null or .bounty_estimate == null)] | length' "$STATE")

{
  echo "# Bug Bounty Report — $TARGET"
  echo ""
  echo "**Engagement:** $ENGAGEMENT  "
  echo "**Pipeline mode:** $MODE ($ACCT account(s))  "
  echo "**Generated:** $(date -u +%FT%TZ)"
  echo ""
  echo "## Executive Summary"
  echo ""
  VC=$(jq '.validated_findings | length' "$STATE")
  TC=$(jq '.triager_closed | length' "$STATE")
  AD=$(jq '.artifact_discarded | length' "$STATE")
  echo "- Validated findings: **$VC**"
  echo "- Triager-closed findings: $TC"
  echo "- Artifact-discarded findings: $AD"
  echo "- Bounty total (precedent-cited only): **\$$TOTAL_LOW - \$$TOTAL_HIGH**  _($N_PRECEDENT of $VC validated findings have matched precedent; $N_UNKNOWN have bounty unknown)_"
  echo ""

  echo "## Validated Findings"
  if [[ "$VC" == "0" ]]; then
    echo ""
    echo "_No findings passed the Advocate ⇆ Triager debate._"
    echo ""
  else
    jq -r '.validated_findings[]? | "### \(.id) — \(.class) (\(.severity))\n\n**Impact demonstrated:** \(.impact_demonstrated)\n\n**Bounty estimate:** " + (if .precedent_url != null then "$\(.bounty_estimate.low) - $\(.bounty_estimate.high) USD (precedent: \(.precedent_url))" else "bounty unknown — no precedent matched" end) + "\n\n**Reporter submission draft:**\n\n" + .reporter_submission_draft + "\n\n---\n"' "$STATE"
  fi

  echo "## Bounty Totals (precedent-cited only)"
  echo ""
  if [[ "$N_PRECEDENT" == "0" ]]; then
    echo "_No validated findings carry a matched HackerOne precedent. Total: \$0._"
  else
    echo "- Precedent-cited findings: $N_PRECEDENT"
    echo "- Total bounty range: **\$$TOTAL_LOW - \$$TOTAL_HIGH USD**"
    if [[ "$N_UNKNOWN" -gt 0 ]]; then
      echo "- Additional findings with bounty unknown: $N_UNKNOWN (not included in total)"
    fi
  fi
  echo ""

  echo "## Triager-Closed Findings"
  if [[ "$TC" == "0" ]]; then
    echo ""
    echo "_None._"
    echo ""
  else
    jq -r '.triager_closed[]? | "- **\(.id)** — \(.close_code): \(.cited_evidence.explanation // .cited_evidence.kind // "no explanation")"' "$STATE"
    echo ""
  fi

  echo "## Artifact-Discarded Findings (Phase 2.9 mechanical gate)"
  if [[ "$AD" == "0" ]]; then
    echo ""
    echo "_None._"
    echo ""
  else
    jq -r '.artifact_discarded[]? | "- **\(.id)** — \(.reason): \(.reason_detail // "no detail")"' "$STATE"
    echo ""
  fi
} > "$OUT"
