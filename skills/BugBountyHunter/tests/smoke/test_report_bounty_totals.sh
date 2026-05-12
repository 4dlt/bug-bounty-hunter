#!/usr/bin/env bash
# F2 smoke test — Phase 4 report generator only sums bounties for findings
# with a precedent_url; no-precedent findings are labeled "bounty unknown".
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GEN="$SKILL_DIR/lib/generate-report.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

test -x "$GEN" || { echo "FAIL: $GEN not executable"; exit 1; }

# Seed state.json with 2 validated findings:
#  - F-1 has precedent_url + bounty_estimate → included in total
#  - F-2 has bounty_estimate but precedent_url null → shown as "bounty unknown"
cat > "$TMP/state.json" <<'JSON'
{
  "engagement_id": "pentest-TEST",
  "target": "test.example",
  "pipeline_mode": "partial_idor",
  "account_count": 1,
  "validated_findings": [
    {
      "id": "F-1",
      "class": "xss_reflected",
      "severity": "P3",
      "impact_demonstrated": "Arbitrary JS executed in victim browser",
      "bounty_estimate": {"low": 800, "high": 1500, "currency": "USD"},
      "precedent_url": "https://hackerone.com/reports/XSS_EXAMPLE",
      "reporter_submission_draft": "# XSS on /search\n\n..."
    },
    {
      "id": "F-2",
      "class": "csrf",
      "severity": "P3",
      "impact_demonstrated": "Forced state change via victim-origin form",
      "bounty_estimate": null,
      "precedent_url": null,
      "reporter_submission_draft": "# CSRF on /settings\n\n..."
    }
  ],
  "triager_closed": [
    {"id": "F-3", "close_code": "INFORMATIVE_NO_IMPACT", "cited_evidence": {"explanation": "speculation only"}}
  ],
  "artifact_discarded": [
    {"id": "F-4", "class": "insecure_cookie_attribute", "reason": "PROGRAM_EXCLUDED_CLASS", "reason_detail": "cookie Secure flag excluded by program"}
  ]
}
JSON

WORKDIR="$TMP" bash "$GEN"

test -f "$TMP/report.md" || { echo "FAIL: report.md not written"; exit 1; }

R=$(cat "$TMP/report.md")

# Report must include the validated finding id and reporter_submission_draft
echo "$R" | grep -qF "F-1" || { echo "FAIL: report missing F-1"; exit 1; }
echo "$R" | grep -qF "F-2" || { echo "FAIL: report missing F-2"; exit 1; }

# Bounty total: only F-1 contributes. Total range = $800-$1500, labeled "precedent-cited only"
echo "$R" | grep -qE 'precedent[- ]cited|Bounty Totals' \
  || { echo "FAIL: report missing precedent-cited bounty total section"; exit 1; }
echo "$R" | grep -qF '800' && echo "$R" | grep -qF '1500' \
  || { echo "FAIL: report must include F-1 bounty numbers (800, 1500)"; exit 1; }

# F-2 must be labeled as "bounty unknown" (no precedent)
echo "$R" | grep -qiF 'bounty unknown' || echo "$R" | grep -qiF 'no precedent' \
  || { echo "FAIL: report must label F-2 as bounty unknown (no precedent)"; exit 1; }

# Report must have a Triager-Closed section with F-3
echo "$R" | grep -qF "F-3" || { echo "FAIL: report missing F-3 (triager closed)"; exit 1; }
echo "$R" | grep -qiF 'triager' || echo "$R" | grep -qiF 'closed' \
  || { echo "FAIL: report missing Triager-Closed section"; exit 1; }

# Report must have an Artifact-Discarded section with F-4
echo "$R" | grep -qF "F-4" || { echo "FAIL: report missing F-4 (artifact discarded)"; exit 1; }
echo "$R" | grep -qiF 'artifact' || echo "$R" | grep -qiF 'discarded' \
  || { echo "FAIL: report missing Artifact-Discarded section"; exit 1; }

# No invented aggregate range: if only F-1 has precedent, total is just F-1's range,
# NOT some fabricated upper bound combining F-1 and F-2.
if echo "$R" | grep -qE '\$[0-9]+,?[0-9]+\s*-\s*\$?[23][0-9]{3}'; then
  # Check the total line specifically; it should cap at F-1's high (1500), not higher
  TOTAL_LINE=$(echo "$R" | grep -E 'precedent.*cited|Total' | head -1 || true)
  if [[ -n "$TOTAL_LINE" ]]; then
    # extract any 4+ digit number; max should be 1500
    MAX=$(echo "$TOTAL_LINE" | grep -oE '[0-9]+' | sort -n | tail -1)
    [[ "$MAX" -le 1500 ]] || { echo "FAIL: bounty total $MAX exceeds F-1's high (1500) — hallucination check"; exit 1; }
  fi
fi

echo "PASS: Phase 4 report — precedent-gated bounty totals, discard sections"
