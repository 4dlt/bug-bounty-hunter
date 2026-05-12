#!/usr/bin/env bash
# G2 — Bounty hallucination canary. A single-purpose test whose only job is to
# guarantee that null precedent + non-null bounty NEVER validates, regardless of
# how convincing the Advocate's argument or the Triager's verdict looks.
# This is the root failure mode the entire patch exists to prevent.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DEBATE="$SKILL_DIR/lib/phase3-debate.sh"
GEN="$SKILL_DIR/lib/generate-report.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/findings/F-FAKE-001"

# Seed finding with full artifact set — so it wouldn't be discarded by Phase 2.9
cat > "$TMP/findings/F-FAKE-001/finding.json" <<'JSON'
{"id":"F-FAKE-001","agent":"T","class":"xss_reflected","claimed_severity":"P3"}
JSON
echo "<html></html>" > "$TMP/findings/F-FAKE-001/browser-poc.html"
echo "{}" > "$TMP/findings/F-FAKE-001/replay.har"
printf '\x89PNG\r\n\x1a\n' > "$TMP/findings/F-FAKE-001/alert-fired.png"

# Advocate sets bounty range WITHOUT a precedent_url (rule 3 violation)
cat > "$TMP/findings/F-FAKE-001/advocate-argument.json" <<'JSON'
{
  "id": "F-FAKE-001",
  "class": "xss_reflected",
  "canonical_class": "xss_reflected",
  "severity": "P3",
  "cwe": "CWE-79",
  "impact_demonstrated": "Arbitrary JavaScript execution demonstrated in target browser",
  "bounty_estimate": {"low": 5000, "high": 12000, "currency": "USD"},
  "precedent_url": null,
  "reporter_submission_draft": "# Reflected XSS on /search\n\nHigh-impact finding...",
  "artifacts_cited": ["browser-poc.html", "alert-fired.png", "replay.har"],
  "rule_compliance": {
    "rule_1_no_speculation": true,
    "rule_2_source_only_cap": "n/a",
    "rule_3_precedent_required": "I GUESSED the bounty range because it felt right",
    "rule_4_ambiguity_downgrade": "not applicable"
  }
}
JSON

# Triager says ACCEPT with high confidence — ANY reasonable triager might accept
# an XSS PoC. The orchestrator's rule-3 enforcement is what must catch this.
cat > "$TMP/findings/F-FAKE-001/triager-verdict.json" <<'JSON'
{"verdict":"ACCEPT","close_code":"ACCEPT",
 "cited_evidence":{"kind":"all_rules_verified","explanation":"artifacts support claimed impact"},
 "confidence":"high"}
JSON

cat > "$TMP/state.json" <<'JSON'
{"findings":[{"id":"F-FAKE-001","class":"xss_reflected"}]}
JSON

WORKDIR="$TMP" bash "$DEBATE"

# Assertion 1: finding is NOT validated despite ACCEPT verdict
jq -e '.validated_findings | all(.id != "F-FAKE-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-FAKE-001 must not be validated (bounty set + precedent null)"; jq . "$TMP/state.json"; exit 1; }

# Assertion 2: finding is triager_closed with ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT
jq -e '.triager_closed | any(.id == "F-FAKE-001" and .close_code == "ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-FAKE-001 should be closed as ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT"; jq '.triager_closed' "$TMP/state.json"; exit 1; }

# Assertion 3: generated report must NOT show any dollar amount in the bounty totals
# (except $0 since we have no precedent-cited findings)
cat > "$TMP/state.json" <<'JSON'
{"engagement_id":"canary","target":"test","pipeline_mode":"full_idor","account_count":2,
 "validated_findings":[],
 "triager_closed":[{"id":"F-FAKE-001","close_code":"ADVOCATE_RULE_3_VIOLATION_NO_PRECEDENT","cited_evidence":{"explanation":"bounty set but precedent null"}}],
 "artifact_discarded":[]}
JSON
WORKDIR="$TMP" bash "$GEN"

# The report should say "$0" or similar for total, never the fake $5000-$12000
R=$(cat "$TMP/report.md")
echo "$R" | grep -qE '\$5000|\$12000|5,000|12,000' \
  && { echo "FAIL: report contains the hallucinated bounty range; should show $0 / unknown"; exit 1; }

# Report should either show a "$0" total OR explicitly say "no precedent-cited findings"
echo "$R" | grep -qE '\$0|no precedent-cited|No validated findings' \
  || { echo "FAIL: report should document the zero-precedent-cited state"; cat "$TMP/report.md"; exit 1; }

echo "PASS: bounty hallucination canary — rule 3 enforced even against ACCEPT verdict"
