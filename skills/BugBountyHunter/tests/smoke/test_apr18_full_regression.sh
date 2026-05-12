#!/usr/bin/env bash
# G1 — Full Apr-18 end-to-end regression.
# Runs Phase 2.9 against the golden fixtures, then for each surviving finding
# seeds a realistic Advocate + Triager verdict (as the real agents would produce),
# runs Phase 3 debate, and asserts the final counts match the acceptance bar:
#   - >=4 findings discarded at Phase 2.9 (mechanical)
#   - <=2 findings survive to validated_findings[] after debate
#
# Stubs follow the expected.yaml dispositions so this test proves the full
# pipeline produces the designed outcome — NOT that the real LLM agents do.
# The LLM agent behavior is tested separately in live smoke runs (T5 in plan).
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$SKILL_DIR/lib/phase29-gate.sh"
DEBATE="$SKILL_DIR/lib/phase3-debate.sh"
FIXDIR="$SKILL_DIR/tests/fixtures/golden/apr-2026-23andme"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Seed workdir from fixtures
mkdir -p "$TMP/findings"
for fix in "$FIXDIR"/F-*.json; do
  id=$(jq -r '.id' "$fix")
  mkdir -p "$TMP/findings/$id"
  cp "$fix" "$TMP/findings/$id/finding.json"
done
cp "$FIXDIR/scope.yaml" "$TMP/scope.yaml"
echo '{"mode":"partial_idor","account_count":1}' > "$TMP/pipeline-mode.json"
echo "datadog clientToken=pub0123456789abcdef0123456789abcdef" > "$TMP/findings/F-J-001/exfiltrated-secret.txt"
echo "n" > "$TMP/findings/F-J-001/sensitive-claim.md"

# Phase 2.9
WORKDIR="$TMP" bash "$GATE"

# Survivors from Phase 2.9 (these will go through Phase 3)
SURVIVORS=$(jq -r '.findings[]?.id' "$TMP/state.json" | sort)
echo "Phase 2.9 survivors: $(echo "$SURVIVORS" | tr '\n' ' ')"

# Seed stub Advocate + Triager outputs for each survivor.
# Dispositions per expected.yaml (mostly INFORMATIVE_NO_IMPACT or PARTIAL_REMEDIATION_DUPLICATE).
make_adv_decline() {
  local id="$1" class="$2" severity="$3"
  cat > "$TMP/findings/$id/advocate-argument.json" <<JSON
{"id":"$id","class":"$class","canonical_class":"$class","severity":"$severity",
 "impact_demonstrated":"evidence set is limited; advocate declines to overclaim",
 "bounty_estimate":null,
 "precedent_url":null,
 "reporter_submission_draft":"# $id — informational\n\nArtifacts are limited; no demonstrated impact beyond description.",
 "artifacts_cited":[],
 "rule_compliance":{"rule_1_no_speculation":true,"rule_2_source_only_cap":"n/a","rule_3_precedent_required":"null precedent","rule_4_ambiguity_downgrade":"applied"}}
JSON
}

make_tri_close() {
  local id="$1" close_code="$2" explanation="$3"
  cat > "$TMP/findings/$id/triager-verdict.json" <<JSON
{"verdict":"$close_code","close_code":"$close_code",
 "cited_evidence":{"kind":"closed_per_taxonomy","explanation":"$explanation"},
 "confidence":"high"}
JSON
}

# Stubbed dispositions — mirror expected.yaml for each survivor
if echo "$SURVIVORS" | grep -q F-I-001; then
  make_adv_decline F-I-001 postmessage_missing_origin_validation P4
  make_tri_close F-I-001 INFORMATIVE_NO_IMPACT "Source-code review + handler replicas do not prove impact on real listeners"
fi
if echo "$SURVIVORS" | grep -q F-A-001; then
  make_adv_decline F-A-001 oauth_misconfiguration P4
  make_tri_close F-A-001 PARTIAL_REMEDIATION_DUPLICATE "Retest of v001 chain; residual issue already on the existing ticket"
fi
if echo "$SURVIVORS" | grep -q F-A-002; then
  make_adv_decline F-A-002 oauth_misconfiguration P4
  make_tri_close F-A-002 INFORMATIVE_NO_IMPACT "PKCE best-practice gap without demonstrated exploit"
fi
if echo "$SURVIVORS" | grep -q F-A-003; then
  make_adv_decline F-A-003 oauth_misconfiguration P4
  make_tri_close F-A-003 INFORMATIVE_NO_IMPACT "State echo alone is not CSRF; no victim-side PoC demonstrating harmful action"
fi
if echo "$SURVIVORS" | grep -q F-F002; then
  make_adv_decline F-F002 security_misconfiguration P5
  make_tri_close F-F002 PUBLIC_BY_DESIGN "Git SHA in X-Git-SHA header is build-metadata; see PublicSafeList.yaml git_commit_sha_header"
fi
if echo "$SURVIVORS" | grep -q F-E-001; then
  make_adv_decline F-E-001 workflow_info_disclosure P5
  make_tri_close F-E-001 INFORMATIVE_NO_IMPACT "500/200 differential oracle on state-changing endpoints without extracted secret is informational"
fi

# Phase 3 debate
WORKDIR="$TMP" bash "$DEBATE"

# Assertions
VALIDATED_COUNT=$(jq '.validated_findings | length' "$TMP/state.json")
DISCARDED_COUNT=$(jq '.artifact_discarded | length' "$TMP/state.json")
CLOSED_COUNT=$(jq '.triager_closed | length' "$TMP/state.json")

echo "Counts: validated=$VALIDATED_COUNT, discarded=$DISCARDED_COUNT, closed=$CLOSED_COUNT"

[[ "$DISCARDED_COUNT" -ge 4 ]] \
  || { echo "FAIL: Phase 2.9 must discard >=4 findings; got $DISCARDED_COUNT"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

[[ "$VALIDATED_COUNT" -le 2 ]] \
  || { echo "FAIL: <=2 validated findings after full pipeline; got $VALIDATED_COUNT"; jq '.validated_findings' "$TMP/state.json"; exit 1; }

# No validated finding may have non-null bounty_estimate AND null precedent_url
NO_FAKE_BOUNTY=$(jq '[.validated_findings[] | select(.bounty_estimate != null and .precedent_url == null)] | length' "$TMP/state.json")
[[ "$NO_FAKE_BOUNTY" == "0" ]] \
  || { echo "FAIL: $NO_FAKE_BOUNTY validated findings have bounty without precedent — hallucination"; exit 1; }

# Full count sanity: 10 input → discarded + closed + validated = 10
TOTAL=$((DISCARDED_COUNT + CLOSED_COUNT + VALIDATED_COUNT))
[[ "$TOTAL" == "10" ]] \
  || { echo "FAIL: 10 input findings should be accounted for; got $TOTAL ($DISCARDED_COUNT + $CLOSED_COUNT + $VALIDATED_COUNT)"; exit 1; }

echo "PASS: G1 end-to-end regression — >=4 mechanical discards + 0-2 validated + 0 hallucinated bounties"
