#!/usr/bin/env bash
# B1 smoke test — Phase 2.9 gate rejects program-excluded classes.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$SKILL_DIR/lib/phase29-gate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

test -x "$GATE" || { echo "FAIL: $GATE missing or not executable"; exit 1; }

# Seed workdir with a minimal scope.yaml and 3 findings:
#   F-K-001: class insecure_cookie_attribute (in program_excluded_classes) → discard
#   F-K-003: class permissive_csp_api_host  (in program_excluded_classes) → discard
#   F-X-001: class xss_reflected             (NOT excluded)                → survives
cat > "$TMP/scope.yaml" <<'YAML'
target: test.example
in_scope:
  - test.example
excluded_findings:
  - low_impact_missing_headers
  - clickjacking
YAML

mkdir -p "$TMP/findings/F-K-001" "$TMP/findings/F-K-003" "$TMP/findings/F-X-001"
echo '{"id":"F-K-001","agent":"K","class":"insecure_cookie_attribute","claimed_severity":"P4"}' > "$TMP/findings/F-K-001/finding.json"
echo '{"id":"F-K-003","agent":"K","class":"permissive_csp_api_host","claimed_severity":"P4"}' > "$TMP/findings/F-K-003/finding.json"
echo '{"id":"F-X-001","agent":"X","class":"xss_reflected","claimed_severity":"P3"}' > "$TMP/findings/F-X-001/finding.json"
# F-X-001 needs all xss_reflected required_artifacts so it survives both B1 and B2 branches;
# B1 checks program-exclusion, B2 checks missing-artifact.
echo "<html></html>" > "$TMP/findings/F-X-001/browser-poc.html"
echo "{}" > "$TMP/findings/F-X-001/replay.har"
printf '\x89PNG\r\n\x1a\n' > "$TMP/findings/F-X-001/alert-fired.png"

WORKDIR="$TMP" bash "$GATE"

# state.json must now contain artifact_discarded with both K findings
jq -e '.artifact_discarded | any(.id == "F-K-001" and .reason == "PROGRAM_EXCLUDED_CLASS")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-K-001 should be in artifact_discarded with reason PROGRAM_EXCLUDED_CLASS"; cat "$TMP/state.json"; exit 1; }

jq -e '.artifact_discarded | any(.id == "F-K-003" and .reason == "PROGRAM_EXCLUDED_CLASS")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-K-003 should be in artifact_discarded with reason PROGRAM_EXCLUDED_CLASS"; exit 1; }

# F-X-001 must NOT be discarded
jq -e '.artifact_discarded | all(.id != "F-X-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-X-001 (xss_reflected) should not be discarded at B1"; exit 1; }

# F-X-001 must be in survivors (.findings[])
jq -e '.findings | any(.id == "F-X-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-X-001 should be in .findings (survivors)"; exit 1; }

# Discard entries must carry reason_detail for auditability
jq -e '.artifact_discarded | all(.reason_detail | type == "string" and length > 0)' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: artifact_discarded entries must have reason_detail"; exit 1; }

# Counts sanity: 2 discarded + 1 surviving = 3 processed
DISCARDED=$(jq '.artifact_discarded | length' "$TMP/state.json")
SURVIVING=$(jq '.findings | length' "$TMP/state.json")
[[ "$DISCARDED" == "2" && "$SURVIVING" == "1" ]] \
  || { echo "FAIL: expected 2 discarded + 1 surviving; got $DISCARDED + $SURVIVING"; exit 1; }

# Idempotency: re-running the gate against the same workdir should produce the same result
# (not double-count, not re-process already-decided findings)
WORKDIR="$TMP" bash "$GATE"
DISCARDED2=$(jq '.artifact_discarded | length' "$TMP/state.json")
SURVIVING2=$(jq '.findings | length' "$TMP/state.json")
[[ "$DISCARDED2" == "2" && "$SURVIVING2" == "1" ]] \
  || { echo "FAIL: gate is not idempotent; second run changed counts"; exit 1; }

# Class alias resolution: a finding with class 'mass_assignment' should resolve to
# idor_auth_logic (per ArtifactMatrix.class_aliases) and NOT be excluded by B1.
# Provide required artifacts so B2 also lets it through.
mkdir -p "$TMP/findings/F-Y-001"
echo '{"id":"F-Y-001","agent":"Y","class":"mass_assignment","claimed_severity":"P3"}' > "$TMP/findings/F-Y-001/finding.json"
echo "GET /foo HTTP/1.1" > "$TMP/findings/F-Y-001/crafted-request.http"
echo "HTTP/1.1 200 OK" > "$TMP/findings/F-Y-001/response-showing-authz-gap.http"
echo "Authz gap analysis." > "$TMP/findings/F-Y-001/authz-logic-analysis.md"
WORKDIR="$TMP" bash "$GATE"
jq -e '.artifact_discarded | all(.id != "F-Y-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-Y-001 (mass_assignment → idor_auth_logic via alias) should not be excluded"; exit 1; }

echo "PASS: Phase 2.9 program-excluded-class branch + idempotency + alias resolution"
