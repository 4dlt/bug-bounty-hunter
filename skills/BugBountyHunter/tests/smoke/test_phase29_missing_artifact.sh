#!/usr/bin/env bash
# B2 smoke test — Phase 2.9 gate rejects findings missing required artifacts.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$SKILL_DIR/lib/phase29-gate.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

cat > "$TMP/scope.yaml" <<'YAML'
target: test.example
excluded_findings: []
YAML

mkdir -p "$TMP/findings"

# Case 1: xss_reflected missing alert-fired.png → MISSING_ARTIFACT with NO_BROWSER_POC
mkdir -p "$TMP/findings/F-X-001"
cat > "$TMP/findings/F-X-001/finding.json" <<'JSON'
{"id":"F-X-001","agent":"X","class":"xss_reflected","claimed_severity":"P3"}
JSON
echo "<html></html>" > "$TMP/findings/F-X-001/browser-poc.html"
echo "{}" > "$TMP/findings/F-X-001/replay.har"
# Missing: alert-fired.png

# Case 2: xss_reflected with ALL required artifacts → survives
mkdir -p "$TMP/findings/F-X-002"
cat > "$TMP/findings/F-X-002/finding.json" <<'JSON'
{"id":"F-X-002","agent":"X","class":"xss_reflected","claimed_severity":"P3"}
JSON
echo "<html></html>" > "$TMP/findings/F-X-002/browser-poc.html"
echo "{}" > "$TMP/findings/F-X-002/replay.har"
printf '\x89PNG\r\n\x1a\n' > "$TMP/findings/F-X-002/alert-fired.png"

# Case 3: ssrf with primary (interactsh-hit.json) → survives
mkdir -p "$TMP/findings/F-S-001"
cat > "$TMP/findings/F-S-001/finding.json" <<'JSON'
{"id":"F-S-001","agent":"D","class":"ssrf","claimed_severity":"P2"}
JSON
echo '{"hit":true}' > "$TMP/findings/F-S-001/interactsh-hit.json"

# Case 4: ssrf with alternate artifacts (internal-response.http + internal-host-reached.txt) → survives
mkdir -p "$TMP/findings/F-S-002"
cat > "$TMP/findings/F-S-002/finding.json" <<'JSON'
{"id":"F-S-002","agent":"D","class":"ssrf","claimed_severity":"P2"}
JSON
echo "HTTP/1.1 200 OK" > "$TMP/findings/F-S-002/internal-response.http"
echo "10.0.0.1" > "$TMP/findings/F-S-002/internal-host-reached.txt"

# Case 5: ssrf with NEITHER primary nor alternate → NO_OOB_CONFIRMATION discard
mkdir -p "$TMP/findings/F-S-003"
cat > "$TMP/findings/F-S-003/finding.json" <<'JSON'
{"id":"F-S-003","agent":"D","class":"ssrf","claimed_severity":"P2"}
JSON
# No artifact files at all

# Case 6: ssrf with PARTIAL alternate (only internal-response.http, missing internal-host-reached.txt) → discard
mkdir -p "$TMP/findings/F-S-004"
cat > "$TMP/findings/F-S-004/finding.json" <<'JSON'
{"id":"F-S-004","agent":"D","class":"ssrf","claimed_severity":"P2"}
JSON
echo "HTTP/1.1 200 OK" > "$TMP/findings/F-S-004/internal-response.http"
# Missing: interactsh-hit.json (primary) AND internal-host-reached.txt (second alt)

# Case 7: unknown class (not in matrix, not in aliases) → survives for later phases
mkdir -p "$TMP/findings/F-U-001"
cat > "$TMP/findings/F-U-001/finding.json" <<'JSON'
{"id":"F-U-001","agent":"Z","class":"wholly_novel_class","claimed_severity":"P4"}
JSON

WORKDIR="$TMP" bash "$GATE"

# F-X-001: discarded as MISSING_ARTIFACT with NO_BROWSER_POC
jq -e '.artifact_discarded[] | select(.id == "F-X-001") | .reason == "NO_BROWSER_POC" and (.missing_artifacts | index("alert-fired.png") != null)' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-X-001 should be NO_BROWSER_POC with alert-fired.png in missing_artifacts"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

# F-X-002: survives
jq -e '.findings | any(.id == "F-X-002")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-X-002 should survive (all required present)"; exit 1; }

# F-S-001: survives (primary interactsh-hit.json present)
jq -e '.findings | any(.id == "F-S-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-S-001 should survive via primary artifact"; exit 1; }

# F-S-002: survives (both alternate artifacts present)
jq -e '.findings | any(.id == "F-S-002")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-S-002 should survive via alternate artifacts"; exit 1; }

# F-S-003: discarded NO_OOB_CONFIRMATION
jq -e '.artifact_discarded[] | select(.id == "F-S-003") | .reason == "NO_OOB_CONFIRMATION"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-S-003 should be NO_OOB_CONFIRMATION"; exit 1; }

# F-S-004: discarded (partial alternate set)
jq -e '.artifact_discarded[] | select(.id == "F-S-004") | .reason == "NO_OOB_CONFIRMATION"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-S-004 should be NO_OOB_CONFIRMATION (partial alternate set)"; exit 1; }

# F-U-001: unknown class → survives (no matrix entry means no artifact requirement here)
# Phase 3 advocate/triager will handle novel classes with the NOVEL_CLASS_NEEDS_REVIEW path.
jq -e '.findings | any(.id == "F-U-001")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-U-001 (unknown class) should fall through to survivors for Phase 3"; exit 1; }

echo "PASS: Phase 2.9 missing-artifact branch + alternate_artifacts + unknown-class fallthrough"
