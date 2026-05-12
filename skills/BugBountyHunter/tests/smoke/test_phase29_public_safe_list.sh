#!/usr/bin/env bash
# B3 smoke test — Phase 2.9 gate auto-rejects info_disclosure findings whose
# exfiltrated-secret.txt content is entirely public-by-design.
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

# Case 1: info_disclosure with Datadog RUM token only → PUBLIC_BY_DESIGN
mkdir -p "$TMP/findings/F-J-001"
cat > "$TMP/findings/F-J-001/finding.json" <<'JSON'
{"id":"F-J-001","agent":"J","class":"info_disclosure","claimed_severity":"P4"}
JSON
echo "datadog clientToken=pub0123456789abcdef0123456789abcdef" > "$TMP/findings/F-J-001/exfiltrated-secret.txt"
echo "Client-side RUM token exposed on main JS bundle." > "$TMP/findings/F-J-001/sensitive-claim.md"

# Case 2: info_disclosure with git SHA header only → PUBLIC_BY_DESIGN
mkdir -p "$TMP/findings/F-F002"
cat > "$TMP/findings/F-F002/finding.json" <<'JSON'
{"id":"F-F002","agent":"F","class":"info_disclosure","claimed_severity":"P4"}
JSON
echo "X-Git-SHA: 1a2b3c4d5e6f7890" > "$TMP/findings/F-F002/exfiltrated-secret.txt"
echo "Git commit SHA leaks in response header." > "$TMP/findings/F-F002/sensitive-claim.md"

# Case 3: info_disclosure with robots.txt paths only → PUBLIC_BY_DESIGN
mkdir -p "$TMP/findings/F-J-002"
cat > "$TMP/findings/F-J-002/finding.json" <<'JSON'
{"id":"F-J-002","agent":"J","class":"info_disclosure","claimed_severity":"P4"}
JSON
cat > "$TMP/findings/F-J-002/exfiltrated-secret.txt" <<'EOF'
User-agent: *
Disallow: /admin
Allow: /public
Sitemap: https://test.example/sitemap.xml
EOF
echo "robots.txt path disclosure." > "$TMP/findings/F-J-002/sensitive-claim.md"

# Case 4: info_disclosure with REAL secret (AWS key) → must NOT be rejected
mkdir -p "$TMP/findings/F-J-003"
cat > "$TMP/findings/F-J-003/finding.json" <<'JSON'
{"id":"F-J-003","agent":"J","class":"info_disclosure","claimed_severity":"P2"}
JSON
echo "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > "$TMP/findings/F-J-003/exfiltrated-secret.txt"
echo "AWS secret key leaked in public JS." > "$TMP/findings/F-J-003/sensitive-claim.md"

# Case 5: info_disclosure with MIXED content (safe + real secret) in a large file → must NOT be rejected
mkdir -p "$TMP/findings/F-J-004"
cat > "$TMP/findings/F-J-004/finding.json" <<'JSON'
{"id":"F-J-004","agent":"J","class":"info_disclosure","claimed_severity":"P2"}
JSON
{
  echo "G-ABCDEFGHIJ"
  echo "aws_secret = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  # Pad to >1024 bytes
  for i in $(seq 1 50); do echo "some other config line number $i with meaningful content here padding padding"; done
} > "$TMP/findings/F-J-004/exfiltrated-secret.txt"
echo "Mixed JS bundle with GA id and AWS key." > "$TMP/findings/F-J-004/sensitive-claim.md"

# Case 6: class is sensitive_data_in_response (alias → info_disclosure), safe content → PUBLIC_BY_DESIGN
mkdir -p "$TMP/findings/F-J-005"
cat > "$TMP/findings/F-J-005/finding.json" <<'JSON'
{"id":"F-J-005","agent":"J","class":"sensitive_data_in_response","claimed_severity":"P3"}
JSON
echo "X-Build-ID: build-42" > "$TMP/findings/F-J-005/exfiltrated-secret.txt"
echo "Build ID header disclosure." > "$TMP/findings/F-J-005/sensitive-claim.md"

# Case 7: info_disclosure missing exfiltrated-secret.txt → B2 missing-artifact fires FIRST
mkdir -p "$TMP/findings/F-J-006"
cat > "$TMP/findings/F-J-006/finding.json" <<'JSON'
{"id":"F-J-006","agent":"J","class":"info_disclosure","claimed_severity":"P3"}
JSON
# Deliberately NO exfiltrated-secret.txt, NO sensitive-claim.md

WORKDIR="$TMP" bash "$GATE"

# Case 1: PUBLIC_BY_DESIGN with match=datadog_rum_client_token
jq -e '.artifact_discarded[] | select(.id == "F-J-001") | .reason == "PUBLIC_BY_DESIGN" and .match == "datadog_rum_client_token"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-001 should be PUBLIC_BY_DESIGN match=datadog_rum_client_token"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

# Case 2: PUBLIC_BY_DESIGN with match=git_commit_sha_header
jq -e '.artifact_discarded[] | select(.id == "F-F002") | .reason == "PUBLIC_BY_DESIGN" and .match == "git_commit_sha_header"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-F002 should be PUBLIC_BY_DESIGN match=git_commit_sha_header"; exit 1; }

# Case 3: PUBLIC_BY_DESIGN with match=robots_txt_paths
jq -e '.artifact_discarded[] | select(.id == "F-J-002") | .reason == "PUBLIC_BY_DESIGN" and .match == "robots_txt_paths"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-002 should be PUBLIC_BY_DESIGN match=robots_txt_paths"; exit 1; }

# Case 4: real AWS secret must survive
jq -e '.findings | any(.id == "F-J-003")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-003 (real AWS key) must not be auto-rejected"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

# Case 5: large mixed file must survive (ALL content must match safe-by-design, and it doesn't)
jq -e '.findings | any(.id == "F-J-004")' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-004 (mixed large content with real AWS key) must survive"; exit 1; }

# Case 6: alias-resolved info_disclosure also rejected when content is safe
jq -e '.artifact_discarded[] | select(.id == "F-J-005") | .reason == "PUBLIC_BY_DESIGN" and .match == "git_commit_sha_header"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-005 (sensitive_data_in_response alias) should be PUBLIC_BY_DESIGN"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

# Case 7: missing artifacts — B2 discards with PUBLIC_BY_DESIGN_OR_NO_SECRET (the class's rejection_reason)
jq -e '.artifact_discarded[] | select(.id == "F-J-006") | .reason == "PUBLIC_BY_DESIGN_OR_NO_SECRET"' "$TMP/state.json" > /dev/null \
  || { echo "FAIL: F-J-006 should be rejected by B2 missing-artifact branch"; jq '.artifact_discarded' "$TMP/state.json"; exit 1; }

echo "PASS: Phase 2.9 public-safe-list matcher + alias resolution + real-secret preservation"
