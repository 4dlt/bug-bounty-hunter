#!/usr/bin/env bash
# B4 smoke test — Phase 2.9 gate rejects cross-tenant claims in partial_idor mode.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="$SKILL_DIR/lib/phase29-gate.sh"

# Case 1: partial_idor mode + class idor → UNPROVABLE_SINGLE_ACCOUNT
TMP1=$(mktemp -d); trap 'rm -rf "$TMP1" "$TMP2" "$TMP3"' EXIT
echo '{"mode":"partial_idor","account_count":1}' > "$TMP1/pipeline-mode.json"
mkdir -p "$TMP1/findings/F-B-001"
cat > "$TMP1/findings/F-B-001/finding.json" <<'JSON'
{"id":"F-B-001","agent":"B","class":"idor","claimed_severity":"P3"}
JSON
# Even if artifacts are present, partial_idor should block cross-tenant claim
echo "GET /users/1 HTTP/1.1" > "$TMP1/findings/F-B-001/account-a-request.http"
echo "HTTP/1.1 200 OK" > "$TMP1/findings/F-B-001/account-b-response.http"
echo "data" > "$TMP1/findings/F-B-001/data-belongs-to-b.txt"
WORKDIR="$TMP1" bash "$GATE"
jq -e '.artifact_discarded[] | select(.id == "F-B-001") | .reason == "UNPROVABLE_SINGLE_ACCOUNT"' "$TMP1/state.json" > /dev/null \
  || { echo "FAIL: F-B-001 (idor in partial_idor) should be UNPROVABLE_SINGLE_ACCOUNT"; jq '.artifact_discarded' "$TMP1/state.json"; exit 1; }

# Case 2: full_idor mode + class idor with all required artifacts → survives
TMP2=$(mktemp -d)
echo '{"mode":"full_idor","account_count":2}' > "$TMP2/pipeline-mode.json"
mkdir -p "$TMP2/findings/F-B-002"
cat > "$TMP2/findings/F-B-002/finding.json" <<'JSON'
{"id":"F-B-002","agent":"B","class":"idor","claimed_severity":"P2"}
JSON
echo "GET /users/1" > "$TMP2/findings/F-B-002/account-a-request.http"
echo "200 OK" > "$TMP2/findings/F-B-002/account-b-response.http"
echo "data" > "$TMP2/findings/F-B-002/data-belongs-to-b.txt"
WORKDIR="$TMP2" bash "$GATE"
jq -e '.findings | any(.id == "F-B-002")' "$TMP2/state.json" > /dev/null \
  || { echo "FAIL: F-B-002 (idor in full_idor) should survive"; exit 1; }

# Case 3: partial_idor + class idor_auth_logic (NOT a cross_tenant class) → survives with artifacts
TMP3=$(mktemp -d)
echo '{"mode":"partial_idor","account_count":1}' > "$TMP3/pipeline-mode.json"
mkdir -p "$TMP3/findings/F-B-003"
cat > "$TMP3/findings/F-B-003/finding.json" <<'JSON'
{"id":"F-B-003","agent":"B","class":"idor_auth_logic","claimed_severity":"P3"}
JSON
echo "GET /foo" > "$TMP3/findings/F-B-003/crafted-request.http"
echo "200 OK" > "$TMP3/findings/F-B-003/response-showing-authz-gap.http"
echo "analysis" > "$TMP3/findings/F-B-003/authz-logic-analysis.md"
WORKDIR="$TMP3" bash "$GATE"
jq -e '.findings | any(.id == "F-B-003")' "$TMP3/state.json" > /dev/null \
  || { echo "FAIL: F-B-003 (idor_auth_logic in partial_idor) should survive"; exit 1; }

# Case 4: bola class in partial_idor mode → UNPROVABLE_SINGLE_ACCOUNT
mkdir -p "$TMP1/findings/F-B-004"
cat > "$TMP1/findings/F-B-004/finding.json" <<'JSON'
{"id":"F-B-004","agent":"B","class":"bola","claimed_severity":"P3"}
JSON
echo "req" > "$TMP1/findings/F-B-004/account-a-request.http"
echo "resp" > "$TMP1/findings/F-B-004/account-b-response.http"
echo "data" > "$TMP1/findings/F-B-004/data-belongs-to-b.txt"
WORKDIR="$TMP1" bash "$GATE"
jq -e '.artifact_discarded[] | select(.id == "F-B-004") | .reason == "UNPROVABLE_SINGLE_ACCOUNT"' "$TMP1/state.json" > /dev/null \
  || { echo "FAIL: F-B-004 (bola in partial_idor) should be UNPROVABLE_SINGLE_ACCOUNT"; exit 1; }

# Case 5: no pipeline-mode.json → treat as full_idor (backward-compat); idor with artifacts survives
TMP4=$(mktemp -d)
trap 'rm -rf "$TMP1" "$TMP2" "$TMP3" "$TMP4"' EXIT
mkdir -p "$TMP4/findings/F-B-005"
cat > "$TMP4/findings/F-B-005/finding.json" <<'JSON'
{"id":"F-B-005","agent":"B","class":"idor","claimed_severity":"P2"}
JSON
echo "req" > "$TMP4/findings/F-B-005/account-a-request.http"
echo "resp" > "$TMP4/findings/F-B-005/account-b-response.http"
echo "data" > "$TMP4/findings/F-B-005/data-belongs-to-b.txt"
WORKDIR="$TMP4" bash "$GATE"
jq -e '.findings | any(.id == "F-B-005")' "$TMP4/state.json" > /dev/null \
  || { echo "FAIL: F-B-005 (idor, no mode file = default to permissive) should survive"; jq '.artifact_discarded' "$TMP4/state.json"; exit 1; }

echo "PASS: Phase 2.9 partial_idor cross-tenant guard"
