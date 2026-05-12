#!/usr/bin/env bash
# D1 smoke test — Phase 0 account-mode detector
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DET="$SKILL_DIR/lib/detect-account-mode.sh"

test -x "$DET" || { echo "FAIL: $DET missing or not executable"; exit 1; }

mk_workdir() {
  local dir=$(mktemp -d)
  echo "$dir"
}

# Case 1: 0 accounts (no auth section) → no_auth
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
in_scope: [test.example]
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode == "no_auth" and .account_count == 0' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: 0 accounts should be no_auth"; jq . "$W/pipeline-mode.json"; exit 1; }
rm -rf "$W"

# Case 2: 1 account scalar form → partial_idor
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
auth:
  username: user1
  password: pass1
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode == "partial_idor" and .account_count == 1' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: 1 scalar account should be partial_idor"; jq . "$W/pipeline-mode.json"; exit 1; }
rm -rf "$W"

# Case 3: 2 accounts list form → full_idor
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
auth:
  - username: user1
    password: pass1
  - username: user2
    password: pass2
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode == "full_idor" and .account_count == 2' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: 2 list accounts should be full_idor"; jq . "$W/pipeline-mode.json"; exit 1; }
rm -rf "$W"

# Case 4: 3+ accounts → full_idor
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
auth:
  - username: u1
    password: p1
  - username: u2
    password: p2
  - username: u3
    password: p3
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode == "full_idor" and .account_count == 3' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: 3 accounts should be full_idor"; jq . "$W/pipeline-mode.json"; exit 1; }
rm -rf "$W"

# Case 5: 1 account + self_signup_allowed flag → self_signup_promoted
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
auth:
  username: user1
  password: pass1
self_signup_allowed: true
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode == "self_signup_promoted"' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: self_signup_allowed + 1 account should be self_signup_promoted"; jq . "$W/pipeline-mode.json"; exit 1; }
rm -rf "$W"

# Case 6: Missing scope.yaml → error
W=$(mk_workdir)
if WORKDIR="$W" bash "$DET" 2>/dev/null; then
  echo "FAIL: missing scope.yaml should error"; exit 1
fi
rm -rf "$W"

# Case 7: Output pipeline-mode.json has expected schema fields
W=$(mk_workdir)
cat > "$W/scope.yaml" <<'YAML'
target: test.example
auth: {username: u, password: p}
YAML
WORKDIR="$W" bash "$DET"
jq -e '.mode and (.account_count | type == "number") and .scope_yaml_fingerprint' "$W/pipeline-mode.json" > /dev/null \
  || { echo "FAIL: pipeline-mode.json missing required fields"; exit 1; }
rm -rf "$W"

echo "PASS: account-mode detection — 4 tiers + schema + error handling"
