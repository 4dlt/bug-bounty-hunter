#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MATRIX="$SKILL_DIR/config/ArtifactMatrix.yaml"
YAML2JSON="$SKILL_DIR/lib/yaml2json.sh"

test -f "$MATRIX" || { echo "FAIL: matrix missing"; exit 1; }
test -x "$YAML2JSON" || { echo "FAIL: yaml2json shim missing/not-exec"; exit 1; }

# Every class entry must have required_artifacts (array) and rejection_reason (string)
"$YAML2JSON" < "$MATRIX" | jq -e '
  .classes | to_entries | all(
    (.value.required_artifacts | type) == "array" and
    (.value.rejection_reason | type) == "string"
  )' > /dev/null || { echo "FAIL: schema"; exit 1; }

# Every class's required_artifacts list must be non-empty
# (empty list would mean "no artifacts required" — defeats the gate)
"$YAML2JSON" < "$MATRIX" | jq -e '.classes | to_entries | all((.value.required_artifacts | length) > 0)' > /dev/null \
  || { echo "FAIL: class has empty required_artifacts"; exit 1; }

# Source-only findings capped at P4
"$YAML2JSON" < "$MATRIX" | jq -e '.severity_cap.source_only == "P4"' > /dev/null \
  || { echo "FAIL: source_only cap missing"; exit 1; }

# Program-excluded classes list non-empty
"$YAML2JSON" < "$MATRIX" | jq -e '.program_excluded_classes | length > 0' > /dev/null \
  || { echo "FAIL: program_excluded_classes empty"; exit 1; }

# Cross-tenant classes list non-empty
"$YAML2JSON" < "$MATRIX" | jq -e '.cross_tenant_classes | length > 0' > /dev/null \
  || { echo "FAIL: cross_tenant_classes empty"; exit 1; }

# Spot-check specific Apr-18 offender classes must be in program_excluded_classes
for c in insecure_cookie_attribute permissive_csp_api_host missing_security_headers; do
  "$YAML2JSON" < "$MATRIX" | jq -e --arg c "$c" '.program_excluded_classes | index($c) != null' > /dev/null \
    || { echo "FAIL: $c missing from program_excluded_classes"; exit 1; }
done

# At least one browser-required class (xss_reflected) present
"$YAML2JSON" < "$MATRIX" | jq -e '.classes.xss_reflected.required_artifacts | index("browser-poc.html") != null' > /dev/null \
  || { echo "FAIL: xss_reflected missing browser-poc.html"; exit 1; }

echo "PASS: artifact matrix schema"
