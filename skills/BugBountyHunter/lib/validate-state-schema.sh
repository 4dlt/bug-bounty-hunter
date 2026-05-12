#!/usr/bin/env bash
# Usage: validate-state-schema.sh <path-to-state.json>
# Exits 0 if valid, 1 if invalid. Prints the missing/wrong field on failure.

set -e
FILE="$1"
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "[ERROR] State file not found: $FILE" >&2
  exit 1
fi

# Required fields with their expected jq types
# Format: jq_path|expected_type (one per line)
REQUIRED='.auth.status|string
.auth.primary_domain|string
.auth.method|string
.auth.auth_strategy|string
.auth.jwts|object
.auth.cookies|array
.auth.refresh_endpoint|string
.auth.refresh_method|string
.auth.refresh_body_template|string
.auth.refresh_count|number
.auth.refresh_failure_count|number
.auth.access_token_lifetime_seconds|number
.auth.expires_at|string
.auth.acquired_at|string
.auth.per_domain_status|object
.auth.sso_chain|array
.auth.stale|boolean'

while IFS='|' read -r path expected_type; do
  actual_type=$(jq -r "$path | type" "$FILE" 2>/dev/null || echo "missing")
  if [ "$actual_type" != "$expected_type" ]; then
    echo "[INVALID] $path expected $expected_type, got $actual_type" >&2
    exit 1
  fi
done <<< "$REQUIRED"

# Validate status enum
status=$(jq -r '.auth.status' "$FILE")
case "$status" in
  verified|partial|stale|failed|unauthenticated) ;;
  *) echo "[INVALID] .auth.status must be one of: verified, partial, stale, failed, unauthenticated. Got: $status" >&2; exit 1 ;;
esac

# Validate auth_strategy enum — picks the refresh mechanism downstream
strategy=$(jq -r '.auth.auth_strategy' "$FILE")
case "$strategy" in
  jwt-oauth|session-cookie|static|none) ;;
  *) echo "[INVALID] .auth.auth_strategy must be one of: jwt-oauth, session-cookie, static, none. Got: $strategy" >&2; exit 1 ;;
esac

# v3.2 finding-level fields — WARN-only (backward compat with v3.1 state.json)
FINDING_COUNT=$(jq '.findings // [] | length' "$FILE" 2>/dev/null || echo 0)
if [ "$FINDING_COUNT" -gt 0 ]; then
  REQUIRED_FINDING='.validation_evidence|object
.impact_demonstrated|string
.discovery_phase|string
.discovery_round|number'

  while IFS='|' read -r path expected_type; do
    actual_type=$(jq -r ".findings[0]$path | type" "$FILE" 2>/dev/null || echo "missing")
    if [ "$actual_type" = "missing" ] || [ "$actual_type" = "null" ]; then
      echo "[WARN] .findings[0]$path missing — v3.2 schema field not populated" >&2
    elif [ "$actual_type" != "$expected_type" ]; then
      echo "[INVALID] .findings[0]$path expected $expected_type, got $actual_type" >&2
      exit 1
    fi
  done <<< "$REQUIRED_FINDING"
fi

# v3.2-patch top-level fields — REQUIRED after the artifact-first adversarial
# validator patch lands. These enable the Phase 2.9 mechanical gate + Phase 3
# debate orchestrator.
V32_REQUIRED='.artifact_discarded|array
.triager_closed|array
.pipeline_mode|string
.account_count|number'

while IFS='|' read -r path expected_type; do
  actual_type=$(jq -r "$path | type" "$FILE" 2>/dev/null || echo "missing")
  if [ "$actual_type" != "$expected_type" ]; then
    echo "[INVALID] $path expected $expected_type, got $actual_type" >&2
    exit 1
  fi
done <<< "$V32_REQUIRED"

# Validate pipeline_mode enum
mode=$(jq -r '.pipeline_mode' "$FILE")
case "$mode" in
  no_auth|partial_idor|full_idor|self_signup_promoted) ;;
  *) echo "[INVALID] .pipeline_mode must be one of: no_auth, partial_idor, full_idor, self_signup_promoted. Got: $mode" >&2; exit 1 ;;
esac

echo "[OK] $FILE matches state.auth schema + v3.2-patch fields"
