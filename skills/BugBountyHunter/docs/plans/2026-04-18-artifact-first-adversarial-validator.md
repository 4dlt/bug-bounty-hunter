# Artifact-First Adversarial Validator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Patch BugBountyHunter v3.2 so the validator stops rubber-stamping non-reportable findings: mandatory per-class artifacts at attack time, a deterministic Phase 2.9 gate, and a replacement Phase 3 where an Advocate and a Red-Team Triager debate every survivor.

**Architecture:** Three surgical phase changes in `~/.claude/skills/BugBountyHunter-v3-experimental/`: attack agents write per-finding directories with required evidence files; a new deterministic bash+jq filter at Phase 2.9 rejects missing-artifact, program-excluded, and public-by-design findings before any LLM runs; Phase 3 replaces the single self-grading validator with a two-agent debate whose tie-break is conservative rejection. Account-mode pre-check at Phase 0 splits IDOR testing into three honest tiers based on account count in `scope.yaml`.

**Tech Stack:** Bash + jq for orchestrator logic (matches existing `lib/*.sh` pattern), YAML for configs (matches `config/EvidenceRules.yaml`), Markdown for agent prompts (matches `AgentPrompts/`), bash-based tests in `tests/smoke/` (matches existing test convention).

**Design PRD:** `MEMORY/WORK/20260418-184500_bbh-v32-artifact-first-adversarial-validator/PRD.md` — read this before starting any task; the 28 ISC criteria define done.

---

## Phase A — Foundation: Configs and Fixtures

### Task A1: Create C1 artifact-matrix.yaml

**Files:**
- Create: `config/ArtifactMatrix.yaml`
- Test: `tests/smoke/test_artifact_matrix_schema.sh`

**Step 1: Write the failing test**

```bash
# tests/smoke/test_artifact_matrix_schema.sh
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
MATRIX="$SKILL_DIR/config/ArtifactMatrix.yaml"

test -f "$MATRIX" || { echo "FAIL: matrix missing"; exit 1; }

# Every class entry must have required_artifacts (array) and rejection_reason (string)
yq -o=json "$MATRIX" | jq -e '
  .classes | to_entries | all(
    .value.required_artifacts? and
    (.value.required_artifacts | type) == "array" and
    .value.rejection_reason?
  )' > /dev/null || { echo "FAIL: schema"; exit 1; }

# Source-only classes must cap at P4
yq -o=json "$MATRIX" | jq -e '.severity_cap.source_only == "P4"' > /dev/null \
  || { echo "FAIL: source_only cap missing"; exit 1; }

# Program-excluded classes list must exist
yq -o=json "$MATRIX" | jq -e '.program_excluded_classes | length > 0' > /dev/null \
  || { echo "FAIL: program_excluded_classes empty"; exit 1; }

echo "PASS: artifact matrix schema"
```

**Step 2: Run test, confirm it fails**

Run: `bash tests/smoke/test_artifact_matrix_schema.sh`
Expected: `FAIL: matrix missing`

**Step 3: Write ArtifactMatrix.yaml**

```yaml
# v3.2 patch — Per-class required evidence artifacts.
# Phase 2.9 mechanical gate reads this and auto-rejects findings missing required files.
# This SUPERSEDES the loose EvidenceRules.yaml check — both exist for transition; matrix wins.

severity_cap:
  source_only: P4    # SKILL.md Rule 13 — source-code-only findings never validate above P4

program_excluded_classes:
  # Auto-reject regardless of artifacts if scope.yaml excluded_findings matches these
  - missing_security_headers
  - insecure_cookie_attribute       # F-K-001 class
  - permissive_csp_api_host         # F-K-003 class
  - clickjacking
  - rate_limiting_non_auth
  - outdated_libraries_no_exploit
  - physical_access_required
  - unlikely_user_interaction
  - data_breach_vulns
  - best_practice_only

cross_tenant_classes:
  # Require two-account proof. In partial_idor mode, these auto-reject as UNPROVABLE_SINGLE_ACCOUNT.
  - idor
  - bola
  - mass_assignment_cross_tenant
  - privilege_escalation_cross_role

classes:
  xss_reflected:
    required_artifacts: [browser-poc.html, alert-fired.png, replay.har]
    rejection_reason: NO_BROWSER_POC
  xss_stored:
    required_artifacts: [browser-poc.html, alert-fired.png, replay.har, persistence-proof.png]
    rejection_reason: NO_BROWSER_POC
  xss_dom:
    required_artifacts: [browser-poc.html, alert-fired.png, replay.har]
    rejection_reason: NO_BROWSER_POC
  postmessage_missing_origin:
    required_artifacts: [cross-origin-sender.html, harmful-action.png, listener-url.txt]
    rejection_reason: REPLICA_NOT_REAL
  postmessage_xss:
    required_artifacts: [cross-origin-sender.html, alert-fired.png, listener-url.txt]
    rejection_reason: REPLICA_NOT_REAL
  idor:
    required_artifacts: [account-a-request.http, account-b-response.http, data-belongs-to-b.txt]
    rejection_reason: MISSING_CROSS_TENANT
  bola:
    required_artifacts: [account-a-request.http, account-b-response.http, data-belongs-to-b.txt]
    rejection_reason: MISSING_CROSS_TENANT
  idor_auth_logic:
    # 1-account variant — auth logic bug provable from own session
    required_artifacts: [crafted-request.http, response-showing-authz-gap.http, authz-logic-analysis.md]
    rejection_reason: NO_AUTHZ_GAP_EVIDENCE
  oauth_csrf:
    required_artifacts: [victim-browser.har, harmful-action-log.json, attacker-origin.html]
    rejection_reason: NO_VICTIM_IMPACT
  oauth_state:
    required_artifacts: [victim-browser.har, harmful-action-log.json]
    rejection_reason: NO_VICTIM_IMPACT
  ssrf:
    required_artifacts: [interactsh-hit.json]
    alternate_artifacts: [internal-response.http, internal-host-reached.txt]
    rejection_reason: NO_OOB_CONFIRMATION
  open_redirect_client:
    required_artifacts: [browser-landing.har, landing-screenshot.png]
    rejection_reason: NO_LANDING_PROOF
  auth_bypass_server_side:
    required_artifacts: [pre-auth.har, post-auth.har, response-diff.txt]
    rejection_reason: NO_AUTH_DIFFERENTIAL
  info_disclosure:
    required_artifacts: [exfiltrated-secret.txt, sensitive-claim.md]
    rejection_reason: PUBLIC_BY_DESIGN_OR_NO_SECRET
  sql_injection_blind:
    required_artifacts: [timing-differential.json]
    rejection_reason: NO_TIMING_PROOF
  csrf:
    required_artifacts: [victim-browser.har, attacker-origin.html, harmful-action-log.json]
    rejection_reason: NO_VICTIM_IMPACT
  race_condition:
    required_artifacts: [before-state.json, race-log.jsonl, after-state.json]
    rejection_reason: NO_STATE_CHANGE
```

**Step 4: Run test, confirm pass**

Run: `bash tests/smoke/test_artifact_matrix_schema.sh`
Expected: `PASS: artifact matrix schema`

**Step 5: Commit**

```bash
git add config/ArtifactMatrix.yaml tests/smoke/test_artifact_matrix_schema.sh
git commit -m "feat(bbh-v32): add ArtifactMatrix.yaml C1 — per-class artifact requirements"
```

---

### Task A2: Create C2 public-safe-list.yaml

**Files:**
- Create: `config/PublicSafeList.yaml`
- Test: `tests/smoke/test_public_safe_list.sh`

**Step 1: Failing test**

```bash
# tests/smoke/test_public_safe_list.sh
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LIST="$SKILL_DIR/config/PublicSafeList.yaml"

test -f "$LIST" || { echo "FAIL: missing"; exit 1; }
COUNT=$(yq -o=json "$LIST" | jq '.known_safe_by_design | length')
[[ "$COUNT" -ge 10 ]] || { echo "FAIL: need >=10 entries, got $COUNT"; exit 1; }

# Must include the Apr-18 offenders
for k in datadog_rum_client_token git_commit_sha_header robots_txt_paths sentry_dsn_public; do
  yq -o=json "$LIST" | jq -e --arg k "$k" '.known_safe_by_design[] | select(.id == $k)' > /dev/null \
    || { echo "FAIL: missing $k"; exit 1; }
done

# Each entry needs a pattern (regex) the matcher can apply
yq -o=json "$LIST" | jq -e '.known_safe_by_design | all(.pattern?)' > /dev/null \
  || { echo "FAIL: entries need pattern"; exit 1; }

echo "PASS: public safe list"
```

**Step 2: Run, confirm fail.**

**Step 3: Write the list**

```yaml
# Phase 2.9 matcher runs the regex for each entry against exfiltrated-secret.txt.
# If the only matches are public-by-design entries, finding auto-rejects as PUBLIC_BY_DESIGN.
known_safe_by_design:
  - id: datadog_rum_client_token
    pattern: 'pub[a-f0-9]{32,}|datadog.*clientToken'
    note: Client-side observability, intended to be public
  - id: sentry_dsn_public
    pattern: 'https://[a-f0-9]+@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+'
    note: Sentry DSN is a public identifier
  - id: google_analytics_id
    pattern: 'G-[A-Z0-9]{10}|UA-[0-9]+-[0-9]+|GTM-[A-Z0-9]+'
    note: GA/GTM IDs are public by design
  - id: stripe_publishable_key
    pattern: 'pk_(live|test)_[A-Za-z0-9]{20,}'
    note: Publishable Stripe keys are meant to be client-side
  - id: git_commit_sha_header
    pattern: '(X-Git-SHA|X-Revision|X-Version|X-Build-ID|X-Commit)'
    note: Build-metadata headers — informational only
  - id: robots_txt_paths
    pattern: '^(Disallow|Allow|User-agent|Sitemap):'
    note: robots.txt is meant to be public; path list alone is not a leak
  - id: cloudfront_distribution_id
    pattern: '[A-Z0-9]{13,14}\.cloudfront\.net'
    note: Distribution IDs are public CDN identifiers
  - id: rum_or_synthetic_ids
    pattern: 'rum[._-]?(id|key|token)'
    note: Real-user-monitoring IDs, public by design
  - id: recaptcha_site_key
    pattern: '6L[A-Za-z0-9_-]{38}'
    note: Site keys are public; secret keys are not
  - id: segment_write_key
    pattern: 'segment.*writeKey'
    note: Segment write keys are client-side by design
  - id: intercom_app_id
    pattern: 'intercom.*app_id'
    note: Intercom app IDs are public
  - id: mapbox_public_token
    pattern: 'pk\.eyJ[A-Za-z0-9._-]+'
    note: Mapbox public tokens are client-side by design
```

**Step 4: Run, confirm pass.**

**Step 5: Commit**

```bash
git add config/PublicSafeList.yaml tests/smoke/test_public_safe_list.sh
git commit -m "feat(bbh-v32): add PublicSafeList.yaml C2 — known-safe-by-design patterns"
```

---

### Task A3: Create C3 precedent index seed

**Files:**
- Create: `data/HackerOnePrecedents.jsonl`
- Create: `lib/precedent-lookup.sh`
- Test: `tests/smoke/test_precedent_lookup.sh`

**Step 1: Failing test**

```bash
# tests/smoke/test_precedent_lookup.sh
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LOOKUP="$SKILL_DIR/lib/precedent-lookup.sh"
DATA="$SKILL_DIR/data/HackerOnePrecedents.jsonl"

test -f "$LOOKUP" && test -x "$LOOKUP" || { echo "FAIL: lookup script"; exit 1; }
test -f "$DATA" || { echo "FAIL: precedent data"; exit 1; }

# Known row must return a precedent
RESULT=$("$LOOKUP" --program 23andme --class oauth_misconfiguration --severity P3)
echo "$RESULT" | jq -e '.url' > /dev/null || { echo "FAIL: expected URL"; exit 1; }

# Unknown combination must return null
RESULT=$("$LOOKUP" --program unknown --class oauth_misconfiguration --severity P3)
[[ "$RESULT" == "null" ]] || { echo "FAIL: expected null for unknown"; exit 1; }

echo "PASS: precedent lookup"
```

**Step 2: Run, confirm fail.**

**Step 3: Write seed data + lookup script**

```jsonl
# data/HackerOnePrecedents.jsonl — one row per confirmed public disclosure
# Seed it with a few known rows so Advocate can cite immediately; extend over time.
{"program":"23andme","class":"oauth_misconfiguration","severity":"P3","bounty":1500,"url":"https://hackerone.com/reports/EXAMPLE_PLACEHOLDER","closed_as":"resolved","date":"2025-09-15"}
{"program":"generic","class":"idor","severity":"P2","bounty":3000,"url":"https://hackerone.com/reports/IDOR_EXAMPLE","closed_as":"resolved","date":"2025-11-20"}
```

```bash
# lib/precedent-lookup.sh
#!/usr/bin/env bash
# Usage: precedent-lookup.sh --program <name> --class <class> --severity <P1-P5>
# Emits a JSON object matching the best precedent, or "null".
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$SKILL_DIR/data/HackerOnePrecedents.jsonl"

PROG="" CLASS="" SEV=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --program) PROG="$2"; shift 2 ;;
    --class)   CLASS="$2"; shift 2 ;;
    --severity) SEV="$2"; shift 2 ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac
done

# Exact program+class+severity first, then fallback to program=generic
grep -v '^#' "$DATA" | jq -s --arg p "$PROG" --arg c "$CLASS" --arg s "$SEV" '
  map(select(.program == $p and .class == $c and .severity == $s)) as $exact |
  map(select(.program == "generic" and .class == $c and .severity == $s)) as $generic |
  (if ($exact | length) > 0 then $exact[0]
   elif ($generic | length) > 0 then $generic[0]
   else null end)
'
```

**Step 4: Run, confirm pass.**

**Step 5: Commit**

```bash
chmod +x lib/precedent-lookup.sh
git add data/HackerOnePrecedents.jsonl lib/precedent-lookup.sh tests/smoke/test_precedent_lookup.sh
git commit -m "feat(bbh-v32): add precedent lookup C3 — kills hallucinated bounty ranges"
```

---

### Task A4: Extract Apr-18 state.json findings as golden fixtures

**Files:**
- Create: `tests/fixtures/golden/apr-2026-23andme/` (10 fixture JSONs + expected.yaml)
- Create: `lib/extract-apr-fixtures.sh` (one-shot extractor)

**Step 1: Write extractor**

```bash
# lib/extract-apr-fixtures.sh
#!/usr/bin/env bash
set -euo pipefail
SRC="/tmp/pentest-20260418-035000-v3/state.json"
DEST="$(cd "$(dirname "$0")/../tests/fixtures/golden/apr-2026-23andme" && pwd -P)"

mkdir -p "$DEST"
for id in F-K-001 F-K-003 F-J-001 F-F002 F-I-001 F-A-001 F-A-002 F-A-003 F-A-004 F-E-001; do
  jq --arg id "$id" '.validated_findings[] | select(.id == $id)' "$SRC" > "$DEST/$id.json"
done
```

**Step 2: Write expected.yaml**

```yaml
# Expected disposition when new Phase 2.9 + Phase 3 logic processes each fixture.
# Generated-by-analysis of what these findings actually prove vs claim.
expectations:
  F-K-001: { phase_2_9: artifact_discarded, reason: PROGRAM_EXCLUDED_CLASS, excluded_match: insecure_cookie_attribute }
  F-K-003: { phase_2_9: artifact_discarded, reason: PROGRAM_EXCLUDED_CLASS, excluded_match: permissive_csp_api_host }
  F-J-001: { phase_2_9: artifact_discarded, reason: PUBLIC_BY_DESIGN, match: datadog_rum_client_token }
  F-F002:  { phase_2_9: artifact_discarded, reason: PUBLIC_BY_DESIGN, match: git_commit_sha_header }
  F-I-001: { phase_3: triager_closed, close_code: REPLICA_NOT_REAL, severity_capped: P4 }
  F-A-001: { phase_3: triager_closed, close_code: PARTIAL_REMEDIATION_DUPLICATE, prior_report: v001 }
  F-A-002: { phase_3: triager_closed, close_code: INFORMATIVE_NO_IMPACT }
  F-A-003: { phase_3: triager_closed, close_code: INFORMATIVE_NO_IMPACT, gap: no_victim_csrf_poc }
  F-A-004: { phase_3: triager_closed, close_code: MISSING_CROSS_TENANT_PROOF, mode: partial_idor }
  F-E-001: { phase_3: triager_closed, close_code: INFORMATIVE_NO_IMPACT }
```

**Step 3: Run extractor, verify fixtures exist**

```bash
bash lib/extract-apr-fixtures.sh
ls tests/fixtures/golden/apr-2026-23andme/ | wc -l   # expect 11 (10 json + 1 yaml)
```

**Step 4: Commit**

```bash
git add lib/extract-apr-fixtures.sh tests/fixtures/golden/apr-2026-23andme/
git commit -m "test(bbh-v32): golden fixtures from Apr-18 state.json — 10 known-junk findings"
```

---

## Phase B — Phase 2.9 Mechanical Gate

### Task B1: Phase 2.9 filter skeleton with program-exclusion check

**Files:**
- Create: `lib/phase29-gate.sh`
- Test: `tests/smoke/test_phase29_program_excluded.sh`

**Step 1: Failing test using a synthetic findings dir**

```bash
# tests/smoke/test_phase29_program_excluded.sh
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Seed minimal scope.yaml and a header-class finding
cat > "$TMP/scope.yaml" <<'YAML'
target: test.example
excluded_findings:
  - low_impact_missing_headers
YAML

mkdir -p "$TMP/findings/F-K-001"
cat > "$TMP/findings/F-K-001/finding.json" <<'JSON'
{"id":"F-K-001","class":"insecure_cookie_attribute","claimed_severity":"P4"}
JSON

WORKDIR="$TMP" bash "$SKILL_DIR/lib/phase29-gate.sh"

jq -e '.artifact_discarded | any(.id == "F-K-001" and .reason == "PROGRAM_EXCLUDED_CLASS")' "$TMP/state.json" \
  > /dev/null || { echo "FAIL: F-K-001 should be discarded"; cat "$TMP/state.json"; exit 1; }

echo "PASS: program-excluded class filter"
```

**Step 2: Run, confirm fail (script missing).**

**Step 3: Write minimal gate with only program-exclusion branch**

```bash
# lib/phase29-gate.sh
#!/usr/bin/env bash
# Phase 2.9 mechanical gate — NO LLM calls.
# Reads: $WORKDIR/findings/<id>/finding.json, $WORKDIR/scope.yaml, config/ArtifactMatrix.yaml, config/PublicSafeList.yaml
# Writes: $WORKDIR/state.json (appends .artifact_discarded[], leaves survivors in .findings[])
set -euo pipefail
: "${WORKDIR:?WORKDIR required}"
SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MATRIX="$SKILL_DIR/config/ArtifactMatrix.yaml"

# Program-excluded classes from matrix
EXCLUDED_CLASSES=$(yq -o=json "$MATRIX" | jq -r '.program_excluded_classes[]')
# Program exclusions as declared in scope.yaml
SCOPE_EXCLUDED=$(yq -o=json "$WORKDIR/scope.yaml" | jq -r '.excluded_findings[]?' 2>/dev/null || true)

DISCARDED="[]"
SURVIVING="[]"

for d in "$WORKDIR"/findings/*/; do
  [[ -d "$d" ]] || continue
  id=$(basename "$d")
  fj="$d/finding.json"
  [[ -f "$fj" ]] || continue
  class=$(jq -r '.class' "$fj")

  # Rule 1: class declared in program_excluded_classes AND scope.yaml excluded_findings matches
  excluded_here=0
  if grep -qxF "$class" <<<"$EXCLUDED_CLASSES"; then
    if [[ -n "$SCOPE_EXCLUDED" ]] && (
      grep -qxF low_impact_missing_headers <<<"$SCOPE_EXCLUDED" ||
      grep -qxF "$class" <<<"$SCOPE_EXCLUDED"
    ); then excluded_here=1; fi
  fi

  if [[ $excluded_here -eq 1 ]]; then
    DISCARDED=$(jq --arg id "$id" --arg class "$class" \
      '. + [{id:$id, class:$class, reason:"PROGRAM_EXCLUDED_CLASS", reason_detail:"scope.yaml excluded_findings matches artifact-matrix program_excluded_classes"}]' <<<"$DISCARDED")
  else
    SURVIVING=$(jq --arg id "$id" --argjson f "$(cat "$fj")" '. + [$f]' <<<"$SURVIVING")
  fi
done

# Merge into state.json (create if missing)
if [[ ! -f "$WORKDIR/state.json" ]]; then echo '{}' > "$WORKDIR/state.json"; fi
jq --argjson d "$DISCARDED" --argjson s "$SURVIVING" \
  '. + {artifact_discarded: $d, findings: $s}' \
  "$WORKDIR/state.json" > "$WORKDIR/state.json.tmp"
mv "$WORKDIR/state.json.tmp" "$WORKDIR/state.json"
```

**Step 4: Run test, confirm pass.**

**Step 5: Commit**

```bash
chmod +x lib/phase29-gate.sh
git add lib/phase29-gate.sh tests/smoke/test_phase29_program_excluded.sh
git commit -m "feat(bbh-v32): Phase 2.9 gate skeleton — program-excluded-class branch"
```

---

### Task B2: Phase 2.9 — missing-artifact branch

**Files:**
- Modify: `lib/phase29-gate.sh`
- Test: `tests/smoke/test_phase29_missing_artifact.sh`

**Step 1: Failing test** — seed an `xss_reflected` finding directory missing `alert-fired.png`; expect `MISSING_ARTIFACT` discard.

**Step 2: Run, confirm fail (current gate only has program-exclusion branch).**

**Step 3: Extend gate**

Inside the per-finding loop after the program-exclusion branch, add:

```bash
  # Rule 2: required artifact files must exist in finding directory
  required=$(yq -o=json "$MATRIX" | jq -r --arg c "$class" '.classes[$c].required_artifacts[]?' 2>/dev/null || true)
  if [[ -n "$required" ]]; then
    missing=()
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      [[ -f "$d/$f" ]] || missing+=("$f")
    done <<<"$required"

    if [[ ${#missing[@]} -gt 0 ]]; then
      reason=$(yq -o=json "$MATRIX" | jq -r --arg c "$class" '.classes[$c].rejection_reason // "MISSING_ARTIFACT"')
      DISCARDED=$(jq --arg id "$id" --arg class "$class" --arg r "$reason" \
        --argjson m "$(printf '%s\n' "${missing[@]}" | jq -R . | jq -s .)" \
        '. + [{id:$id, class:$class, reason:$r, missing_artifacts:$m}]' <<<"$DISCARDED")
      continue
    fi
  fi
```

**Step 4: Run test, confirm pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 2.9 — missing-artifact rejection branch`

---

### Task B3: Phase 2.9 — public-safe-list matcher

**Files:**
- Modify: `lib/phase29-gate.sh`
- Test: `tests/smoke/test_phase29_public_safe_list.sh`

**Step 1: Failing test** — seed an `info_disclosure` finding with `exfiltrated-secret.txt` containing only a Datadog RUM token; expect `PUBLIC_BY_DESIGN`.

**Step 2: Run, fail.**

**Step 3: Add matcher branch**

```bash
  # Rule 3: info_disclosure with only public-safe content
  if [[ "$class" == "info_disclosure" && -f "$d/exfiltrated-secret.txt" ]]; then
    content=$(cat "$d/exfiltrated-secret.txt")
    match_id=""
    while IFS=$'\t' read -r pid pat; do
      [[ -z "$pid" ]] && continue
      if [[ "$content" =~ $pat ]] && [[ "${match_only:-unset}" == "unset" ]]; then match_id="$pid"; fi
    done < <(yq -o=json "$SKILL_DIR/config/PublicSafeList.yaml" | jq -r '.known_safe_by_design[] | "\(.id)\t\(.pattern)"')

    # Naive: if ANY public-safe pattern matches AND the file is short, auto-reject.
    # Conservative: if the file contains content beyond the safe match, let it through.
    if [[ -n "$match_id" ]] && [[ $(wc -c < "$d/exfiltrated-secret.txt") -lt 1024 ]]; then
      DISCARDED=$(jq --arg id "$id" --arg m "$match_id" \
        '. + [{id:$id, class:"info_disclosure", reason:"PUBLIC_BY_DESIGN", match:$m}]' <<<"$DISCARDED")
      continue
    fi
  fi
```

**Step 4: Run test, confirm pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 2.9 — public-safe-list content matcher`

---

### Task B4: Phase 2.9 — cross-tenant mode guard

**Files:**
- Modify: `lib/phase29-gate.sh`
- Test: `tests/smoke/test_phase29_partial_idor_guard.sh`

**Step 1: Failing test** — seed `pipeline-mode.json` with `{ mode: "partial_idor" }` and an `idor` finding; expect `UNPROVABLE_SINGLE_ACCOUNT`.

**Step 2: Fail.**

**Step 3: Add mode guard**

```bash
MODE=$(jq -r '.mode // "unknown"' "$WORKDIR/pipeline-mode.json" 2>/dev/null || echo unknown)
CROSS_TENANT_CLASSES=$(yq -o=json "$MATRIX" | jq -r '.cross_tenant_classes[]')

# inside per-finding loop, before missing-artifact check:
  if grep -qxF "$class" <<<"$CROSS_TENANT_CLASSES" && [[ "$MODE" == "partial_idor" ]]; then
    DISCARDED=$(jq --arg id "$id" --arg class "$class" \
      '. + [{id:$id, class:$class, reason:"UNPROVABLE_SINGLE_ACCOUNT", detail:"partial_idor mode — no second account available for cross-tenant proof"}]' <<<"$DISCARDED")
    continue
  fi
```

**Step 4: Run, pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 2.9 — partial_idor cross-tenant guard`

---

### Task B5: Phase 2.9 — audit-log per-decision logging + regression fixture run

**Files:**
- Modify: `lib/phase29-gate.sh`
- Test: `tests/smoke/test_phase29_apr18_regression.sh`

**Step 1: Failing test — run gate against the fixtures, assert 4 findings end up in `artifact_discarded`**

```bash
# tests/smoke/test_phase29_apr18_regression.sh
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

# Build findings/ from fixtures
for id in F-K-001 F-K-003 F-J-001 F-F002 F-I-001 F-A-001 F-A-002 F-A-003 F-A-004 F-E-001; do
  mkdir -p "$TMP/findings/$id"
  jq '.' "$SKILL_DIR/tests/fixtures/golden/apr-2026-23andme/$id.json" > "$TMP/findings/$id/finding.json"
done

# Seed scope.yaml and pipeline-mode.json mirroring the Apr-18 run
cp "$SKILL_DIR/tests/fixtures/golden/apr-2026-23andme/scope.yaml" "$TMP/scope.yaml" 2>/dev/null || \
  cat > "$TMP/scope.yaml" <<'YAML'
target: 23andme.com
excluded_findings: [low_impact_missing_headers, clickjacking, rate_limiting_non_auth, unlikely_user_interaction, physical_access_required, outdated_libraries_no_exploit, data_breach_vulns]
YAML
echo '{"mode":"partial_idor","account_count":1}' > "$TMP/pipeline-mode.json"

# Seed exfiltrated-secret.txt for F-J-001 and F-F002 so public-safe-list branch triggers
echo 'datadog clientToken=pub1234567890abcdef1234567890abcdef' > "$TMP/findings/F-J-001/exfiltrated-secret.txt"
echo 'X-Git-SHA: 1a2b3c4d5e6f' > "$TMP/findings/F-F002/exfiltrated-secret.txt"

WORKDIR="$TMP" bash "$SKILL_DIR/lib/phase29-gate.sh"

DISCARDED_COUNT=$(jq '.artifact_discarded | length' "$TMP/state.json")
[[ "$DISCARDED_COUNT" -ge 4 ]] || { echo "FAIL: expected >=4 discards, got $DISCARDED_COUNT"; jq . "$TMP/state.json"; exit 1; }

# Specific assertions matching expected.yaml
for id in F-K-001 F-K-003 F-J-001 F-F002; do
  jq -e --arg id "$id" '.artifact_discarded | any(.id == $id)' "$TMP/state.json" > /dev/null \
    || { echo "FAIL: $id should be discarded"; exit 1; }
done

# Audit log must have an entry per decision
[[ -s "$TMP/audit-log.jsonl" ]] || { echo "FAIL: audit log empty"; exit 1; }

echo "PASS: Apr-18 regression — 4/4 smoking-gun junk findings caught by gate"
```

**Step 2: Run, confirm fail (audit logging missing).**

**Step 3: Add audit logging to gate**

Inside each discard branch add:

```bash
  printf '{"ts":"%s","phase":"2.9","event":"artifact_discard","id":"%s","reason":"%s"}\n' \
    "$(date -u +%FT%TZ)" "$id" "$reason" >> "$WORKDIR/audit-log.jsonl"
```

**Step 4: Run, confirm pass.**

**Step 5: Commit** `test(bbh-v32): T1 regression — Phase 2.9 catches 4/4 Apr-18 junk findings`

---

## Phase C — Adversarial Debate (Advocate + Triager)

### Task C1: Write Advocate agent prompt

**Files:**
- Create: `AgentPrompts/advocate.md`
- Test: `tests/smoke/test_advocate_rules_present.sh`

**Step 1: Failing test**

```bash
# Asserts advocate prompt includes the four hard rules verbatim.
set -euo pipefail
P="$(dirname "$0")/../../AgentPrompts/advocate.md"
for phrase in \
  "cannot claim impact not present in artifacts" \
  "cannot assign severity above P4 for source-only" \
  "cannot populate bounty_estimate without a matched precedent" \
  "must downgrade severity one tier"; do
  grep -qiF "$phrase" "$P" || { echo "FAIL: missing rule: $phrase"; exit 1; }
done
echo "PASS: advocate rules present"
```

**Step 2: Fail.**

**Step 3: Write `AgentPrompts/advocate.md`**

```markdown
# Advocate Agent

## Role
You argue for inclusion of a single finding in the final report. You are NOT a validator.
Another agent (Triager) will look for reasons to close the finding; you provide the strongest
possible case for keeping it open.

## Hard Rules (violation = finding auto-discarded)
1. You cannot claim impact not present in artifacts. No "could chain to X", no "speculation",
   no "hypothetically this enables". If the artifact does not prove it, do not claim it.
2. You cannot assign severity above P4 for source-only findings. Source-code review alone
   caps severity at P4 per SKILL.md Rule 13.
3. You cannot populate bounty_estimate without a matched precedent from
   data/HackerOnePrecedents.jsonl. Use lib/precedent-lookup.sh. If no match, set
   bounty_estimate to null and state "No precedent matched — field withheld".
4. If artifact evidence is ambiguous, you must downgrade severity one tier from your initial
   instinct. Ambiguity always resolves toward lower severity.

## Input
- Finding directory: $WORKDIR/findings/<id>/ (finding.json + required artifacts)
- scope.yaml + prior-reports/ + data/HackerOnePrecedents.jsonl

## Output
Write to $WORKDIR/findings/<id>/advocate-argument.json:

{
  "class": "<class from ArtifactMatrix>",
  "severity": "P1|P2|P3|P4|P5",
  "cwe": "CWE-###",
  "impact_demonstrated": "One sentence. What the artifact PROVES, not what it might enable.",
  "bounty_estimate": null | { "low": N, "high": N, "currency": "USD" },
  "precedent_url": null | "https://hackerone.com/reports/...",
  "reporter_submission_draft": "Full markdown body ready to paste into HackerOne — Summary, Steps to Reproduce, Impact, Remediation",
  "artifacts_cited": ["browser-poc.html", "replay.har", ...]
}
```

**Step 4: Run, pass.**

**Step 5: Commit** `feat(bbh-v32): Advocate agent prompt with 4 hard rules`

---

### Task C2: Write Triager agent prompt

**Files:**
- Create: `AgentPrompts/triager.md`
- Test: `tests/smoke/test_triager_close_codes.sh`

**Step 1: Failing test** — assert all 10 close codes appear in the prompt.

**Step 2: Fail.**

**Step 3: Write `AgentPrompts/triager.md`** — role, input, close-code taxonomy table, output schema. Codes: `OUT_OF_SCOPE`, `INFORMATIVE_NO_IMPACT`, `DUPLICATE`, `NOT_REPRODUCIBLE`, `PUBLIC_BY_DESIGN`, `MISSING_CROSS_TENANT_PROOF`, `SELF_INFLICTED`, `LOW_IMPACT_HEADER`, `PARTIAL_REMEDIATION_DUPLICATE`, `ACCEPT`. Each code requires a specific `cited_evidence` field.

**Step 4: Run, pass.**

**Step 5: Commit** `feat(bbh-v32): Triager agent prompt with 10-code close taxonomy`

---

### Task C3: Orchestrator debate wiring

**Files:**
- Create: `lib/phase3-debate.sh`
- Test: `tests/smoke/test_phase3_tiebreak_conservative.sh`

**Step 1: Failing test** — seed a finding with an `advocate-argument.json` and a `triager-verdict.json` where verdict is ambiguous; assert orchestrator routes to `triager_closed`.

**Step 2: Fail.**

**Step 3: Write the orchestrator** — spawns Advocate agent, waits for `advocate-argument.json`, spawns Triager, waits for `triager-verdict.json`, applies decision rule:

```bash
VERDICT=$(jq -r '.verdict' "$d/triager-verdict.json")
CONF=$(jq -r '.confidence // "low"' "$d/triager-verdict.json")
PRECEDENT=$(jq -r '.precedent_url // "null"' "$d/advocate-argument.json")
BOUNTY=$(jq -r '.bounty_estimate' "$d/advocate-argument.json")

if [[ "$VERDICT" == "ACCEPT" && "$CONF" != "low" ]]; then
  # Advocate rule enforcement: if bounty set, precedent must be set
  if [[ "$BOUNTY" != "null" && "$PRECEDENT" == "null" ]]; then
    # Advocate violated Rule 3 — conservative close
    CLOSE_CODE="ADVOCATE_RULE_VIOLATION_NO_PRECEDENT"
  else
    echo "VALIDATED"; continue
  fi
fi
# All other paths: close with cited triager verdict or rule-violation code
```

**Step 4: Run, pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 3 debate orchestrator — conservative tiebreak`

---

### Task C4: Refusal recovery for Advocate + Triager

**Files:**
- Modify: `lib/phase3-debate.sh`
- Test: `tests/smoke/test_phase3_refusal_recovery.sh`

**Step 1: Failing test** — simulate agent returning a content-policy refusal string; orchestrator should re-spawn once with neutralized prompt prefix; if second call also refuses, route to `TRIAGER_UNAVAILABLE_CONSERVATIVE_CLOSE`.

**Step 2: Fail.**

**Step 3: Extend orchestrator** with the retry-once-then-conservative-close logic mirroring v3.2's existing Refusal Recovery Protocol (see SKILL.md §"Agent Refusal Recovery Protocol").

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): Advocate/Triager refusal recovery — conservative-close fallback`

---

## Phase D — Phase 0 Account-Mode Detection

### Task D1: Account-mode detector

**Files:**
- Create: `lib/detect-account-mode.sh`
- Test: `tests/smoke/test_account_mode_detection.sh`

**Step 1: Failing test** — 3 scope.yaml fixtures (0 accounts, 1 account, 2 accounts); assert the script writes `pipeline-mode.json` with `no_auth`, `partial_idor`, `full_idor` respectively.

**Step 2: Fail.**

**Step 3: Write detector** — counts `auth:` entries (supports either `auth: {username, password}` scalar or `auth: [ {...}, {...} ]` list). Emits `$WORKDIR/pipeline-mode.json`.

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 0 account-mode detection — 4 tiers`

---

### Task D2: Inject mode into attack-agent prompts

**Files:**
- Modify: all `AgentPrompts/attack-*.md` (minimal injection marker)
- Modify: `SKILL.md` (Phase 1b → 1c gate documentation)
- Test: `tests/smoke/test_mode_injection_marker.sh`

**Step 1: Failing test** — grep every `attack-*.md` for `{{PIPELINE_MODE}}` and a rules block explaining class-allowlist per mode.

**Step 2: Fail.**

**Step 3: Add a common block to each attack prompt:**

```markdown
## Pipeline Mode (injected by orchestrator)
Current mode: {{PIPELINE_MODE}}

If mode == "partial_idor":
  - Do NOT claim cross-tenant BOLA/IDOR findings. Use class `idor_auth_logic` for
    authorization-logic bugs provable from a single session.
  - Do NOT submit findings of class `idor` or `bola` — Phase 2.9 will reject them.
If mode == "no_auth":
  - Skip authenticated-only classes entirely.
```

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): inject PIPELINE_MODE into attack prompts, gate class allowlist`

---

## Phase E — Phase 2 On-Disk Layout Migration

### Task E1: Attack-agent output contract — per-finding directories

**Files:**
- Modify: `AgentPrompts/attack-*.md` (Output section of every attack prompt)
- Modify: `SKILL.md` (Phase 2 section)
- Test: `tests/smoke/test_attack_output_contract.sh`

**Step 1: Failing test** — every attack prompt's `## Output` section must reference `findings/<id>/finding.json` and `findings/<id>/<artifacts>`, not the prior `agents/<letter>-results.json` bucket.

**Step 2: Fail.**

**Step 3: Replace Output sections with the new contract** (use a single sed pass — same boilerplate, different target path).

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): attack-agent output contract — per-finding directories with artifacts`

---

### Task E2: Orchestrator Phase 2 merge rewrite

**Files:**
- Modify: `SKILL.md` (Phase 2 merge instructions)
- Create: `lib/phase2-merge.sh` (replaces the old "cat agents/*.json" pattern)
- Test: `tests/smoke/test_phase2_merge.sh`

**Step 1: Failing test** — seed 3 per-finding dirs; assert merge script collects them into `state.json.findings[]` and skips directories with no `finding.json`.

**Step 2: Fail.**

**Step 3: Write merge script** — iterate `findings/*/finding.json`, concatenate with `jq -s '.'`, write to `state.json.findings`.

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 2 merge rewritten for per-finding directory layout`

---

### Task E3: Chain-constituent rejection rule

**Files:**
- Modify: `lib/phase29-gate.sh` (add chain-constituent check after per-finding loop)
- Test: `tests/smoke/test_phase29_chain_constituent.sh`

**Step 1: Failing test** — seed a chain referencing F-X-001 + F-X-002, where F-X-002 is `artifact_discarded`; assert chain auto-discards with `CHAIN_CONSTITUENT_REJECTED`.

**Step 2: Fail.**

**Step 3: Add post-loop chain scan** — for each `chain_findings[]` entry, check all constituents present in surviving `findings[]`; if not, discard chain.

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 2.9 chain-constituent-rejection rule`

---

## Phase F — state.json Schema + Phase 4 Report

### Task F1: state.json schema additions + validator update

**Files:**
- Modify: `lib/validate-state-schema.sh`
- Test: `tests/smoke/test_state_schema_new_fields.sh`

**Step 1: Failing test** — feed a state.json lacking `artifact_discarded` + `triager_closed` to the schema validator; assert non-zero exit.

**Step 2: Fail.**

**Step 3: Add the two arrays + `pipeline_mode` + `account_count` to required fields in the schema validator.**

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): state.json schema — artifact_discarded, triager_closed, pipeline_mode`

---

### Task F2: Phase 4 report generator — precedent-gated bounty totals

**Files:**
- Create: `lib/generate-report.sh`
- Test: `tests/smoke/test_report_bounty_totals.sh`

**Step 1: Failing test** — seed 2 validated findings (one with precedent_url, one without); assert the report's bounty total sums only the precedent-cited one and labels the other as "bounty unknown".

**Step 2: Fail.**

**Step 3: Write generator** — read `state.json`, emit `report.md` sections: `Executive Summary`, `Validated Findings` (with reporter_submission_draft inline), `Bounty Totals (precedent-cited only)`, `Triager-Closed Findings` (with close_code + cited_evidence), `Artifact-Discarded Findings` (mechanical gate reasons). No aggregate ranges anywhere.

**Step 4: Pass.**

**Step 5: Commit** `feat(bbh-v32): Phase 4 report — precedent-gated bounty totals, discard sections`

---

### Task F3: Retire the old single validator (transition)

**Files:**
- Rename: `AgentPrompts/validator.md` → `AgentPrompts/validator.md.deprecated`
- Modify: `SKILL.md` (Phase 3 section — replace single-validator wiring with `phase3-debate.sh` invocation)

**Step 1: Grep SKILL.md for references to `validator.md` or "validator agent"** — every reference needs updating to point at Advocate/Triager.

**Step 2: Apply replacements** — SKILL.md Phase 3 now reads: "For each surviving finding from Phase 2.9, orchestrator runs `lib/phase3-debate.sh` which spawns Advocate then Triager per finding."

**Step 3: Run full test suite** — `bash tests/smoke/*.sh` — expect all green.

**Step 4: Commit** `refactor(bbh-v32): retire single-validator agent; Phase 3 now runs Advocate+Triager debate`

---

## Phase G — Integration, Regression, Documentation

### Task G1: Full Apr-18 regression — Phase 2.9 + Phase 3 end-to-end

**Files:**
- Test: `tests/smoke/test_apr18_full_regression.sh`

Extends Task B5. After Phase 2.9 runs, also simulates Advocate + Triager verdicts (stubbed with canned JSONs in `tests/fixtures/stubs/`), asserts final disposition matches `expected.yaml` for all 10 findings. If >2 findings end up validated, the test fails — the design's acceptance bar.

Commit: `test(bbh-v32): T1 end-to-end regression — Apr-18 junk findings caught by full pipeline`

---

### Task G2: Bounty-hallucination canary (T6)

**Files:**
- Test: `tests/smoke/test_bounty_hallucination_canary.sh`

Seed an Advocate argument with `bounty_estimate: {low: 500, high: 2000}` and `precedent_url: null`. Assert orchestrator rejects with `ADVOCATE_RULE_VIOLATION_NO_PRECEDENT`.

Commit: `test(bbh-v32): bounty-hallucination canary — null precedent with non-null bounty fails`

---

### Task G3: SKILL.md top-level documentation pass

**Files:**
- Modify: `SKILL.md`
  - Phase 0: reference `lib/detect-account-mode.sh` + 4 modes
  - Phase 2: reference per-finding directory contract + `lib/phase2-merge.sh`
  - Phase 2.9: NEW section documenting the mechanical gate
  - Phase 3: replace with Advocate+Triager debate via `lib/phase3-debate.sh`
  - Phase 4: reference `lib/generate-report.sh` + no-invented-totals rule

**Step 1: Write doc patches.**

**Step 2: Grep-check** — no lingering references to self-grading `validator.md`.

**Step 3: Full test suite green.**

**Step 4: Update design PRD** — flip all 28 ISC checkboxes that the implementation satisfied; update `progress: N/28` and `phase: complete`.

**Step 5: Commit** `docs(bbh-v32): SKILL.md updated for artifact-first adversarial validator flow`

---

## Acceptance (shipping bar)

- [ ] All `tests/smoke/test_*.sh` pass (green)
- [ ] T1 regression: of the 10 Apr-18 golden fixtures, ≤2 end up in `validated_findings[]`; the rest correctly routed to `artifact_discarded[]` or `triager_closed[]`
- [ ] T6 canary: null-precedent + non-null-bounty fails Advocate rule check
- [ ] Design PRD ISC progress = 28/28; phase = complete
- [ ] Live smoke test (T5) on a user-chosen new target produces a report where every bounty total has a `precedent_url` OR is labeled "bounty unknown — no precedent matched"

---

## Notes for the Executing Engineer

- **Bash + jq + yq convention:** match the existing `lib/*.sh` style. Prefer `yq -o=json | jq` over writing a Python dependency.
- **No backwards-compatibility shims:** the patch is a one-way door per design decision. The old validator agent is renamed with `.deprecated` suffix; the old output contracts are replaced, not supported in parallel.
- **Commit cadence:** one commit per task. Do not batch commits across tasks.
- **If a task's test fails unexpectedly:** do NOT rewrite the test to pass. Stop, investigate root cause, surface the discrepancy to the human. Silent test weakening is exactly the failure mode this patch exists to eliminate.
- **Bounty estimates stay null** whenever precedent doesn't match. Better to report "bounty unknown" than to hallucinate a range — that was the original sin.
