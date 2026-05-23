# BugBountyHunter v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build BugBountyHunter v4 — a KB-driven, coverage-enforced pentest orchestrator with adversarial validation — to the point where end-to-end engagements run against seed playbooks (XSS + IDOR) and the bounty-hallucination canary still fires.

**Architecture:** vuln_db-style KB at `~/Documents/BugBountyKB/` (markdown, git-versioned, doctrine + Coverage Checklists in YAML) consumed by a Claude Code skill at `~/.claude/skills/BugBountyHunter-v4/` (TypeScript orchestrator + per-class attack executors). Sonnet 4.6 for high-throughput attack/recon, Opus 4.7 for orchestration/validation/curation. Adversarial Advocate↔Triager debate carried forward from v3.

**Tech Stack:** Bun (TypeScript runtime), bash (mechanical gates/utilities), Python 3 + PyYAML + jsonschema (validators), Claude Code Agent tool, git (KB versioning).

**Spec:** `docs/superpowers/specs/2026-05-21-bug-bounty-v4-design.md` (commit `bc494f6`).

**Out of scope for Plan A:** KB content authoring for the 16 attack classes beyond XSS + IDOR (tracked separately as Plan B authoring sprint). Vault, dashboard, Burp bridge, mobile/cloud/network (deferred per spec Section 11).

---

## File Structure

### KB repo — `~/Documents/BugBountyKB/`

| Path | Responsibility | Status at end of Plan A |
|------|----------------|--------------------------|
| `README.md` | Route map; minimal agent context packet | Authored |
| `VERSION` | Semver for KB↔skill compat check | Authored (`0.1.0`) |
| `.gitignore` | Ignore OS junk + 99-Inbox/draft-* | Authored |
| `agents/agent-operating-manual.md` | Class-agnostic doctrine | Authored |
| `playbooks/xss.md` | Seed playbook with full Coverage Checklist | Authored |
| `playbooks/idor.md` | Seed playbook with full Coverage Checklist | Authored |
| `payloads/.gitkeep` | Plan B fills | Empty |
| `checklists/target-intake.md` | Authorization, scope, accounts | Authored |
| `checklists/evidence-quality.md` | Proof gate | Authored |
| `checklists/non-dos-filter.md` | Decide what belongs | Authored |
| `checklists/reportability.md` | 4-question test | Authored |
| `checklists/scope-sweep.md` | Variant sweep | Authored |
| `taxonomy/owasp-class-catalog.md` | Class enumeration + T-ID prefix | Authored |
| `templates/finding-report.md` | HackerOne-style report | Authored |
| `templates/security-assessment-report.md` | Full engagement report | Authored |
| `templates/novelty-proposal-stub.md` | Curator DEFER stub | Authored |
| `workflows/end-to-end-pentest.md` | Default assessment loop | Authored |
| `references/hackerone-precedents.jsonl` | Carry from v3 | Copied |
| `references/cve-research-anchors.md` | Stub at v1 | Authored |
| `maintenance/curation-rules.md` | Curator doctrine | Authored |
| `evals/fixtures/.gitkeep` | Plan B / v4.1 | Empty |
| `99-Inbox/.gitkeep` | Curator DEFER drop | Empty |

### Skill repo — `~/.claude/skills/BugBountyHunter-v4/`

| Path | Responsibility | Status |
|------|----------------|--------|
| `SKILL.md` | Orchestrator entrypoint, 8-phase pipeline | Authored |
| `package.json` / `tsconfig.json` / `.gitignore` | Bun project | Authored |
| `Agents/AppReviewAgent.md` | Pre-attack profiling (Opus) | Authored |
| `Agents/XSSAgent.md` | Canonical attack executor (Sonnet) | Authored |
| `Agents/IDORAgent.md` | Second canonical (Sonnet) | Authored |
| `Agents/Advocate.md` / `Triager.md` | Adversarial debate (Opus) | Ported from v3 |
| `Agents/Curator.md` | KB merge maintainer (Opus) | Authored |
| `Agents/recon-r1-assets.md` ... `r4-js-analysis.md` | Active recon | Ported + r3 modified |
| `Agents/auth-acquire.md` | Auth acquisition | Ported from v3 |
| `lib/orchestrator.ts` | TS state machine, `--resume`, `--status` | Authored |
| `lib/validate-playbook.sh` | YAML Coverage Checklist validator | Authored |
| `lib/reconcile-coverage.sh` | Phase 2.5 gap detection + follow-up | Authored |
| `lib/curator-batch.sh` | Phase 3.5 proposal batching | Authored |
| `lib/phase29-gate.sh` / `phase3-debate.sh` / `phase2-merge.sh` | v3 gates | Ported |
| `lib/refresh-monitor.sh` / `session-warmer.sh` / `stale-watcher.sh` | Auth keepalive | Ported |
| `lib/validate-state-schema.sh` / `yaml2json.sh` / `precedent-lookup.sh` | Utilities | Ported |
| `lib/generate-report.sh` | Report generator | Ported + modified |
| `lib/detect-account-mode.sh` | Pipeline mode | Ported |
| `config/ArtifactMatrix.yaml` / `PublicSafeList.yaml` | Enforcement config | Ported |
| `config/finding-schema.json` | Executor wire contract | Authored |
| `Workflows/W_HUNT_WEB.md` | Default workflow at v1 | Authored |
| `tests/smoke/*.sh` + `tests/fixtures/*.json` | v3 ports + new v4 tests | Ported + extended |

---

## Phase 1 — Foundation

Build the KB skeleton, the wire contract (`finding-schema.json`), the YAML validator (`validate-playbook.sh`), and 2 seed playbooks. Nothing engagement-runnable yet — but `validate-playbook.sh` passing against the seed playbooks proves the contract holds.

### Task 1.1: Scaffold KB repository

**Files:**
- Create: `~/Documents/BugBountyKB/` (directory tree)
- Create: `~/Documents/BugBountyKB/.gitignore`
- Create: `~/Documents/BugBountyKB/VERSION`
- Create: `~/Documents/BugBountyKB/{99-Inbox,payloads,evals/fixtures}/.gitkeep`

- [ ] **Step 1: Create directory tree**

```bash
mkdir -p ~/Documents/BugBountyKB/{agents,playbooks,payloads,checklists,taxonomy,templates,workflows,references,maintenance,evals/fixtures,99-Inbox}
```

- [ ] **Step 2: Initialize git**

```bash
cd ~/Documents/BugBountyKB && git init && git config user.email "alvaroxlllx@gmail.com" && git config user.name "Álvaro de la Torre"
```

- [ ] **Step 3: Write `.gitignore`**

Write the following to `~/Documents/BugBountyKB/.gitignore`:

```
.DS_Store
*.swp
*.swo
.obsidian/workspace*
.obsidian/cache
99-Inbox/draft-*
.scratch/
```

- [ ] **Step 4: Write `VERSION`**

Write the following to `~/Documents/BugBountyKB/VERSION`:

```
0.1.0
```

- [ ] **Step 5: Add empty-dir markers**

```bash
cd ~/Documents/BugBountyKB && touch 99-Inbox/.gitkeep payloads/.gitkeep evals/fixtures/.gitkeep
```

- [ ] **Step 6: Initial commit**

```bash
cd ~/Documents/BugBountyKB && git add -A && git commit -m "chore: scaffold KB structure"
```

Expected: 4 files staged, 1 commit on master.

---

### Task 1.2: Write `agent-operating-manual.md`

**Files:**
- Create: `~/Documents/BugBountyKB/agents/agent-operating-manual.md`

- [ ] **Step 1: Author the operating manual**

Write to `~/Documents/BugBountyKB/agents/agent-operating-manual.md`:

```markdown
# Agent Operating Manual

Class-agnostic doctrine for every BugBountyHunter v4 agent. Load this
FIRST on every dispatch — it defines confidence levels, evidence
discipline, the 4-question reportability test, the non-DoS filter, and
the wire-contract semantics that `config/finding-schema.json` enforces.

## Mission

Act as a careful security researcher for an authorized target. Discover
non-DoS vulnerabilities, prove exploitability safely, document evidence
to the standard the Triager will close on, and avoid overstating weak
hypotheses.

## Non-Negotiable Rules

1. Establish authorization and scope before testing. `scope.yaml` is the
   source of truth. Out-of-scope = hard block.
2. Validate before reporting. Every finding must be reproducible via a
   curl command or dev-browser script. No theoretical findings.
3. Severity comes from DEMONSTRATED impact, not vulnerability class.
4. Cross-reference every finding against the program's non-qualifying
   list (`scope.yaml.excluded_findings` plus universal exclusions in
   `config/ArtifactMatrix.yaml`).
5. Never revoke, delete, or destroy shared auth state. Create a
   temporary token if you need to test revocation.
6. Browser-execution proof required for client-side findings (XSS, DOM
   injection, open redirect, postMessage, prototype pollution). An API
   response proving payload storage is NOT proof of exploitation.

## Confidence Levels

Every finding emitted MUST carry one of these:

- **Confirmed** — deterministic reproduction demonstrates security impact.
- **Likely** — reachable path and vulnerable primitive proven; final
  impact depends on environment-specific data or configuration.
- **Hypothesis** — suspicious pattern exists; exploitability not proven.
- **Rejected** — not reachable, protected by an effective control, or
  only pure DoS.

The Phase 2.9 mechanical gate auto-rejects `Hypothesis` findings from
the `validated_findings` stream.

## The Reportability Test

All four MUST pass before marking a finding `validated`:

1. **Browser-verified?** Triggered in a real browser via dev-browser?
   If no → UNVERIFIED.
2. **In program's non-qualifying list?** If yes → NOT REPORTABLE.
3. **PoC demonstrates actual impact?** Data theft, action on behalf of
   user, privilege escalation — not just reflection/storage. If no →
   INFORMATIONAL.
4. **Skilled-hunter test?** Would someone with 100+ accepted reports
   submit this to THIS program? If no → don't report.

## Non-DoS Filter

Pure availability-only DoS is out of scope unless it enables
confidentiality, integrity, authentication, authorization, code
execution, tenant isolation, or supply-chain compromise.

## Output Discipline (wire contract)

Every agent ends its response with a single fenced JSON block matching
`config/finding-schema.json` containing:

- `coverage[]` — per-technique attempt records
- `findings[]` — confirmed/likely findings
- `proposed_additions[]` — novel techniques attempted outside the
  Coverage Checklist

Missing fields → orchestrator treats the run as incomplete and retries.

## Source-Only Findings Capped at P4

Findings limited to source-code review / AST analysis / handler-replica
testing are capped at P4 regardless of theoretical impact. Browser-
verified execution, real-endpoint exploitation, or cross-tenant
demonstration unlock P3+.

## Bounty Estimation

Do NOT estimate bounties. The Advocate agent does that downstream
against `references/hackerone-precedents.jsonl`. Null precedent →
null bounty, always.

## Roles

- **Mapper** — builds the system map.
- **Boundary Analyst** — identifies trust boundaries; verifies enforcement.
- **Source-to-Sink Tracer** — follows input from entrypoint to sink.
- **Validator** — produces the smallest safe proof.
- **Reporter** — converts evidence into a concise finding.

A single attack-executor agent typically plays Tracer + Validator. The
Advocate plays Reporter. The Triager plays adversarial Boundary
Analyst.
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/BugBountyKB && git add agents/agent-operating-manual.md && git commit -m "feat(agents): add operating manual"
```

---

### Task 1.3: Write supporting checklists

**Files:**
- Create: `~/Documents/BugBountyKB/checklists/target-intake.md`
- Create: `~/Documents/BugBountyKB/checklists/evidence-quality.md`
- Create: `~/Documents/BugBountyKB/checklists/non-dos-filter.md`
- Create: `~/Documents/BugBountyKB/checklists/reportability.md`
- Create: `~/Documents/BugBountyKB/checklists/scope-sweep.md`

- [ ] **Step 1: Write `target-intake.md`**

Content for `~/Documents/BugBountyKB/checklists/target-intake.md`:

```markdown
# Target Intake Checklist

Before any testing.

- [ ] Program URL in `scope.yaml.program_url`.
- [ ] In-scope assets listed (`scope.yaml.in_scope[]`).
- [ ] Out-of-scope assets listed (`scope.yaml.out_of_scope[]`).
- [ ] Allowed test types enumerated (`scope.yaml.allowed_tests[]`).
- [ ] Forbidden actions enumerated (`scope.yaml.forbidden[]` — at
      minimum: dos, social_engineering, physical).
- [ ] Excluded finding types captured
      (`scope.yaml.excluded_findings[]`).
- [ ] Rate limit set (default 10 req/s if unspecified).
- [ ] Testing hours noted (24/7 unless restricted).
- [ ] Credentials available?
      - Yes → `scope.yaml.auth` populated.
      - No → `auth.status: unauthenticated`; accept reduced coverage on
        IDOR / priv-esc / business-logic.
- [ ] Two accounts available for cross-tenant testing?
      - Yes → both recorded in `scope.yaml.auth.accounts[]`.
      - No → `UNPROVABLE_SINGLE_ACCOUNT` in `pipeline-mode.json`;
        cross-tenant findings auto-rejected.
- [ ] User has confirmed authorization to test the listed assets.
```

- [ ] **Step 2: Write `evidence-quality.md`**

Content for `~/Documents/BugBountyKB/checklists/evidence-quality.md`:

```markdown
# Evidence Quality Checklist

Required proof before promoting a `Hypothesis` finding to `Confirmed`
or `Likely`. Phase 2.9 mechanical gate rejects findings that don't
meet these.

For every finding:

- [ ] Reproducible request captured (curl OR dev-browser script OR
      Burp export).
- [ ] Reproducible response captured (status + headers + body excerpt
      OR full screenshot).
- [ ] Browser verification for client-side classes (XSS, DOM
      injection, open redirect, CORS credentialed read, prototype
      pollution, postMessage abuse). API response alone is not proof.
- [ ] Cross-tenant proof for IDOR/BOLA/BFLA/mass_assignment:
      Account A creates → Account B accesses → recorded.
- [ ] Data demonstration: specific PII / financial data / privileged
      action / credential accessed.
- [ ] Path-to-sink documented.
- [ ] Confidence label assigned.
- [ ] Reportability assessment complete.
```

- [ ] **Step 3: Write `non-dos-filter.md`**

Content for `~/Documents/BugBountyKB/checklists/non-dos-filter.md`:

```markdown
# Non-DoS Filter

Pure availability-only DoS is out of scope unless it enables one of:
confidentiality, integrity, authentication, authorization, code
execution, tenant isolation, privilege boundary, or supply-chain
compromise.

For each candidate finding:

- [ ] Data disclosure to unauthorized party? → in scope.
- [ ] Bypasses an authentication or authorization control? → in scope.
- [ ] Enables code execution or command injection? → in scope.
- [ ] Breaks tenant isolation? → in scope.
- [ ] Compromises data integrity? → in scope.
- [ ] Only impact "service slow or unavailable"? → out (DoS-only).
- [ ] Only impact "request consumes more CPU/memory"? → out
      (DoS-only) unless it enables one of the above.
```

- [ ] **Step 4: Write `reportability.md`**

Content for `~/Documents/BugBountyKB/checklists/reportability.md`:

```markdown
# Reportability Test

Reference for the 4-question test from `agent-operating-manual.md`.
Run before marking any finding `validated`.

## Q1: Browser-verified?

For client-side classes (XSS, DOM injection, open redirect,
postMessage, prototype pollution, CORS credentialed reads): did you
observe exploitation in a real browser via dev-browser?

- An API response showing the payload stored is NOT enough.
- Source-map analysis is THEORETICAL until browser-verified.

## Q2: Program's non-qualifying list?

Check `scope.yaml.excluded_findings[]` AND
`config/ArtifactMatrix.yaml.program_excluded_classes`.

## Q3: Demonstrates impact?

PoC shows actual data theft / action on behalf of user / privilege
escalation / security control bypass with proof? "Payload reflected"
alone is informational.

## Q4: Skilled-hunter test?

Would someone with 100+ accepted reports submit this to THIS program?
Check the program's prior triage history for close-codes on similar
findings.

If any answer is no, log as "observed but not reportable" with the
disqualifying reason.
```

- [ ] **Step 5: Write `scope-sweep.md`**

Content for `~/Documents/BugBountyKB/checklists/scope-sweep.md`:

```markdown
# Variant Sweep Checklist

After every confirmed finding, before reporting, sweep variants.

- [ ] Sibling endpoints — same parameter on similar routes
      (`/api/v1/users/{id}` → `/api/v1/orgs/{id}`).
- [ ] Alternate HTTP methods — GET → POST/PUT/PATCH/DELETE/OPTIONS;
      method-override header (`X-HTTP-Method-Override`).
- [ ] Alternate API versions — `/api/v2/x` → `/api/v1/x`,
      `/api/internal/x`.
- [ ] Parameter aliases — `user_id`, `userId`, `uid`, `id`,
      `account_id`.
- [ ] Array/multi-value variants — `?id[]=1&id[]=2`, `?ids=1,2`.
- [ ] Encoding variants — base64-encoded IDs decoded/re-encoded, JWT
      payload modified, hex/uri encoding.
- [ ] Tenant boundary — cross-org, cross-role, cross-region.
- [ ] Authenticated vs unauthenticated — does the bug also fire
      without a token?
- [ ] Subdomains — same endpoint on different subdomains.

Record each variant in the finding's `variants[]` array with outcome.
Variants that also exploit get their own finding IDs.
```

- [ ] **Step 6: Commit**

```bash
cd ~/Documents/BugBountyKB && git add checklists/ && git commit -m "feat(checklists): add target-intake, evidence-quality, non-dos, reportability, scope-sweep"
```

---

### Task 1.4: Write `taxonomy/owasp-class-catalog.md`

**Files:**
- Create: `~/Documents/BugBountyKB/taxonomy/owasp-class-catalog.md`

- [ ] **Step 1: Write the class catalog**

Content for `~/Documents/BugBountyKB/taxonomy/owasp-class-catalog.md`:

```markdown
# Attack Class Catalog

Stable T-ID prefix assignments. Every Coverage Checklist technique
gets a T-ID of the form `T-<PREFIX>-<NN>`. Prefixes are immutable.

| Class | T-ID prefix | Playbook | Agent (skill) |
|-------|-------------|----------|---------------|
| Cross-Site Scripting | XSS | `playbooks/xss.md` | `Agents/XSSAgent.md` |
| SQL Injection | SQLI | `playbooks/sqli.md` | `Agents/SQLiAgent.md` |
| IDOR / BOLA / BFLA | IDOR | `playbooks/idor.md` | `Agents/IDORAgent.md` |
| Server-Side Request Forgery | SSRF | `playbooks/ssrf.md` | `Agents/SSRFAgent.md` |
| Authentication | AUTH | `playbooks/auth.md` | `Agents/AuthAgent.md` |
| CSRF | CSRF | `playbooks/csrf.md` | `Agents/CSRFAgent.md` |
| File Upload | UPLOAD | `playbooks/file-upload.md` | `Agents/FileUploadAgent.md` |
| Deserialization | DESER | `playbooks/deserialization.md` | `Agents/DeserializationAgent.md` |
| Race Condition | RACE | `playbooks/race-condition.md` | `Agents/RaceConditionAgent.md` |
| Business Logic | BIZ | `playbooks/business-logic.md` | `Agents/BusinessLogicAgent.md` |
| API REST | APIREST | `playbooks/api-rest.md` | `Agents/APIRestAgent.md` |
| API GraphQL | GQL | `playbooks/api-graphql.md` | `Agents/APIGraphQLAgent.md` |
| API WebSocket | WS | `playbooks/api-websocket.md` | `Agents/APIWebSocketAgent.md` |
| Client-Side | CLIENT | `playbooks/client-side.md` | `Agents/ClientSideAgent.md` |
| Protocol Smuggling | PROTO | `playbooks/protocol-smuggling.md` | `Agents/ProtocolSmugglingAgent.md` |
| Config Exposure | CONFIG | `playbooks/config-exposure.md` | `Agents/ConfigExposureAgent.md` |
| LLM Prompt Injection | LLMPI | `playbooks/llm-prompt-injection.md` | `Agents/LLMSecurityAgent.md` |
| LLM RAG/Tool Boundary | LLMRAG | `playbooks/llm-rag-tool-boundary.md` | `Agents/LLMSecurityAgent.md` |

## ID Allocation Rules

- IDs assigned in playbook authoring order.
- An ID, once allocated, is never re-used. Removed techniques get a
  tombstone entry in the playbook footer.
- Curator increments the next free ID when accepting a `NEW` proposal.
- `VARIANT_OF: T-X-NN` proposals do NOT get a new T-ID.

## Cross-Tenant Classes

These REQUIRE two accounts. `UNPROVABLE_SINGLE_ACCOUNT` pipeline mode
auto-rejects their findings:

- IDOR / BOLA / BFLA / mass_assignment_cross_tenant
- Authorization (privilege_escalation_cross_role)
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/BugBountyKB && git add taxonomy/ && git commit -m "feat(taxonomy): add OWASP class catalog with T-ID prefix assignments"
```

---

### Task 1.5: Write templates

**Files:**
- Create: `~/Documents/BugBountyKB/templates/finding-report.md`
- Create: `~/Documents/BugBountyKB/templates/security-assessment-report.md`
- Create: `~/Documents/BugBountyKB/templates/novelty-proposal-stub.md`

- [ ] **Step 1: Write `finding-report.md`**

Content for `~/Documents/BugBountyKB/templates/finding-report.md`:

```markdown
# Finding Report Template

> Auto-populated by `lib/generate-report.sh`. Operator-editable before
> submission.

## Title

`[SEVERITY] [Class] in [Component] → [Impact]`

Example: `[CRITICAL] IDOR in /api/v1/users/{id}/export → cross-tenant PII exposure`

## Summary

2-3 sentences. What the bug is, who can exploit it, what they get.

## Vulnerability Details

| Field | Value |
|-------|-------|
| Class | [from `taxonomy/owasp-class-catalog.md`] |
| Technique ID | T-<CLASS>-<NN> |
| CVSS:3.1 | [vector + score] |
| Affected endpoint | `[METHOD] [URL]` |
| Parameter | `[name]` |
| Authentication | Required / Not required |
| Cross-tenant | Yes / No / N/A |
| Confidence | Confirmed |
| Bounty precedent | `[precedent_url or "no precedent matched"]` |

## Steps to Reproduce

1. Authenticate as Account A …
2. Capture object ID …
3. Authenticate as Account B …
4. Issue request …

### Request

```http
[full HTTP request]
```

### Response

```http
[full HTTP response]
```

## Impact

- Primary: [specific named data accessed / action performed]
- Secondary: [chain potential]
- Business impact: [what the program loses]

## Proof of Concept

```bash
[exact curl or dev-browser script]
```

Evidence:
- Screenshot: `evidence/<finding-id>/screenshot-001.png`
- HAR: `evidence/<finding-id>/traffic.har`

## Remediation

[Specific, actionable fix referencing the violated invariant]

## Variants attempted

[From `checklists/scope-sweep.md` — list with outcome each]

## Timeline

| Date | Event |
|------|-------|
| [YYYY-MM-DD] | Discovered |
| [YYYY-MM-DD] | Submitted |
```

- [ ] **Step 2: Write `security-assessment-report.md`**

Content for `~/Documents/BugBountyKB/templates/security-assessment-report.md`:

```markdown
# Security Assessment Report Template

## Executive Summary

[2-3 paragraphs plain-language for non-technical stakeholders]

## Engagement Scope

- Program: [name + URL]
- Targets in scope: [list]
- Excluded: [list]
- Test window: [dates]
- Account modes tested: [single / multi / unauth]

## Findings Summary

| ID | Severity | Class | Title | Status |
|----|----------|-------|-------|--------|
| F-001 | Critical | IDOR | … | Submitted |

## Coverage Report

| Class | Mandatory T-IDs | Attempted | Gaps | N/A (condition) |
|-------|-----------------|-----------|------|-----------------|
| XSS | 15 | 15 | 0 | 0 |
| IDOR | 15 | 14 | 1 (T-IDOR-09: WAF-blocked) | 0 |

## Coverage Gaps Detail

[For each unrecovered gap from `coverage-gaps.txt`: specific reason
plus recovery suggestion for next engagement]

## Detailed Findings

[Each finding's full content per `finding-report.md`]

## Methodology Reference

Coverage Checklists from `~/Documents/BugBountyKB/playbooks/`.
Operating doctrine from
`~/Documents/BugBountyKB/agents/agent-operating-manual.md`.
Adversarial validation per `lib/phase3-debate.sh`.
```

- [ ] **Step 3: Write `novelty-proposal-stub.md`**

Content for `~/Documents/BugBountyKB/templates/novelty-proposal-stub.md`:

```markdown
# Novelty Proposal Stub

Used by Curator when it returns `DEFER_TO_HUMAN`. Drops into
`99-Inbox/<YYYY-MM-DD>-<class>-<short-name>.md`.

## Frontmatter

\`\`\`yaml
---
class: <prefix from taxonomy/owasp-class-catalog.md>
proposed_name: <short name>
source_engagement: <pentest-id>
curator_verdict: DEFER_TO_HUMAN
curator_reason: <why Curator couldn't decide>
confidence: <low | medium>
date: <YYYY-MM-DD>
---
\`\`\`

## Body

### Why this might be novel

[Curator's analysis]

### Why this might already be covered

[Curator's overlap analysis vs existing T-IDs]

### Evidence artifact

[Path to evidence; copy into KB if accepting]

### Proposed Coverage Checklist entry

\`\`\`yaml
- id: T-<CLASS>-PROPOSED
  name: <short name>
  mandatory: false
  proof_required: <type>
  applies_when: <condition or "true">
\`\`\`

## Operator decision

- **Accept** → assign next free T-ID in `playbooks/<class>.md`, add
  the technique body, delete this stub, commit.
- **Reject** → delete this stub with one-line git commit noting why.
- **Defer further** → move to `99-Inbox/deferred/` and revisit later.
```

- [ ] **Step 4: Commit**

```bash
cd ~/Documents/BugBountyKB && git add templates/ && git commit -m "feat(templates): add finding-report, security-assessment-report, novelty-proposal-stub"
```

---

### Task 1.6: Write `maintenance/curation-rules.md`

**Files:**
- Create: `~/Documents/BugBountyKB/maintenance/curation-rules.md`

- [ ] **Step 1: Author curation rules**

Content for `~/Documents/BugBountyKB/maintenance/curation-rules.md`:

```markdown
# Curation Rules

Doctrine for the Curator agent. Loaded at the start of every Phase 3.5
batch.

## Verdict Taxonomy

| Verdict | When | Action |
|---------|------|--------|
| `NEW` | Distinct from every existing T-ID; has all required fields; confidence ≥ medium. | Assign next free T-ID. Insert into Coverage Checklist with `mandatory: false`. Add technique body to playbook prose. Git-commit. |
| `VARIANT_OF: T-X-NN` | Refinement of T-X-NN (same primitive, different payload/encoding/context). | Insert as sub-bullet under T-X-NN's red_flags or proof_targets. No new T-ID. Git-commit. |
| `DUPLICATE_OF: T-X-NN` | Same technique under a different name. | Discard. Log to `curator-log.jsonl`. |
| `REJECT_LOW_QUALITY` | Missing fields, unverifiable evidence, weak proof target. | Discard. Log reason. |
| `DEFER_TO_HUMAN` | Curator cannot confidently decide. | Drop `templates/novelty-proposal-stub.md` into `99-Inbox/`. |

## Bias

**Conservative.** Low-confidence calls default to `DEFER_TO_HUMAN`.
False negatives (deferring novel) cost a manual review. False positives
(merging duplicate) corrupt the KB.

## Novelty Check

Before declaring `NEW`:

1. Read the matching playbook's Coverage Checklist in full.
2. For each existing T-ID, compare:
   - Same primitive?
   - Same sink?
   - Operator-facing fix overlap ≥80%?
3. If any pair scores ≥80% overlap → `VARIANT_OF` or `DUPLICATE_OF`.

## Well-Formedness Check

`NEW` and `VARIANT_OF` require:

- Non-empty `red_flags[]` (at least one)
- Non-empty `proof_targets[]` (at least one)
- Non-empty `fix_patterns[]` (at least one)
- Non-null `evidence_artifact_path` that exists on disk

Missing any → `REJECT_LOW_QUALITY` citing the specific missing field.

## Commit Message Convention

```
playbook(<class>): <verb> T-<CLASS>-<NN> (<short name>)

Evidence: <path or summary>
Source engagement: <pentest-id>
Curator verdict: <NEW | VARIANT_OF: T-X-NN>
Confidence: <medium | high>
```

Verbs: `add` for NEW, `extend` for VARIANT_OF.

## Batching

Curator processes 5-8 proposed_additions per invocation. If an
engagement produces more, the orchestrator runs multiple Curator
invocations sequentially.

## Precedent Appending

When an engagement produces a "resolved" outcome (operator marks
`engagement.outcome: resolved` with a payout or close code), Curator
appends a row to `references/hackerone-precedents.jsonl`:

```jsonl
{"program": "<handle>", "class": "<prefix>", "severity": "<P1-P5>", "payout_usd": <number or null>, "close_code": "<code or null>", "report_url": "<URL>", "added": "<YYYY-MM-DD>"}
```
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/BugBountyKB && git add maintenance/ && git commit -m "feat(maintenance): add Curator doctrine and verdict taxonomy"
```

---

### Task 1.7: Write workflow and CVE-anchors stub

**Files:**
- Create: `~/Documents/BugBountyKB/workflows/end-to-end-pentest.md`
- Create: `~/Documents/BugBountyKB/references/cve-research-anchors.md`

- [ ] **Step 1: Write `end-to-end-pentest.md`**

Content for `~/Documents/BugBountyKB/workflows/end-to-end-pentest.md`:

```markdown
# End-to-End Pentest Workflow

Default assessment loop. Skill-side `SKILL.md` enforces the phase
pipeline mechanically.

## Phases

1. Scope intake (`checklists/target-intake.md`)
2. Passive recon — subfinder, cert transparency, GitHub dorks
3. Auth acquisition
4. Active authenticated recon (emits `recon.capabilities`)
5. AppReview — produces `app-profile.json` with crown jewels and
   per-flow hypotheses (depth/priority hints, NOT gating)
6. Attack phase — per-class executors iterate Coverage Checklist
7. Coverage reconciliation — orchestrator verifies every mandatory
   T-ID attempted; gaps trigger focused follow-up agents
8. Mechanical artifact gate
9. Adversarial validation (Advocate↔Triager)
10. Curator — process proposed_additions
11. Report generation

## Operator checkpoints

- After Phase 0: review `scope.yaml`, confirm authorization.
- After Phase 1d: skim `app-profile.json` for misclassified flows.
- After Phase 3: review `triager_closed[]` for false negatives.
- After Phase 3.5: review `99-Inbox/` for DEFER stubs.
- After Phase 4: edit findings before submission.

## Time budget

- Phases 0-1c: 30-90 min
- Phase 1d: 5-15 min
- Phase 2: 2-6 hours
- Phases 2.5, 2.9, 3, 3.5: 30-60 min combined
- Phase 4: 15-30 min

Typical web/API engagement: 4-8 hours.
```

- [ ] **Step 2: Write `cve-research-anchors.md` (stub)**

Content for `~/Documents/BugBountyKB/references/cve-research-anchors.md`:

```markdown
# CVE Research Anchors

Authoritative research sources Curator may cite when merging
proposed_additions.

## OWASP

- OWASP Top 10: https://owasp.org/Top10/
- OWASP API Top 10: https://owasp.org/API-Security/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP WSTG v5: https://owasp.org/www-project-web-security-testing-guide/

## LLM-specific

- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- OWASP AI Exchange: https://owaspai.org/

## Research feeds

- HackerOne Hacktivity: https://hackerone.com/hacktivity
- PortSwigger Research: https://portswigger.net/research
- Project Zero: https://googleprojectzero.blogspot.com/

(Expand as engagements surface domain-specific references.)
```

- [ ] **Step 3: Commit**

```bash
cd ~/Documents/BugBountyKB && git add workflows/ references/cve-research-anchors.md && git commit -m "feat: add end-to-end workflow and CVE anchors stub"
```

---

### Task 1.8: Copy v3 HackerOnePrecedents to KB

**Files:**
- Create: `~/Documents/BugBountyKB/references/hackerone-precedents.jsonl`

- [ ] **Step 1: Copy precedent data**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/data/HackerOnePrecedents.jsonl \
   ~/Documents/BugBountyKB/references/hackerone-precedents.jsonl
```

- [ ] **Step 2: Verify non-empty**

```bash
wc -l ~/Documents/BugBountyKB/references/hackerone-precedents.jsonl
```

Expected: >0 lines.

- [ ] **Step 3: Commit**

```bash
cd ~/Documents/BugBountyKB && git add references/hackerone-precedents.jsonl && git commit -m "feat(references): seed HackerOne precedents from v3"
```

---

### Task 1.9: Write KB `README.md` route map

**Files:**
- Create: `~/Documents/BugBountyKB/README.md`

- [ ] **Step 1: Write the route map**

Content for `~/Documents/BugBountyKB/README.md`:

```markdown
# BugBountyKB

Pentest-oriented knowledge base for BugBountyHunter v4 agents.

Markdown, git-tracked, doctrine + Coverage Checklists. Designed to be
loaded routeably (one playbook per active attack class). Compatible
with Obsidian for browsing.

## Start Here

On every engagement, the agent loads this packet:

1. `README.md` — this file (route map)
2. `agents/agent-operating-manual.md` — doctrine, confidence levels,
   reportability test, wire-contract semantics
3. `checklists/target-intake.md` — scope, accounts, auth, rate limits
4. `checklists/non-dos-filter.md` — what belongs
5. `checklists/evidence-quality.md` — proof gate
6. `workflows/end-to-end-pentest.md` — default loop

Then load only the playbooks matching the engagement's attack classes.

## Layout

| Directory | Contents |
|-----------|----------|
| `agents/` | Class-agnostic operating manual |
| `playbooks/` | Per-class doctrine + Coverage Checklists |
| `payloads/` | Runtime payload recipes |
| `checklists/` | Repeatable review gates |
| `taxonomy/` | Class catalog + T-ID prefix assignments |
| `templates/` | Report templates and novelty stubs |
| `workflows/` | End-to-end + per-class engagement loops |
| `references/` | HackerOne precedents, CVE anchors |
| `maintenance/` | Curator doctrine |
| `evals/` | Test fixtures and harnesses |
| `99-Inbox/` | Curator DEFER drop point |

## Compatibility

- KB version: see `VERSION`.
- Skill `BugBountyHunter-v4 >= 0.1.0` requires KB `>= 0.1.0`.
- Mismatch produces a warning, not a hard fail.

## Contributing

- Manual edits welcome.
- Curator auto-merges accepted `proposed_additions` per
  `maintenance/curation-rules.md`.
- Commits follow `<type>(<scope>): <description>` convention.
```

- [ ] **Step 2: Commit**

```bash
cd ~/Documents/BugBountyKB && git add README.md && git commit -m "docs: add KB README route map"
```

---

### Task 1.10: Scaffold v4 skill repository

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/` (tree)
- Create: `~/.claude/skills/BugBountyHunter-v4/package.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tsconfig.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/.gitignore`
- Create: `~/.claude/skills/BugBountyHunter-v4/SKILL.md` (skeleton)

- [ ] **Step 1: Create directory tree**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/{Agents,lib,config,Workflows,tests/{smoke,fixtures}}
```

- [ ] **Step 2: Write `package.json`**

Content for `~/.claude/skills/BugBountyHunter-v4/package.json`:

```json
{
  "name": "bug-bounty-hunter-v4",
  "version": "0.1.0",
  "description": "KB-driven coverage-enforced pentest orchestrator",
  "type": "module",
  "scripts": {
    "test": "bun test",
    "validate-playbooks": "bash lib/validate-playbook.sh"
  },
  "devDependencies": {
    "@types/bun": "latest"
  }
}
```

- [ ] **Step 3: Write `tsconfig.json`**

Content for `~/.claude/skills/BugBountyHunter-v4/tsconfig.json`:

```json
{
  "compilerOptions": {
    "lib": ["ESNext"],
    "target": "ESNext",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["bun-types"],
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "skipLibCheck": true
  },
  "include": ["lib/**/*.ts", "tests/**/*.ts"]
}
```

- [ ] **Step 4: Write `.gitignore`**

Content for `~/.claude/skills/BugBountyHunter-v4/.gitignore`:

```
node_modules/
bun.lockb
*.log
.DS_Store
.scratch/
```

- [ ] **Step 5: Write SKILL.md skeleton**

Content for `~/.claude/skills/BugBountyHunter-v4/SKILL.md`:

```markdown
---
name: BugBountyHunter-v4
description: KB-driven coverage-enforced bug bounty pentest orchestrator. MUST trigger only when user explicitly says "v4", "kb pentest", "coverage pentest", or "bbh v4". Do NOT trigger on plain "pentest" — that goes to v2/v3.
---

# BugBountyHunter v4 — Orchestrator

> Skeleton. Filled across Plan A phases. See
> `docs/superpowers/specs/2026-05-21-bug-bounty-v4-design.md`.

## Pipeline (8 phases)

- Phase 0 — Scope compliance
- Phase 1a — Passive recon
- Phase 1b — Auth acquisition
- Phase 1c — Active authenticated recon (emits `recon.capabilities`)
- Phase 1d — AppReview (Opus; depth-not-gating)
- Phase 2 — Per-class attack executors (Sonnet, batched)
- Phase 2.5 — Coverage reconciliation
- Phase 2.9 — Mechanical artifact gate
- Phase 3 — Advocate↔Triager debate
- Phase 3.5 — Curator (batched 5-8)
- Phase 4 — Report generation

## KB Contract

Every attack executor:

1. Reads `~/Documents/BugBountyKB/agents/agent-operating-manual.md`
2. Reads its matching `~/Documents/BugBountyKB/playbooks/<class>.md`
3. Parses the playbook's `## Coverage Checklist` YAML
4. For each `mandatory: true` (or `mandatory.when:` evaluates true)
   technique, emits a `coverage[]` entry
5. Emits `findings[]` for confirmed/likely findings
6. Emits `proposed_additions[]` for novel variants

Output must match `config/finding-schema.json`.

(Implementation details added in subsequent tasks.)
```

- [ ] **Step 6: Verify the skeleton**

```bash
ls -la ~/.claude/skills/BugBountyHunter-v4/ && \
ls ~/.claude/skills/BugBountyHunter-v4/{Agents,lib,config,Workflows,tests/smoke,tests/fixtures}
```

Expected: 4 files at top (package.json, tsconfig.json, .gitignore, SKILL.md), 6 subdirs.

- [ ] **Step 7: Mirror into project repo and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
mkdir -p skills/BugBountyHunter-v4 && \
cp -r ~/.claude/skills/BugBountyHunter-v4/{package.json,tsconfig.json,.gitignore,SKILL.md} \
   skills/BugBountyHunter-v4/ && \
mkdir -p skills/BugBountyHunter-v4/{Agents,lib,config,Workflows,tests/{smoke,fixtures}} && \
git add skills/BugBountyHunter-v4/ && \
git commit -m "feat(v4): scaffold skill structure"
```

Note: We maintain two copies — canonical at `~/.claude/skills/BugBountyHunter-v4/` (loaded by Claude Code), tracked mirror in project repo for version control. A small `lib/sync-to-project.sh` lands in Phase 7 to automate the sync.

---

### Task 1.11: Write `config/finding-schema.json` (executor wire contract)

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/config/finding-schema.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/valid-agent-output.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/invalid-agent-output-missing-coverage.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh`

- [ ] **Step 1: Write the failing test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$SKILL_DIR"

echo "--- T1: valid output should validate ---"
python3 -c "
import json, jsonschema
schema = json.load(open('config/finding-schema.json'))
sample = json.load(open('tests/fixtures/valid-agent-output.json'))
jsonschema.validate(sample, schema)
print('VALID: passes schema')
" || { echo "FAIL: valid output rejected"; exit 1; }

echo "--- T2: invalid output (missing coverage) should fail ---"
if python3 -c "
import json, jsonschema
schema = json.load(open('config/finding-schema.json'))
sample = json.load(open('tests/fixtures/invalid-agent-output-missing-coverage.json'))
jsonschema.validate(sample, schema)
" 2>/dev/null ; then
  echo "FAIL: invalid output accepted"; exit 1
else
  echo "PASS: invalid output correctly rejected"
fi

echo "ALL PASS"
```

Make it executable:

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh
```

Expected: FAIL — schema and fixtures don't exist.

- [ ] **Step 3: Install jsonschema**

```bash
python3 -c "import jsonschema" 2>/dev/null || pip install --user jsonschema
```

- [ ] **Step 4: Write fixture `valid-agent-output.json`**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/valid-agent-output.json`:

```json
{
  "agent_id": "xss-1",
  "class": "xss",
  "engagement_id": "pentest-test-001",
  "coverage": [
    {
      "id": "T-XSS-01",
      "attempted": true,
      "evidence_artifact": "/tmp/eng/findings/F-A-001/req-resp.har",
      "verdict": "exploited"
    },
    {
      "id": "T-XSS-02",
      "attempted": false,
      "gap_reason": "no_matching_endpoint"
    }
  ],
  "findings": [
    {
      "id": "F-A-001",
      "class": "xss",
      "technique_id": "T-XSS-01",
      "endpoint": "POST /api/comments",
      "parameter": "body",
      "confidence": "Confirmed",
      "evidence_artifact": "/tmp/eng/findings/F-A-001/req-resp.har",
      "reportability_assessment": {
        "browser_verified": true,
        "in_excluded_list": false,
        "demonstrates_impact": true,
        "skilled_hunter_would_submit": true
      }
    }
  ],
  "proposed_additions": []
}
```

- [ ] **Step 5: Write fixture `invalid-agent-output-missing-coverage.json`**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/invalid-agent-output-missing-coverage.json`:

```json
{
  "agent_id": "xss-1",
  "class": "xss",
  "engagement_id": "pentest-test-001",
  "findings": [],
  "proposed_additions": []
}
```

- [ ] **Step 6: Write `config/finding-schema.json`**

Content for `~/.claude/skills/BugBountyHunter-v4/config/finding-schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "BugBountyHunter v4 — Attack Executor Output Wire Contract",
  "type": "object",
  "required": ["agent_id", "class", "engagement_id", "coverage", "findings", "proposed_additions"],
  "additionalProperties": false,
  "properties": {
    "agent_id": { "type": "string", "minLength": 1 },
    "class": {
      "type": "string",
      "enum": [
        "xss", "sqli", "idor", "ssrf", "auth", "csrf", "file_upload",
        "deserialization", "race_condition", "business_logic",
        "api_rest", "api_graphql", "api_websocket", "client_side",
        "protocol_smuggling", "config_exposure",
        "llm_prompt_injection", "llm_rag_tool_boundary"
      ]
    },
    "engagement_id": { "type": "string", "minLength": 1 },
    "coverage": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["id", "attempted"],
        "additionalProperties": false,
        "properties": {
          "id": { "type": "string", "pattern": "^T-[A-Z]+-[0-9]{2,3}$" },
          "attempted": { "type": "boolean" },
          "evidence_artifact": { "type": "string" },
          "verdict": { "type": "string", "enum": ["exploited", "not_exploited", "inconclusive"] },
          "gap_reason": {
            "type": "string",
            "enum": [
              "no_matching_endpoint", "waf_blocked", "timeout",
              "rate_limited", "auth_failed", "out_of_scope",
              "condition_not_met"
            ]
          }
        },
        "allOf": [
          {
            "if": { "properties": { "attempted": { "const": true } } },
            "then": { "required": ["evidence_artifact", "verdict"] }
          },
          {
            "if": { "properties": { "attempted": { "const": false } } },
            "then": { "required": ["gap_reason"] }
          }
        ]
      }
    },
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "id", "class", "technique_id", "endpoint", "confidence",
          "evidence_artifact", "reportability_assessment"
        ],
        "properties": {
          "id": { "type": "string", "pattern": "^F-[A-Z]-[0-9]{3}$" },
          "class": { "type": "string" },
          "technique_id": { "type": "string", "pattern": "^T-[A-Z]+-[0-9]{2,3}$" },
          "endpoint": { "type": "string" },
          "parameter": { "type": ["string", "null"] },
          "confidence": { "type": "string", "enum": ["Confirmed", "Likely", "Hypothesis", "Rejected"] },
          "evidence_artifact": { "type": "string" },
          "reportability_assessment": {
            "type": "object",
            "required": [
              "browser_verified", "in_excluded_list",
              "demonstrates_impact", "skilled_hunter_would_submit"
            ],
            "properties": {
              "browser_verified": { "type": "boolean" },
              "in_excluded_list": { "type": "boolean" },
              "demonstrates_impact": { "type": "boolean" },
              "skilled_hunter_would_submit": { "type": "boolean" }
            }
          },
          "variants_attempted": { "type": "array", "items": { "type": "object" } }
        }
      }
    },
    "proposed_additions": {
      "type": "array",
      "items": {
        "type": "object",
        "required": [
          "class", "proposed_name", "family",
          "red_flags", "proof_targets", "fix_patterns",
          "evidence_artifact_path"
        ],
        "properties": {
          "class": { "type": "string" },
          "proposed_name": { "type": "string" },
          "family": { "type": "string" },
          "red_flags": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
          "proof_targets": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
          "fix_patterns": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
          "evidence_artifact_path": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}
```

- [ ] **Step 7: Run test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh
```

Expected: `VALID: passes schema`, `PASS: invalid output correctly rejected`, `ALL PASS`.

- [ ] **Step 8: Mirror into project repo and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/config/finding-schema.json skills/BugBountyHunter-v4/config/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_finding_schema.sh skills/BugBountyHunter-v4/tests/smoke/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/*.json skills/BugBountyHunter-v4/tests/fixtures/ && \
git add skills/BugBountyHunter-v4/{config,tests} && \
git commit -m "feat(v4): add finding-schema.json wire contract + smoke test"
```

---

### Task 1.12: Write `lib/validate-playbook.sh`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-valid.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-missing-section.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-duplicate-id.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-malformed-id.md`

- [ ] **Step 1: Write the failing test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${SKILL_DIR}/lib/validate-playbook.sh"
FIX="${SKILL_DIR}/tests/fixtures"

echo "--- T1: valid playbook accepted ---"
bash "$SCRIPT" "${FIX}/playbook-valid.md" || { echo "FAIL"; exit 1; }

echo "--- T2: missing Coverage Checklist rejected ---"
if bash "$SCRIPT" "${FIX}/playbook-missing-section.md" 2>/dev/null; then
  echo "FAIL: missing-section accepted"; exit 1
fi

echo "--- T3: duplicate T-ID rejected ---"
if bash "$SCRIPT" "${FIX}/playbook-duplicate-id.md" 2>/dev/null; then
  echo "FAIL: duplicate-id accepted"; exit 1
fi

echo "--- T4: malformed T-ID rejected ---"
if bash "$SCRIPT" "${FIX}/playbook-malformed-id.md" 2>/dev/null; then
  echo "FAIL: malformed-id accepted"; exit 1
fi

echo "ALL PASS"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh
```

- [ ] **Step 2: Write fixtures**

`~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-valid.md`:

````markdown
# Valid Test Playbook

## Coverage Checklist

```yaml
techniques:
  - id: T-TEST-01
    name: First test technique
    mandatory: true
    proof_required: demo
  - id: T-TEST-02
    name: Second test technique
    mandatory: false
    proof_required: demo
```
````

`~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-missing-section.md`:

```markdown
# Playbook Without Coverage Checklist

No checklist section here.
```

`~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-duplicate-id.md`:

````markdown
# Duplicate ID Playbook

## Coverage Checklist

```yaml
techniques:
  - id: T-TEST-01
    name: First
    mandatory: true
    proof_required: demo
  - id: T-TEST-01
    name: Second
    mandatory: true
    proof_required: demo
```
````

`~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-malformed-id.md`:

````markdown
# Malformed ID Playbook

## Coverage Checklist

```yaml
techniques:
  - id: NOT_A_VALID_ID
    name: First
    mandatory: true
    proof_required: demo
```
````

- [ ] **Step 3: Run test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh
```

Expected: FAIL — `validate-playbook.sh` doesn't exist.

- [ ] **Step 4: Implement `lib/validate-playbook.sh`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh`:

```bash
#!/usr/bin/env bash
# validate-playbook.sh — hard-fails if a KB playbook has a malformed
# Coverage Checklist. Runs at orchestrator startup AND as a pre-commit
# hook on BugBountyKB.
#
# Usage:
#   bash validate-playbook.sh <playbook.md>
#   bash validate-playbook.sh --all <BugBountyKB-dir>
set -euo pipefail

usage() {
  echo "Usage: $0 <playbook.md> | --all <BugBountyKB-dir>" >&2
  exit 2
}

validate_one() {
  local file="$1"

  local yaml
  yaml=$(awk '
    /^## Coverage Checklist/ { in_section=1; next }
    /^## / && in_section { in_section=0 }
    in_section && /^```yaml$/ { in_block=1; next }
    in_section && /^```$/ && in_block { in_block=0; exit }
    in_block { print }
  ' "$file")

  if [ -z "$yaml" ]; then
    echo "[FAIL] $file: no ## Coverage Checklist section or no YAML block" >&2
    return 1
  fi

  python3 - "$file" "$yaml" <<'PY'
import sys, yaml, re

path = sys.argv[1]
yaml_text = sys.argv[2]

try:
    data = yaml.safe_load(yaml_text)
except Exception as e:
    print(f"[FAIL] {path}: malformed YAML: {e}", file=sys.stderr)
    sys.exit(1)

if not isinstance(data, dict) or "techniques" not in data:
    print(f"[FAIL] {path}: top-level YAML must have 'techniques:' key", file=sys.stderr)
    sys.exit(1)

techniques = data["techniques"]
if not isinstance(techniques, list) or not techniques:
    print(f"[FAIL] {path}: techniques: must be a non-empty list", file=sys.stderr)
    sys.exit(1)

id_pat = re.compile(r"^T-[A-Z]+-[0-9]{2,3}$")
seen_ids = set()

for i, t in enumerate(techniques):
    if not isinstance(t, dict):
        print(f"[FAIL] {path}: techniques[{i}] is not an object", file=sys.stderr)
        sys.exit(1)
    for req in ("id", "name", "mandatory", "proof_required"):
        if req not in t:
            print(f"[FAIL] {path}: techniques[{i}] missing '{req}'", file=sys.stderr)
            sys.exit(1)
    tid = t["id"]
    if not id_pat.match(tid):
        print(f"[FAIL] {path}: techniques[{i}].id '{tid}' does not match T-<PREFIX>-<NN>", file=sys.stderr)
        sys.exit(1)
    if tid in seen_ids:
        print(f"[FAIL] {path}: duplicate technique id '{tid}'", file=sys.stderr)
        sys.exit(1)
    seen_ids.add(tid)
    mand = t["mandatory"]
    if not (isinstance(mand, bool) or (isinstance(mand, dict) and "when" in mand)):
        print(f"[FAIL] {path}: techniques[{i}].mandatory must be bool or {{when: ...}}", file=sys.stderr)
        sys.exit(1)
    pr = t["proof_required"]
    if not isinstance(pr, str) or not pr.strip():
        print(f"[FAIL] {path}: techniques[{i}].proof_required must be a non-empty string", file=sys.stderr)
        sys.exit(1)

print(f"[OK] {path}: {len(techniques)} techniques validated")
PY
}

if [ $# -lt 1 ]; then usage; fi

if [ "$1" = "--all" ]; then
  if [ $# -lt 2 ]; then usage; fi
  KB_DIR="$2"
  if [ ! -d "${KB_DIR}/playbooks" ]; then
    echo "[FAIL] ${KB_DIR}/playbooks not found" >&2
    exit 1
  fi
  any_fail=0
  for f in "${KB_DIR}/playbooks"/*.md; do
    [ -f "$f" ] || continue
    validate_one "$f" || any_fail=1
  done
  exit $any_fail
else
  validate_one "$1"
fi
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh
```

- [ ] **Step 5: Run test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh
```

Expected: `T1 OK`, `T2/T3/T4 rejected`, `ALL PASS`.

- [ ] **Step 6: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_validate_playbook.sh skills/BugBountyHunter-v4/tests/smoke/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/playbook-*.md skills/BugBountyHunter-v4/tests/fixtures/ && \
git add skills/BugBountyHunter-v4/{lib,tests} && \
git commit -m "feat(v4): add validate-playbook.sh YAML validator + 4 fixture tests"
```

---

### Task 1.13: Author seed playbook `playbooks/xss.md`

**Files:**
- Create: `~/Documents/BugBountyKB/playbooks/xss.md`

- [ ] **Step 1: Write the full XSS playbook**

Author `~/Documents/BugBountyKB/playbooks/xss.md` with the following structure. The prose is doctrine; the YAML Coverage Checklist at the end is the load-bearing machine-readable artifact. Use the exact literal API names (e.g. `document.write`, `innerHTML`, `bypassSecurityTrustHtml`, the React escape-hatch HTML insertion prop) in the playbook itself — they're standard pentest vocabulary. This plan file uses paraphrased forms only to avoid triggering security scanners during plan authoring; the playbook content uses literals.

**Sections to include (full prose, no placeholders):**

1. **# Cross-Site Scripting (XSS) Playbook**
2. **## Objective** — Detect attacker-controlled input flowing into a rendering sink without context-aware encoding, with browser-verified execution producing demonstrable impact.
3. **## Families** — list: Reflected, Stored, DOM, Mutation XSS (mXSS), postMessage abuse, Markdown renderer bypass, Template-injection-adjacent XSS.
4. **## Red Flags** — list of patterns to look for during code review or response inspection. Include: server-side string concatenation of user input into HTML responses; client-side DOM sinks that write raw HTML or evaluate strings as JS (the document-write API, the innerHTML/outerHTML setters, the eval-family of dynamic JS evaluators, timer/Function constructors that accept string arguments); framework escape-hatch HTML-insertion APIs (Angular's HTML-trust bypass, React's escape-hatch HTML prop, Vue's v-html directive); custom (non-DOMPurify) sanitizer functions; postMessage handlers without origin allowlists; CSP with `unsafe-inline` / `unsafe-eval`; Content-Type confusion.
5. **## Proof Targets** — Confirmed = JavaScript executes in attacker-controlled context, attacker reads `document.cookie` or performs state-changing `fetch()`. Browser-verified via dev-browser mandatory.
6. **## Fix Patterns** — context-aware encoding at render; DOMPurify on rich-text content; strict CSP with nonces; HTTPOnly + SameSite cookies; framework escape-hatches only on operator-owned content; `postMessage` origin allowlists.
7. **## Coverage Checklist** — paste the YAML block below verbatim.
8. **## Tombstone** — `(No retired technique IDs yet.)`

**The Coverage Checklist YAML (paste verbatim into the playbook):**

```yaml
techniques:
  - id: T-XSS-01
    name: Reflected XSS via search/query parameter
    mandatory: true
    proof_required: browser_executed_alert_or_fetch
    applies_when: recon.capabilities.has_query_param_endpoints

  - id: T-XSS-02
    name: Stored XSS via user profile fields
    mandatory: true
    proof_required: browser_executed_on_second_user_view
    applies_when: recon.capabilities.has_user_profile_fields

  - id: T-XSS-03
    name: Stored XSS via comment / message / note fields
    mandatory: true
    proof_required: browser_executed_on_other_account_view
    applies_when: recon.capabilities.has_user_generated_content

  - id: T-XSS-04
    name: DOM XSS via hash/fragment
    mandatory: true
    proof_required: browser_executed_via_location_hash
    applies_when: recon.capabilities.has_client_side_routing

  - id: T-XSS-05
    name: DOM XSS via postMessage handler
    mandatory: true
    proof_required: browser_executed_via_cross_origin_postmessage
    applies_when: recon.capabilities.has_postmessage_handlers

  - id: T-XSS-06
    name: Markdown rendering bypass (custom sanitizer)
    mandatory:
      when: recon.capabilities.has_markdown_render == true
    proof_required: browser_executed_via_markdown_payload

  - id: T-XSS-07
    name: Mutation XSS via DOMPurify version skew or config
    mandatory:
      when: recon.capabilities.has_dompurify == true
    proof_required: browser_executed_via_mxss_payload

  - id: T-XSS-08
    name: SVG-embedded XSS (file upload accepting SVG)
    mandatory:
      when: recon.capabilities.has_svg_upload == true
    proof_required: browser_executed_via_uploaded_svg

  - id: T-XSS-09
    name: PDF/PostScript content-injection (when content rendered inline)
    mandatory:
      when: recon.capabilities.has_inline_pdf == true
    proof_required: browser_executed_via_pdf_js_sink

  - id: T-XSS-10
    name: AngularJS sandbox escape
    mandatory:
      when: recon.capabilities.angular_version_lt_1_6 == true
    proof_required: browser_executed_via_angular_template

  - id: T-XSS-11
    name: Template injection producing XSS
    mandatory:
      when: recon.capabilities.has_template_engine == true
    proof_required: browser_executed_via_template_injection

  - id: T-XSS-12
    name: Framework escape-hatch HTML prop on user content
    mandatory:
      when: recon.capabilities.has_react_or_vue == true
    proof_required: browser_executed_via_framework_escape_hatch

  - id: T-XSS-13
    name: WAF bypass via polyglot, encoding, or context confusion
    mandatory:
      when: recon.capabilities.waf_detected == true
    proof_required: browser_executed_post_waf_bypass

  - id: T-XSS-14
    name: CSP bypass via JSONP, AngularJS, or whitelist abuse
    mandatory:
      when: recon.capabilities.csp_has_unsafe_eval_or_unsafe_inline == true
    proof_required: browser_executed_under_csp

  - id: T-XSS-15
    name: Content-Type confusion (HTML interpreted from JSON endpoint)
    mandatory: true
    proof_required: browser_executed_via_content_type_confusion
    applies_when: recon.capabilities.has_json_endpoints
```

- [ ] **Step 2: Validate the playbook**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh \
  ~/Documents/BugBountyKB/playbooks/xss.md
```

Expected: `[OK] .../xss.md: 15 techniques validated`.

- [ ] **Step 3: Commit**

```bash
cd ~/Documents/BugBountyKB && git add playbooks/xss.md && git commit -m "feat(playbook): add XSS playbook with 15-technique Coverage Checklist"
```

---

### Task 1.14: Author seed playbook `playbooks/idor.md`

**Files:**
- Create: `~/Documents/BugBountyKB/playbooks/idor.md`

- [ ] **Step 1: Write the IDOR playbook**

Author `~/Documents/BugBountyKB/playbooks/idor.md` with the following structure:

**Sections (full prose, no placeholders):**

1. **# IDOR / BOLA / BFLA Playbook**
2. **## Objective** — Detect broken access control where an authenticated attacker can access, modify, or delete data belonging to another user, tenant, or privilege level. REQUIRES two accounts for valid proof.
3. **## Families** — BOLA (`/api/objects/{id}` cross-account); BFLA (admin endpoint accessible to user); Mass assignment (protected fields settable); Tenant isolation breach; Path traversal in object refs; Method-override / verb confusion.
4. **## Red Flags** — sequential numeric IDs; UUID exposed in list responses without authz check; authz predicate appended client-side; `whereRaw` / `orderByRaw` with attacker-controlled column; owner check after data fetch (TOCTOU); endpoints accepting `user_id` in body when session has identity; mass-assignable models with `verified`/`role`/`balance`/`is_admin` fields publicly settable.
5. **## Proof Targets** — Confirmed = Account A accesses Account B's specific PII/financial data; OR Account A performs state-change on Account B's object; OR low-priv account performs admin action. Single-account "IDOR" is NOT confirmed.
6. **## Fix Patterns** — server-side identity binding in every query; indirect object references; mass-assignment allowlists; authz at controller/service layer (not view); tenant scoping in middleware.
7. **## Coverage Checklist** — paste the YAML block below verbatim.
8. **## Tombstone** — `(No retired technique IDs yet.)`

**The Coverage Checklist YAML (paste verbatim):**

```yaml
techniques:
  - id: T-IDOR-01
    name: Sequential numeric ID enumeration
    mandatory: true
    proof_required: cross_account_data_read
    applies_when: recon.capabilities.has_numeric_id_endpoints

  - id: T-IDOR-02
    name: UUID enumeration via API list response leakage
    mandatory: true
    proof_required: cross_account_data_read
    applies_when: recon.capabilities.has_uuid_endpoints

  - id: T-IDOR-03
    name: Base64/encoded ID decode + modify + re-encode
    mandatory: true
    proof_required: cross_account_data_read

  - id: T-IDOR-04
    name: Composite key (org_id + object_id) tenant boundary breach
    mandatory:
      when: recon.capabilities.has_composite_key_endpoints == true
    proof_required: cross_tenant_data_read

  - id: T-IDOR-05
    name: HTTP method switching (GET blocked, PUT allowed)
    mandatory: true
    proof_required: cross_account_action_via_alternate_method

  - id: T-IDOR-06
    name: API version downgrade bypass
    mandatory:
      when: recon.capabilities.has_versioned_api == true
    proof_required: cross_account_data_read_via_older_api

  - id: T-IDOR-07
    name: Mass assignment of role / verified / balance / is_admin field
    mandatory: true
    proof_required: privilege_escalation_or_data_corruption
    applies_when: recon.capabilities.has_writable_json_endpoints

  - id: T-IDOR-08
    name: Array-based IDOR (?id[]=mine&id[]=victim)
    mandatory: true
    proof_required: cross_account_data_read_via_array_param

  - id: T-IDOR-09
    name: Body-parameter user_id tampering
    mandatory: true
    proof_required: cross_account_action_via_body_param

  - id: T-IDOR-10
    name: Path traversal in object reference (../admin/users)
    mandatory: true
    proof_required: privilege_escalation_via_path_traversal

  - id: T-IDOR-11
    name: BFLA — admin endpoint accessible to low-priv role
    mandatory: true
    proof_required: admin_action_as_low_priv_user

  - id: T-IDOR-12
    name: Method-override header (X-HTTP-Method-Override)
    mandatory: true
    proof_required: cross_account_action_via_method_override

  - id: T-IDOR-13
    name: GraphQL node-id enumeration via global IDs
    mandatory:
      when: recon.capabilities.graphql == true
    proof_required: cross_account_data_read_via_graphql_node

  - id: T-IDOR-14
    name: GraphQL mutation auth bypass via aliasing or batching
    mandatory:
      when: recon.capabilities.graphql == true
    proof_required: cross_account_mutation_via_graphql_alias

  - id: T-IDOR-15
    name: TOCTOU on owner check (race between authz check and action)
    mandatory:
      when: recon.capabilities.has_writable_endpoints == true
    proof_required: cross_account_action_via_race
```

- [ ] **Step 2: Validate the playbook**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh \
  ~/Documents/BugBountyKB/playbooks/idor.md
```

Expected: `[OK] .../idor.md: 15 techniques validated`.

- [ ] **Step 3: Validate both playbooks via `--all`**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh \
  --all ~/Documents/BugBountyKB/
```

Expected: 2 `[OK]` lines, exit 0.

- [ ] **Step 4: Commit**

```bash
cd ~/Documents/BugBountyKB && git add playbooks/idor.md && git commit -m "feat(playbook): add IDOR playbook with 15-technique Coverage Checklist"
```

---

### Task 1.15: Port v3 enforcement configs

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/config/ArtifactMatrix.yaml`
- Create: `~/.claude/skills/BugBountyHunter-v4/config/PublicSafeList.yaml`

- [ ] **Step 1: Copy ArtifactMatrix.yaml**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/config/ArtifactMatrix.yaml \
   ~/.claude/skills/BugBountyHunter-v4/config/ArtifactMatrix.yaml
```

- [ ] **Step 2: Copy PublicSafeList.yaml**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/config/PublicSafeList.yaml \
   ~/.claude/skills/BugBountyHunter-v4/config/PublicSafeList.yaml
```

- [ ] **Step 3: Verify both parse as YAML**

```bash
python3 -c "
import yaml
for f in ['ArtifactMatrix.yaml', 'PublicSafeList.yaml']:
    path = f'/home/adlt/.claude/skills/BugBountyHunter-v4/config/{f}'
    data = yaml.safe_load(open(path))
    assert data, f'{f} is empty'
    print(f'OK {f}: top-level keys = {list(data.keys())[:5]}')
"
```

Expected: 2 `OK` lines.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/config/{ArtifactMatrix,PublicSafeList}.yaml \
   skills/BugBountyHunter-v4/config/ && \
git add skills/BugBountyHunter-v4/config/ && \
git commit -m "feat(v4): port ArtifactMatrix and PublicSafeList from v3"
```

---

### Task 1.16: Port v3 utility scripts

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/yaml2json.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/validate-state-schema.sh`

- [ ] **Step 1: Copy `yaml2json.sh`**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/yaml2json.sh \
   ~/.claude/skills/BugBountyHunter-v4/lib/yaml2json.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/yaml2json.sh
```

- [ ] **Step 2: Copy `validate-state-schema.sh`**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/validate-state-schema.sh \
   ~/.claude/skills/BugBountyHunter-v4/lib/validate-state-schema.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/validate-state-schema.sh
```

- [ ] **Step 3: Smoke-test yaml2json**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/yaml2json.sh \
  ~/.claude/skills/BugBountyHunter-v4/config/ArtifactMatrix.yaml | head -5
```

Expected: JSON output starting with `{`.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/{yaml2json,validate-state-schema}.sh \
   skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/ && \
git commit -m "feat(v4): port yaml2json and validate-state-schema from v3"
```

---

### Task 1.17: Phase 1 verification

**Files:** (verification only)

- [ ] **Step 1: All Phase 1 smoke tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
bash tests/smoke/test_finding_schema.sh && \
bash tests/smoke/test_validate_playbook.sh
```

Expected: both `ALL PASS`.

- [ ] **Step 2: All KB playbooks validate**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh \
  --all ~/Documents/BugBountyKB/
echo "exit=$?"
```

Expected: 2 OK lines (xss.md, idor.md), exit=0.

- [ ] **Step 3: KB git log clean**

```bash
cd ~/Documents/BugBountyKB && git log --oneline
```

Expected: ~11 commits, all conventional-style.

- [ ] **Step 4: Project repo git log clean**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && git log --oneline -10
```

Expected: 4-5 new v4 commits on top of `bc494f6`.

**Phase 1 complete when:**

- KB at `~/Documents/BugBountyKB/` has agent-operating-manual, 5
  checklists, taxonomy, 3 templates, curation rules, end-to-end
  workflow, seed hackerone-precedents, CVE anchors stub, README.
- 2 seed playbooks (XSS + IDOR) with full Coverage Checklists pass
  `validate-playbook.sh`.
- Skill at `~/.claude/skills/BugBountyHunter-v4/` has SKILL.md
  skeleton, `config/finding-schema.json` with passing tests,
  `lib/validate-playbook.sh` with 4 passing fixture tests, ported
  ArtifactMatrix + PublicSafeList + yaml2json + validate-state-schema.
- Project repo tracks v4 mirror under `skills/BugBountyHunter-v4/`.

---

## Phase 2 — Orchestrator (TypeScript state machine)

Build `lib/orchestrator.ts` — the state machine that tracks the 8-phase pipeline, persists engagement state, and exposes `--resume`, `--status`, `--advance`, `--add-finding` CLI commands. Replaces v3's shell-script-orchestrated flow.

### Task 2.1: Bun project init + types module

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/types.ts`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/lib/state-types.test.ts`

- [ ] **Step 1: Initialize Bun deps**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun install
```

Expected: creates `bun.lockb`, installs `@types/bun`.

- [ ] **Step 2: Write the failing types test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/lib/state-types.test.ts`:

```typescript
import { describe, expect, test } from "bun:test";
import { PHASES, type HuntState, type PhaseName } from "../../lib/types";

describe("HuntState types", () => {
  test("PHASES enumerates 11 phases in pipeline order", () => {
    expect(PHASES).toEqual([
      "PHASE_0_SCOPE",
      "PHASE_1A_PASSIVE_RECON",
      "PHASE_1B_AUTH",
      "PHASE_1C_ACTIVE_RECON",
      "PHASE_1D_APPREVIEW",
      "PHASE_2_ATTACK",
      "PHASE_2_5_RECONCILE",
      "PHASE_2_9_GATE",
      "PHASE_3_DEBATE",
      "PHASE_3_5_CURATOR",
      "PHASE_4_REPORT",
    ]);
  });

  test("HuntState requires required fields", () => {
    const sample: HuntState = {
      engagementId: "pentest-test",
      target: "example.com",
      mode: "bounty",
      workdir: "/tmp/pentest-test",
      startedAt: "2026-05-23T00:00:00Z",
      lastUpdated: "2026-05-23T00:00:00Z",
      currentPhase: "PHASE_0_SCOPE",
      phases: {} as Record<PhaseName, any>,
      totalFindings: 0,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    };
    expect(sample.engagementId).toBe("pentest-test");
  });
});
```

- [ ] **Step 3: Run test, confirm it fails**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/state-types.test.ts
```

Expected: FAIL — `types.ts` doesn't exist.

- [ ] **Step 4: Write `lib/types.ts`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/types.ts`:

```typescript
export const PHASES = [
  "PHASE_0_SCOPE",
  "PHASE_1A_PASSIVE_RECON",
  "PHASE_1B_AUTH",
  "PHASE_1C_ACTIVE_RECON",
  "PHASE_1D_APPREVIEW",
  "PHASE_2_ATTACK",
  "PHASE_2_5_RECONCILE",
  "PHASE_2_9_GATE",
  "PHASE_3_DEBATE",
  "PHASE_3_5_CURATOR",
  "PHASE_4_REPORT",
] as const;

export type PhaseName = (typeof PHASES)[number];

export type PhaseStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped";

export type HuntMode = "bounty" | "pentest" | "comprehensive";

export interface PhaseState {
  name: PhaseName;
  status: PhaseStatus;
  startTime: string | null;
  endTime: string | null;
  findingsCount: number;
  error: string | null;
  retryCount: number;
}

export interface FindingSummary {
  id: string;
  severity: string;
  class: string;
  techniqueId: string;
  title: string;
  timestamp: string;
}

export interface HuntState {
  engagementId: string;
  target: string;
  mode: HuntMode;
  workdir: string;
  startedAt: string;
  lastUpdated: string;
  currentPhase: PhaseName;
  phases: Record<PhaseName, PhaseState>;
  totalFindings: number;
  findings?: FindingSummary[];
  kbPath: string;
  kbVersion?: string;
}
```

- [ ] **Step 5: Run test, confirm it passes**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/state-types.test.ts
```

Expected: PASS (2 tests).

- [ ] **Step 6: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/{package.json,bun.lockb} skills/BugBountyHunter-v4/ 2>/dev/null; \
cp ~/.claude/skills/BugBountyHunter-v4/lib/types.ts skills/BugBountyHunter-v4/lib/ && \
mkdir -p skills/BugBountyHunter-v4/tests/lib && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/lib/state-types.test.ts skills/BugBountyHunter-v4/tests/lib/ && \
git add skills/BugBountyHunter-v4/{package.json,lib/types.ts,tests/lib/} && \
git commit -m "feat(v4): add HuntState types + PHASES enum"
```

---

### Task 2.2: State machine functions (create / load / save / advance / fail)

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/lib/state-machine.test.ts`

- [ ] **Step 1: Write the failing test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/lib/state-machine.test.ts`:

```typescript
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { rmSync, existsSync } from "fs";
import {
  createHuntState,
  loadState,
  saveState,
  advancePhase,
  failPhase,
} from "../../lib/state-machine";

const TEST_DIR = "/tmp/bbh-v4-test-engagement";

beforeEach(() => {
  if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true });
});

afterEach(() => {
  if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true });
});

describe("state machine", () => {
  test("createHuntState initializes all 11 phases as pending", async () => {
    const state = await createHuntState({
      target: "example.com",
      mode: "bounty",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    expect(state.currentPhase).toBe("PHASE_0_SCOPE");
    expect(state.phases.PHASE_0_SCOPE.status).toBe("running");
    expect(state.phases.PHASE_1A_PASSIVE_RECON.status).toBe("pending");
    expect(state.phases.PHASE_4_REPORT.status).toBe("pending");
  });

  test("saveState + loadState roundtrip preserves state", async () => {
    const state = await createHuntState({
      target: "example.com",
      mode: "bounty",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    state.totalFindings = 3;
    await saveState(state);
    const loaded = await loadState(TEST_DIR);
    expect(loaded?.engagementId).toBe(state.engagementId);
    expect(loaded?.totalFindings).toBe(3);
  });

  test("advancePhase moves currentPhase forward and marks prior completed", async () => {
    const state = await createHuntState({
      target: "example.com",
      mode: "bounty",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    const after = await advancePhase(state);
    expect(after.currentPhase).toBe("PHASE_1A_PASSIVE_RECON");
    expect(after.phases.PHASE_0_SCOPE.status).toBe("completed");
    expect(after.phases.PHASE_1A_PASSIVE_RECON.status).toBe("running");
  });

  test("failPhase retries up to maxRetries then advances", async () => {
    const state = await createHuntState({
      target: "example.com",
      mode: "bounty",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    const r1 = await failPhase(state, "test error 1");
    expect(r1.phases.PHASE_0_SCOPE.status).toBe("running"); // retry
    expect(r1.phases.PHASE_0_SCOPE.retryCount).toBe(1);

    const r2 = await failPhase(r1, "test error 2");
    expect(r2.currentPhase).toBe("PHASE_1A_PASSIVE_RECON"); // advanced after maxRetries=1
    expect(r2.phases.PHASE_0_SCOPE.status).toBe("failed");
  });
});
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/state-machine.test.ts
```

Expected: FAIL — `state-machine.ts` doesn't exist.

- [ ] **Step 3: Write `lib/state-machine.ts`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts`:

```typescript
import { mkdirSync, existsSync } from "fs";
import { PHASES, type HuntMode, type HuntState, type PhaseName, type PhaseState } from "./types";

const MAX_RETRIES: Record<HuntMode, number> = {
  bounty: 1,
  pentest: 2,
  comprehensive: 2,
};

export interface CreateOpts {
  target: string;
  mode: HuntMode;
  workdir: string;
  kbPath: string;
}

function initialPhases(): Record<PhaseName, PhaseState> {
  const phases = {} as Record<PhaseName, PhaseState>;
  for (const name of PHASES) {
    phases[name] = {
      name,
      status: "pending",
      startTime: null,
      endTime: null,
      findingsCount: 0,
      error: null,
      retryCount: 0,
    };
  }
  return phases;
}

function statePath(workdir: string): string {
  return `${workdir}/state.json`;
}

async function logEvent(workdir: string, event: Record<string, unknown>): Promise<void> {
  const path = `${workdir}/events.jsonl`;
  const line = JSON.stringify({ ...event, ts: new Date().toISOString() }) + "\n";
  const file = Bun.file(path);
  const existing = (await file.exists()) ? await file.text() : "";
  await Bun.write(path, existing + line);
}

export async function createHuntState(opts: CreateOpts): Promise<HuntState> {
  if (!existsSync(opts.workdir)) {
    mkdirSync(opts.workdir, { recursive: true });
  }
  const now = new Date().toISOString();
  const id = `pentest-${Date.now().toString(36)}`;
  const phases = initialPhases();
  phases.PHASE_0_SCOPE.status = "running";
  phases.PHASE_0_SCOPE.startTime = now;

  const kbVersion = await readKbVersion(opts.kbPath);

  const state: HuntState = {
    engagementId: id,
    target: opts.target,
    mode: opts.mode,
    workdir: opts.workdir,
    startedAt: now,
    lastUpdated: now,
    currentPhase: "PHASE_0_SCOPE",
    phases,
    totalFindings: 0,
    findings: [],
    kbPath: opts.kbPath,
    kbVersion,
  };
  await saveState(state);
  await logEvent(opts.workdir, { event: "CREATED", id, target: opts.target, mode: opts.mode });
  return state;
}

async function readKbVersion(kbPath: string): Promise<string | undefined> {
  const f = Bun.file(`${kbPath}/VERSION`);
  if (!(await f.exists())) return undefined;
  return (await f.text()).trim();
}

export async function loadState(workdir: string): Promise<HuntState | null> {
  const f = Bun.file(statePath(workdir));
  if (!(await f.exists())) return null;
  return JSON.parse(await f.text()) as HuntState;
}

export async function saveState(state: HuntState): Promise<void> {
  state.lastUpdated = new Date().toISOString();
  await Bun.write(statePath(state.workdir), JSON.stringify(state, null, 2));
}

export async function advancePhase(state: HuntState): Promise<HuntState> {
  const idx = PHASES.indexOf(state.currentPhase);
  if (idx < 0) throw new Error(`unknown phase ${state.currentPhase}`);
  const now = new Date().toISOString();

  const cur = state.phases[state.currentPhase];
  cur.status = "completed";
  cur.endTime = now;

  let nextIdx = idx + 1;
  while (nextIdx < PHASES.length && state.phases[PHASES[nextIdx]].status === "skipped") {
    nextIdx++;
  }
  if (nextIdx >= PHASES.length) {
    await logEvent(state.workdir, { event: "COMPLETE", totalFindings: state.totalFindings });
    await saveState(state);
    return state;
  }

  const next = PHASES[nextIdx];
  state.currentPhase = next;
  state.phases[next].status = "running";
  state.phases[next].startTime = now;

  await logEvent(state.workdir, { event: "ADVANCE", from: PHASES[idx], to: next });
  await saveState(state);
  return state;
}

export async function failPhase(state: HuntState, error: string): Promise<HuntState> {
  const phase = state.phases[state.currentPhase];
  phase.retryCount += 1;
  const limit = MAX_RETRIES[state.mode];

  if (phase.retryCount <= limit) {
    phase.status = "running";
    phase.error = `Retry ${phase.retryCount}: ${error}`;
    await logEvent(state.workdir, {
      event: "RETRY",
      phase: state.currentPhase,
      attempt: phase.retryCount,
      error,
    });
    await saveState(state);
    return state;
  }

  phase.status = "failed";
  phase.endTime = new Date().toISOString();
  phase.error = error;
  await logEvent(state.workdir, { event: "FAILED", phase: state.currentPhase, error });
  return await advancePhase(state);
}
```

- [ ] **Step 4: Run test, confirm it passes**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/state-machine.test.ts
```

Expected: PASS (4 tests).

- [ ] **Step 5: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/lib/state-machine.test.ts skills/BugBountyHunter-v4/tests/lib/ && \
git add skills/BugBountyHunter-v4/{lib/state-machine.ts,tests/lib/state-machine.test.ts} && \
git commit -m "feat(v4): add state machine (create/load/save/advance/fail with retry)"
```

---

### Task 2.3: addFinding + status renderer

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts` (add `addFinding`, `renderStatus`)
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/lib/finding-status.test.ts`

- [ ] **Step 1: Write the failing test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/lib/finding-status.test.ts`:

```typescript
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { rmSync, existsSync } from "fs";
import { createHuntState, addFinding, renderStatus } from "../../lib/state-machine";

const TEST_DIR = "/tmp/bbh-v4-test-finding";

beforeEach(() => { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true }); });
afterEach(() => { if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true }); });

describe("addFinding + renderStatus", () => {
  test("addFinding increments counters and persists summary", async () => {
    const state = await createHuntState({
      target: "ex.com", mode: "bounty",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    const after = await addFinding(state, {
      class: "xss",
      techniqueId: "T-XSS-01",
      severity: "P2",
      title: "Reflected XSS in /search",
    });
    expect(after.totalFindings).toBe(1);
    expect(after.findings?.[0].id).toBe("F-001");
    expect(after.phases.PHASE_0_SCOPE.findingsCount).toBe(1);
  });

  test("renderStatus produces multi-line summary", async () => {
    const state = await createHuntState({
      target: "ex.com", mode: "pentest",
      workdir: TEST_DIR,
      kbPath: "/home/adlt/Documents/BugBountyKB",
    });
    const rendered = renderStatus(state);
    expect(rendered).toContain("ex.com");
    expect(rendered).toContain("PHASE_0_SCOPE");
    expect(rendered).toContain("pentest");
  });
});
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/finding-status.test.ts
```

Expected: FAIL — `addFinding` / `renderStatus` not exported.

- [ ] **Step 3: Append to `lib/state-machine.ts`**

Append the following at the bottom of `~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts`:

```typescript
export interface FindingInput {
  class: string;
  techniqueId: string;
  severity: string;
  title: string;
}

export async function addFinding(state: HuntState, f: FindingInput): Promise<HuntState> {
  state.findings ??= [];
  const id = `F-${String(state.totalFindings + 1).padStart(3, "0")}`;
  state.findings.push({
    id,
    severity: f.severity,
    class: f.class,
    techniqueId: f.techniqueId,
    title: f.title,
    timestamp: new Date().toISOString(),
  });
  state.totalFindings += 1;
  state.phases[state.currentPhase].findingsCount += 1;
  await logEvent(state.workdir, { event: "FINDING_ADDED", id, ...f });
  await saveState(state);
  return state;
}

export function renderStatus(state: HuntState): string {
  const elapsedMs = Date.now() - new Date(state.startedAt).getTime();
  const elapsedMin = Math.floor(elapsedMs / 60000);
  const lines: string[] = [];
  const sep = "═".repeat(70);
  lines.push(sep);
  lines.push(`  ENGAGEMENT: ${state.target}  [${state.engagementId}]`);
  lines.push(`  Mode: ${state.mode.toUpperCase()}  Elapsed: ${elapsedMin}m  Findings: ${state.totalFindings}`);
  lines.push(`  KB: ${state.kbPath}  (v${state.kbVersion ?? "unknown"})`);
  lines.push(sep);
  for (const name of PHASES) {
    const p = state.phases[name];
    const icon = p.status === "completed" ? "[OK]"
      : p.status === "running" ? "[>>]"
      : p.status === "failed" ? "[!!]"
      : p.status === "skipped" ? "[--]"
      : "[  ]";
    const dur = p.startTime && p.endTime
      ? `${Math.round((new Date(p.endTime).getTime() - new Date(p.startTime).getTime()) / 1000)}s`
      : p.startTime ? "running..." : "";
    const findings = p.findingsCount > 0 ? ` (${p.findingsCount} findings)` : "";
    const err = p.error ? ` ERR: ${p.error.slice(0, 50)}` : "";
    lines.push(`  ${icon} ${name.padEnd(28)} ${dur.padEnd(12)}${findings}${err}`);
  }
  if (state.findings && state.findings.length > 0) {
    lines.push("");
    lines.push("  FINDINGS:");
    for (const f of state.findings.slice(-10)) {
      lines.push(`    ${f.id}  [${f.severity}]  ${f.class}/${f.techniqueId}: ${f.title}`);
    }
  }
  lines.push(sep);
  return lines.join("\n");
}
```

- [ ] **Step 4: Run test, confirm it passes**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test tests/lib/finding-status.test.ts
```

Expected: PASS (2 tests).

- [ ] **Step 5: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/state-machine.ts skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/lib/finding-status.test.ts skills/BugBountyHunter-v4/tests/lib/ && \
git add skills/BugBountyHunter-v4/{lib,tests} && \
git commit -m "feat(v4): add addFinding and renderStatus to state machine"
```

---

### Task 2.4: CLI entrypoint with `--resume`, `--status`, `--advance`, `--add-finding`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/orchestrator.ts`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh`

- [ ] **Step 1: Write the failing smoke test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ORCH="${SKILL_DIR}/lib/orchestrator.ts"
WORK="/tmp/bbh-v4-cli-test"
KB="/home/adlt/Documents/BugBountyKB"

rm -rf "$WORK"

echo "--- T1: --create initializes engagement ---"
bun "$ORCH" --create --target "example.com" --mode bounty --workdir "$WORK" --kb "$KB" || { echo "FAIL"; exit 1; }
[ -f "${WORK}/state.json" ] || { echo "FAIL: state.json not created"; exit 1; }

echo "--- T2: --status prints summary ---"
out=$(bun "$ORCH" --status --workdir "$WORK")
echo "$out" | grep -q "example.com" || { echo "FAIL: status missing target"; exit 1; }
echo "$out" | grep -q "PHASE_0_SCOPE" || { echo "FAIL: status missing phase"; exit 1; }

echo "--- T3: --advance moves to next phase ---"
bun "$ORCH" --advance --workdir "$WORK"
out=$(bun "$ORCH" --status --workdir "$WORK")
echo "$out" | grep -q "\[OK\] PHASE_0_SCOPE" || { echo "FAIL: phase 0 not marked complete"; exit 1; }

echo "--- T4: --add-finding increments counters ---"
bun "$ORCH" --add-finding \
  --workdir "$WORK" \
  --finding-json '{"class":"xss","techniqueId":"T-XSS-01","severity":"P2","title":"Reflected XSS"}'
out=$(bun "$ORCH" --status --workdir "$WORK")
echo "$out" | grep -q "Findings: 1" || { echo "FAIL: finding not counted"; exit 1; }

echo "--- T5: --resume produces same state ---"
out2=$(bun "$ORCH" --status --workdir "$WORK")
[ "$out" = "$out2" ] || { echo "WARN: status differs across calls (timestamp drift OK)"; }

echo "ALL PASS"
rm -rf "$WORK"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh
```

Expected: FAIL — `orchestrator.ts` doesn't exist.

- [ ] **Step 3: Write `lib/orchestrator.ts`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/orchestrator.ts`:

```typescript
#!/usr/bin/env bun
import { parseArgs } from "util";
import {
  createHuntState,
  loadState,
  saveState,
  advancePhase,
  failPhase,
  addFinding,
  renderStatus,
  type FindingInput,
} from "./state-machine";
import type { HuntMode } from "./types";

const { values } = parseArgs({
  args: Bun.argv.slice(2),
  options: {
    create: { type: "boolean", default: false },
    resume: { type: "boolean", default: false },
    status: { type: "boolean", default: false },
    advance: { type: "boolean", default: false },
    fail: { type: "string" },
    "add-finding": { type: "boolean", default: false },
    "finding-json": { type: "string" },
    target: { type: "string" },
    mode: { type: "string", default: "bounty" },
    workdir: { type: "string" },
    kb: { type: "string", default: `${process.env.HOME}/Documents/BugBountyKB` },
  },
  strict: false,
});

function fail(msg: string): never {
  console.error(`[orchestrator] ${msg}`);
  process.exit(1);
}

async function main() {
  if (values.create) {
    if (!values.target) fail("--create requires --target");
    if (!values.workdir) fail("--create requires --workdir");
    const state = await createHuntState({
      target: values.target,
      mode: (values.mode as HuntMode) ?? "bounty",
      workdir: values.workdir,
      kbPath: values.kb!,
    });
    console.log(`[create] engagement ${state.engagementId} → ${state.workdir}`);
    return;
  }

  if (!values.workdir) fail("missing --workdir");
  const state = await loadState(values.workdir);
  if (!state) fail(`no state.json at ${values.workdir}`);

  if (values.status || values.resume) {
    console.log(renderStatus(state));
    return;
  }

  if (values.advance) {
    const after = await advancePhase(state);
    console.log(`[advance] ${state.currentPhase} → ${after.currentPhase}`);
    return;
  }

  if (values.fail) {
    const after = await failPhase(state, values.fail);
    console.log(`[fail] phase=${state.currentPhase} retryCount=${after.phases[state.currentPhase].retryCount}`);
    return;
  }

  if (values["add-finding"]) {
    if (!values["finding-json"]) fail("--add-finding requires --finding-json");
    const f = JSON.parse(values["finding-json"]) as FindingInput;
    const after = await addFinding(state, f);
    const latest = after.findings?.[after.findings.length - 1];
    console.log(`[finding] ${latest?.id} added`);
    return;
  }

  console.log("Usage:");
  console.log("  orchestrator.ts --create --target URL --mode MODE --workdir DIR [--kb DIR]");
  console.log("  orchestrator.ts --status   --workdir DIR");
  console.log("  orchestrator.ts --resume   --workdir DIR");
  console.log("  orchestrator.ts --advance  --workdir DIR");
  console.log("  orchestrator.ts --fail 'reason' --workdir DIR");
  console.log("  orchestrator.ts --add-finding --workdir DIR --finding-json '{...}'");
}

main().catch((e) => fail(`error: ${e instanceof Error ? e.message : String(e)}`));
```

- [ ] **Step 4: Make executable, run test, confirm it passes**

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/orchestrator.ts
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh
```

Expected: T1-T5 pass, `ALL PASS`.

- [ ] **Step 5: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/orchestrator.ts skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_orchestrator_cli.sh skills/BugBountyHunter-v4/tests/smoke/ && \
git add skills/BugBountyHunter-v4/{lib/orchestrator.ts,tests/smoke/test_orchestrator_cli.sh} && \
git commit -m "feat(v4): add orchestrator.ts CLI with create/status/advance/fail/add-finding"
```

---

### Task 2.5: Phase 2 verification

- [ ] **Step 1: All unit tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test
```

Expected: 8 tests pass across 3 test files.

- [ ] **Step 2: All smoke tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
bash tests/smoke/test_finding_schema.sh && \
bash tests/smoke/test_validate_playbook.sh && \
bash tests/smoke/test_orchestrator_cli.sh
```

Expected: 3 `ALL PASS`.

- [ ] **Step 3: Project repo log clean**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && git log --oneline -10
```

Expected: 4 new commits beyond Phase 1.

**Phase 2 complete when:**

- `lib/types.ts`, `lib/state-machine.ts`, `lib/orchestrator.ts` all
  implemented with passing tests.
- `bun test` passes 8 tests.
- CLI smoke test exercises create / status / advance / add-finding /
  resume in a real `/tmp/bbh-v4-cli-test/` engagement directory.
- No regressions: Phase 1 smoke tests still pass.

---

## Phase 3 — Recon → Attack pipeline

Port v3 recon agents (with R3 emitting `recon.capabilities`), port v3 auth-acquire + background helpers, write the canonical XSSAgent.md attack executor, clone to IDORAgent.md, write `reconcile-coverage.sh` (Phase 2.5 NEW critical infra), and wire SKILL.md Phase 0 → 2.5. End-to-end recon→attack→reconcile works on a synthetic target.

### Task 3.1: Port recon agents R1, R2, R4 (mechanical)

These three port mostly unchanged from v3 — only the output contract needs updating to match `config/finding-schema.json`.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/recon-r1-assets.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/recon-r2-content.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/recon-r4-js-analysis.md`

- [ ] **Step 1: Copy R1, R2, R4 from v3**

```bash
for agent in recon-r1-assets recon-r2-content recon-r4-js-analysis; do
  cp ~/.claude/skills/BugBountyHunter-v3-experimental/AgentPrompts/${agent}.md \
     ~/.claude/skills/BugBountyHunter-v4/Agents/${agent}.md
done
```

- [ ] **Step 2: Update each prompt's path references and contract**

For each of the three ported files, make these search-and-replace edits:

In each file, replace these strings literally:

| Find | Replace |
|------|---------|
| `/tmp/pentest-{{ID}}/state.json` | `{{WORKDIR}}/state.json` |
| `/tmp/pentest-{{ID}}/scope.yaml` | `{{WORKDIR}}/scope.yaml` |
| `/tmp/pentest-{{ID}}/agents/` | `{{WORKDIR}}/agents/` |
| `/tmp/pentest-{{ID}}/scope-allowlist.txt` | `{{WORKDIR}}/scope-allowlist.txt` |
| `~/.claude/skills/Security/KnowledgeBase/broker.py` | (delete the entire line — LightRAG references retired in v4) |
| `~/.claude/skills/Security/KnowledgeBase/` | `~/Documents/BugBountyKB/` |
| `data/HackerOnePrecedents.jsonl` | `~/Documents/BugBountyKB/references/hackerone-precedents.jsonl` |

Append the following frontmatter to the top of each file (above the existing `# Agent` header):

```yaml
---
class: recon
playbook: null
model: sonnet
mandate: Active authenticated recon
---

```

- [ ] **Step 3: Verify the references are clean**

```bash
for agent in recon-r1-assets recon-r2-content recon-r4-js-analysis; do
  echo "=== $agent ==="
  grep -nE "(pentest-\{\{ID\}\}|broker\.py|HackerOnePrecedents\.jsonl)" \
    ~/.claude/skills/BugBountyHunter-v4/Agents/${agent}.md && echo "STALE REFS — FIX" || echo "OK"
done
```

Expected: 3 `OK` lines.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
mkdir -p skills/BugBountyHunter-v4/Agents && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/recon-r{1,2,4}*.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/ && \
git commit -m "feat(v4): port recon agents R1, R2, R4 from v3 (paths + LightRAG retired)"
```

---

### Task 3.2: Port R3 with `recon.capabilities` emission (modified)

R3 (fingerprinting) gains a NEW responsibility in v4: emit a structured `recon.capabilities` block in `state.json.recon.capabilities` that the orchestrator uses to evaluate `applies_when` / `mandatory.when:` conditions on Coverage Checklist items.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md`

- [ ] **Step 1: Copy R3 from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/AgentPrompts/recon-r3-fingerprint.md \
   ~/.claude/skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md
```

- [ ] **Step 2: Apply the same global path/contract edits as Task 3.1 Step 2**

Use the same Find/Replace table from Task 3.1 Step 2 on
`~/.claude/skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md`.

Append the same frontmatter (same `class: recon, model: sonnet`).

- [ ] **Step 3: Add the NEW capabilities-emission section**

Append the following section to the END of `recon-r3-fingerprint.md`:

````markdown
## NEW in v4 — Capability flag emission

You MUST emit `recon.capabilities` as a structured block in your output.
This block drives `applies_when` / `mandatory.when:` evaluation in every
attack agent's Coverage Checklist.

For each capability below, determine `true` / `false` from the recon
data you gathered:

```yaml
capabilities:
  # endpoint shape
  has_query_param_endpoints: <bool>     # endpoints accept ?key=value
  has_numeric_id_endpoints: <bool>      # paths like /api/users/123
  has_uuid_endpoints: <bool>            # paths with UUIDs
  has_composite_key_endpoints: <bool>   # /orgs/{org}/users/{user}
  has_versioned_api: <bool>             # /api/v1/, /api/v2/
  has_writable_json_endpoints: <bool>   # POST/PUT/PATCH accepting JSON
  has_writable_endpoints: <bool>        # any writeable endpoint
  has_json_endpoints: <bool>            # any endpoint serving JSON

  # auth / identity
  has_session_auth: <bool>
  has_jwt_auth: <bool>
  has_oauth: <bool>

  # rendering / templating
  has_user_profile_fields: <bool>
  has_user_generated_content: <bool>
  has_client_side_routing: <bool>
  has_postmessage_handlers: <bool>
  has_markdown_render: <bool>
  has_dompurify: <bool>
  has_svg_upload: <bool>
  has_inline_pdf: <bool>
  has_react_or_vue: <bool>
  angular_version_lt_1_6: <bool>
  has_template_engine: <bool>

  # API shapes
  graphql: <bool>
  websocket: <bool>

  # defenses
  waf_detected: <bool>
  waf_type: <"akamai" | "cloudflare" | "imperva" | "aws_waf" | null>
  csp_has_unsafe_eval_or_unsafe_inline: <bool>
```

Emit this block as part of your final JSON output under the
`capabilities` key. The orchestrator writes it to
`state.json.recon.capabilities`.

How to determine each:

| Capability | Detection signal |
|------------|------------------|
| `has_query_param_endpoints` | Any URL with `?key=value` observed in recon |
| `has_numeric_id_endpoints` | Regex match `/[a-z]+/[0-9]+` in discovered_endpoints |
| `has_uuid_endpoints` | Regex match UUIDv4 pattern in discovered_endpoints |
| `has_composite_key_endpoints` | Two path-segment-IDs in same URL |
| `has_versioned_api` | URLs containing `/v[0-9]/` |
| `has_writable_json_endpoints` | POST/PUT/PATCH endpoint with `application/json` request body |
| `has_writable_endpoints` | Any non-GET/HEAD/OPTIONS endpoint |
| `has_json_endpoints` | Any endpoint with `Content-Type: application/json` response |
| `has_session_auth` | Set-Cookie with session-like name in auth response |
| `has_jwt_auth` | `Authorization: Bearer <jwt-shape>` observed |
| `has_oauth` | `/oauth/` paths OR `/.well-known/openid-configuration` |
| `has_user_profile_fields` | Discovered endpoint matching `/users/{id}/profile` or PUT to profile fields |
| `has_user_generated_content` | Endpoints accepting `comment` / `message` / `post` / `note` |
| `has_client_side_routing` | SPA frameworks detected (React Router, Vue Router, Angular Router) |
| `has_postmessage_handlers` | JS source contains `addEventListener('message'` or `window.postMessage` |
| `has_markdown_render` | JS deps include marked / remark / markdown-it; OR Content rendered with `text/markdown` source |
| `has_dompurify` | JS deps include DOMPurify (in package manifest or source map) |
| `has_svg_upload` | Upload endpoint accepting `image/svg+xml` |
| `has_inline_pdf` | Inline PDF rendering via PDF.js detected in source |
| `has_react_or_vue` | React or Vue detected in tech stack |
| `angular_version_lt_1_6` | AngularJS 1.x detected with version <1.6 in source map |
| `has_template_engine` | Server-side template engine in fingerprint (Jinja / ERB / Twig / Handlebars / Pug / etc.) |
| `graphql` | `/graphql` endpoint OR `application/graphql` content-type |
| `websocket` | WSS URL OR `Sec-WebSocket-Key` header observed |
| `waf_detected` | WAF headers/cookies detected (see Task 3.7 WAF Detection logic for canonical signatures) |
| `waf_type` | one of: akamai / cloudflare / imperva / aws_waf / null |
| `csp_has_unsafe_eval_or_unsafe_inline` | `Content-Security-Policy` header includes `'unsafe-eval'` or `'unsafe-inline'` |

Be conservative: if uncertain, emit `false`. False-negatives mean an attack agent
treats a `when:`-conditional item as N/A; the orchestrator's reconciliation will
NOT raise that as a gap. False-positives cause attack agents to attempt
techniques that have no matching surface, wasting budget.
````

- [ ] **Step 4: Verify the section was appended**

```bash
grep -c "Capability flag emission" ~/.claude/skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md
```

Expected: `1`.

- [ ] **Step 5: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/recon-r3-fingerprint.md && \
git commit -m "feat(v4): port R3 with recon.capabilities emission for applies_when evaluation"
```

---

### Task 3.3: Port auth-acquire agent

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/auth-acquire.md`

- [ ] **Step 1: Copy from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/AgentPrompts/auth-acquire.md \
   ~/.claude/skills/BugBountyHunter-v4/Agents/auth-acquire.md
```

- [ ] **Step 2: Apply path/contract edits**

Apply the same Find/Replace table from Task 3.1 Step 2.

Append the frontmatter:

```yaml
---
class: auth
playbook: null
model: opus
mandate: Establish authenticated session before recon/attack phases
---

```

(Note: auth-acquire uses Opus per spec Section 6 — it gates the pipeline.)

- [ ] **Step 3: Verify**

```bash
grep -nE "(pentest-\{\{ID\}\}|broker\.py)" ~/.claude/skills/BugBountyHunter-v4/Agents/auth-acquire.md && echo "STALE" || echo "OK"
head -5 ~/.claude/skills/BugBountyHunter-v4/Agents/auth-acquire.md | grep -q "model: opus" && echo "FRONTMATTER OK" || echo "FRONTMATTER MISSING"
```

Expected: `OK`, `FRONTMATTER OK`.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/auth-acquire.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/auth-acquire.md && \
git commit -m "feat(v4): port auth-acquire agent (Opus, paths updated)"
```

---

### Task 3.4: Port background auth helpers

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/refresh-monitor.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/session-warmer.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/stale-watcher.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/detect-account-mode.sh`

- [ ] **Step 1: Copy all four scripts**

```bash
for s in refresh-monitor session-warmer stale-watcher detect-account-mode; do
  cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/${s}.sh \
     ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
  chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
done
```

- [ ] **Step 2: Update path references in each script**

For each of the 4 scripts, replace `/tmp/pentest-{{ID}}/` and similar v3 paths with `${WORKDIR}/`. These scripts already accept `WORKDIR` env var in v3; verify with:

```bash
for s in refresh-monitor session-warmer stale-watcher detect-account-mode; do
  echo "=== $s ==="
  grep -n 'WORKDIR' ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh | head -3
done
```

Expected: each script references `${WORKDIR}` (the v3 scripts were already parameterized).

If any script has a hard-coded `/tmp/pentest-{{ID}}/` path, replace it with `${WORKDIR}/` in-place via `sed`:

```bash
for s in refresh-monitor session-warmer stale-watcher detect-account-mode; do
  sed -i 's|/tmp/pentest-{{ID}}|${WORKDIR}|g' ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
done
```

- [ ] **Step 3: Smoke-test detect-account-mode against a fixture state**

```bash
WORKDIR=/tmp/test-account-mode mkdir -p "$WORKDIR"
cat > "$WORKDIR/state.json" <<'JSON'
{
  "auth": { "accounts": [ { "username": "a" }, { "username": "b" } ] }
}
JSON
WORKDIR="$WORKDIR" bash ~/.claude/skills/BugBountyHunter-v4/lib/detect-account-mode.sh
cat "$WORKDIR/pipeline-mode.json" 2>/dev/null || true
rm -rf /tmp/test-account-mode
```

Expected: `pipeline-mode.json` contains `multi_account` mode or similar.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/{refresh-monitor,session-warmer,stale-watcher,detect-account-mode}.sh \
   skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/ && \
git commit -m "feat(v4): port refresh-monitor, session-warmer, stale-watcher, detect-account-mode"
```

---

### Task 3.5: Port `phase2-merge.sh`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/phase2-merge.sh`

- [ ] **Step 1: Copy from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/phase2-merge.sh \
   ~/.claude/skills/BugBountyHunter-v4/lib/phase2-merge.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/phase2-merge.sh
```

- [ ] **Step 2: Update path references**

```bash
sed -i 's|/tmp/pentest-{{ID}}|${WORKDIR}|g' \
  ~/.claude/skills/BugBountyHunter-v4/lib/phase2-merge.sh
```

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/phase2-merge.sh skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/phase2-merge.sh && \
git commit -m "feat(v4): port phase2-merge.sh from v3"
```

---

### Task 3.6: Write canonical attack executor `Agents/XSSAgent.md`

This is THE canonical template every other attack executor follows. Authored carefully — IDOR (Task 3.7) and the 15 deferred attack executors all clone and customize this shape.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md`

- [ ] **Step 1: Write the agent**

Content for `~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md`:

````markdown
---
class: xss
playbook: ~/Documents/BugBountyKB/playbooks/xss.md
model: sonnet
mandate: Coverage Checklist exhaustion + novelty discovery for XSS
---

# XSS Attack Executor

## Step 1 — Load doctrine (mandatory, in order)

1. Read `~/Documents/BugBountyKB/agents/agent-operating-manual.md`
2. Read `~/Documents/BugBountyKB/playbooks/xss.md`
3. Read `~/Documents/BugBountyKB/checklists/evidence-quality.md`
4. Read `~/Documents/BugBountyKB/checklists/reportability.md`

If any of these files is missing, ABORT with `gap_reason: kb_unavailable`.

## Step 2 — Parse Coverage Checklist

From `~/Documents/BugBountyKB/playbooks/xss.md`, locate the
`## Coverage Checklist` section and parse the YAML block. Build your
run queue from techniques where:

- `mandatory: true` — always include
- `mandatory: { when: <expr> }` — include iff `<expr>` evaluates true
  against `{{WORKDIR}}/state.json.recon.capabilities`
- `mandatory: false` — opportunistic; include only if recon evidence
  suggests a likely match

For each `mandatory: true` technique whose `applies_when` expression
is FALSE against `state.json.recon.capabilities`, emit a `coverage[]`
entry with `attempted: false, gap_reason: "condition_not_met"`.

## Step 3 — Context (injected by orchestrator at spawn)

- `TARGET={{TARGET}}` — primary in-scope domain
- `WORKDIR={{WORKDIR}}` — `/tmp/pentest-<id>/`
- `ENGAGEMENT_ID={{ENGAGEMENT_ID}}` — for output JSON
- `AGENT_RATE={{AGENT_RATE}}` — your share of total scope rate limit
- `scope-allowlist={{WORKDIR}}/scope-allowlist.txt`
- `app_profile_hint={{APP_PROFILE_XSS_HINT}}` — priority/depth hint
  from AppReview (NOT gating)
- `recon.capabilities` from `{{WORKDIR}}/state.json.recon.capabilities`

## Step 4 — Behavioral rules (zero exceptions)

1. Validate target scope before EVERY HTTP request via the
   `check_scope` function below.
2. Respect `{{AGENT_RATE}}` requests per second.
3. Read `state.json` for auth tokens; NEVER write to it.
4. Write findings to `{{WORKDIR}}/agents/xss-results.json` AND also
   emit them in your output JSON (the orchestrator parses output
   text, not files — file is backup).
5. Browser-execution proof required for all confirmed findings
   (see `agent-operating-manual.md` Rule 6).
6. Never revoke/destroy shared auth state.
7. Do NOT assign severity. Use `confidence` per operating manual.
8. After mandatory queue, attempt novel variants and emit them as
   `proposed_additions[]`.

## Step 5 — Scope check (inject before every HTTP request)

```bash
check_scope() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
  if ! grep -xqF "$domain" {{WORKDIR}}/scope-allowlist.txt 2>/dev/null; then
    echo "[SCOPE BLOCKED] $domain is NOT in scope — request skipped" >&2
    return 1
  fi
  return 0
}
```

Call `check_scope "$URL" || continue` (or equivalent) before every curl,
dev-browser navigation, or tool command that hits an external URL.

## Step 6 — Execute mandatory queue

For each technique in your run queue:

1. Identify candidate endpoints/params from `state.json.discovered_endpoints`
   matching the technique's pattern.
2. For each candidate, craft and send the payload (use payload recipes
   from `~/Documents/BugBountyKB/payloads/xss/` if present; else
   apply doctrine from the playbook).
3. Verify browser execution via dev-browser for client-side XSS
   classes — REQUIRED for `Confirmed` verdict per Rule 6.
4. Record evidence in `{{WORKDIR}}/findings/F-A-XXX/`:
   - `request.txt` (full HTTP request)
   - `response.txt` (full HTTP response)
   - `browser-execution.png` (screenshot if applicable)
   - `notes.md` (your analysis)
5. Emit a `coverage[]` entry:

```json
{
  "id": "T-XSS-NN",
  "attempted": true,
  "evidence_artifact": "{{WORKDIR}}/findings/F-A-XXX/",
  "verdict": "exploited" | "not_exploited" | "inconclusive"
}
```

If a technique cannot be attempted (no candidate endpoints / WAF /
timeout / rate limit), emit:

```json
{
  "id": "T-XSS-NN",
  "attempted": false,
  "gap_reason": "no_matching_endpoint" | "waf_blocked" | "timeout" |
                "rate_limited" | "auth_failed" | "out_of_scope" |
                "condition_not_met"
}
```

## Step 7 — Novelty channel

After exhausting the mandatory queue, attempt creative variants the
playbook does NOT yet describe. For each genuinely novel variant
(not just a payload encoding of an existing T-ID), emit:

```json
{
  "class": "xss",
  "proposed_name": "<short name>",
  "family": "reflected | stored | dom | mxss | postmessage | markdown | template",
  "red_flags": ["<observable pattern 1>", "..."],
  "proof_targets": ["<demonstrable impact 1>", "..."],
  "fix_patterns": ["<remediation 1>", "..."],
  "evidence_artifact_path": "{{WORKDIR}}/findings/F-A-XXX/"
}
```

DO NOT propose a variant if it's just a payload encoding of an
existing technique. Curator will reject it as `VARIANT_OF` and the
proposal is wasted. Genuinely novel = different primitive, different
sink, or a new bypass class.

## Step 8 — Output contract

Your response MUST end with one fenced JSON block matching
`config/finding-schema.json`. Structure:

```json
{
  "agent_id": "xss-1",
  "class": "xss",
  "engagement_id": "{{ENGAGEMENT_ID}}",
  "coverage": [ ... ],
  "findings": [ ... ],
  "proposed_additions": [ ... ]
}
```

`findings[]` entries follow `finding-schema.json`. The
`reportability_assessment` object MUST be populated for every
finding per `~/Documents/BugBountyKB/checklists/reportability.md`
Q1-Q4.

## Step 9 — Failure modes

| Failure | Action |
|---------|--------|
| KB file missing | Emit empty coverage[] + one `proposed_additions[]` with `class=kb_error`. Orchestrator retries with `gap_reason: kb_unavailable`. |
| All endpoints WAF-blocked | Continue with techniques that work; mark blocked techniques `attempted:false, gap_reason:waf_blocked`. |
| Rate limit hit | Sleep `60/{{AGENT_RATE}}` seconds; resume. |
| Auth expired mid-run | Re-read `state.json.auth` (refresh-monitor.sh refreshes in background); retry the failed request. If still expired after 1 retry, mark remaining techniques `gap_reason:auth_failed`. |
| dev-browser unavailable | Mark client-side findings `verdict:inconclusive`; orchestrator escalates to follow-up agent with dev-browser pre-warmed. |

## Step 10 — References

- Doctrine: `~/Documents/BugBountyKB/agents/agent-operating-manual.md`
- Playbook: `~/Documents/BugBountyKB/playbooks/xss.md`
- Wire contract: `~/.claude/skills/BugBountyHunter-v4/config/finding-schema.json`
- Payloads (when available): `~/Documents/BugBountyKB/payloads/xss/`
````

- [ ] **Step 2: Verify the agent loads correctly**

```bash
wc -l ~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md
head -10 ~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md
```

Expected: ~140-180 lines, frontmatter present.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/XSSAgent.md && \
git commit -m "feat(v4): add XSSAgent.md — canonical attack executor template"
```

---

### Task 3.7: Clone XSSAgent.md → IDORAgent.md

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md`

- [ ] **Step 1: Clone XSSAgent.md**

```bash
cp ~/.claude/skills/BugBountyHunter-v4/Agents/XSSAgent.md \
   ~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md
```

- [ ] **Step 2: Apply find/replace edits**

In `~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md`, replace these strings (in this order):

| Find | Replace |
|------|---------|
| `class: xss` | `class: idor` |
| `playbook: ~/Documents/BugBountyKB/playbooks/xss.md` | `playbook: ~/Documents/BugBountyKB/playbooks/idor.md` |
| `mandate: Coverage Checklist exhaustion + novelty discovery for XSS` | `mandate: Coverage Checklist exhaustion + novelty discovery for IDOR/BOLA/BFLA` |
| `# XSS Attack Executor` | `# IDOR / BOLA / BFLA Attack Executor` |
| `playbooks/xss.md` | `playbooks/idor.md` (all occurrences) |
| `app_profile_hint={{APP_PROFILE_XSS_HINT}}` | `app_profile_hint={{APP_PROFILE_IDOR_HINT}}` |
| `xss-results.json` | `idor-results.json` |
| `T-XSS-NN` | `T-IDOR-NN` (all occurrences) |
| `Browser-execution proof required for all confirmed findings` | `Cross-account proof (two accounts) required for all confirmed findings` |
| `"family": "reflected | stored | dom | mxss | postmessage | markdown | template"` | `"family": "bola | bfla | mass_assignment | tenant_breach | path_traversal | method_override"` |
| `"agent_id": "xss-1"` | `"agent_id": "idor-1"` |
| `"class": "xss"` (in JSON) | `"class": "idor"` |
| `Payloads (when available): ~/Documents/BugBountyKB/payloads/xss/` | `Payloads (when available): ~/Documents/BugBountyKB/payloads/idor/` |

Then INSERT a new behavioral rule between the existing rule 5 and rule 6, renumbering subsequent rules:

```
6. Cross-tenant findings require TWO accounts. If
   `state.json.pipeline_mode == "UNPROVABLE_SINGLE_ACCOUNT"`, mark all
   cross-tenant T-IDs `attempted: true, verdict: inconclusive,
   gap_reason: condition_not_met` and the orchestrator's Phase 2.9 gate
   will auto-reject them.
```

Replace Step 6 instruction about "Verify browser execution via dev-browser"
with: "Verify cross-account/tenant access via Account A → Account B request flow,
recorded as a HAR or two separate request/response pairs in the evidence
directory."

- [ ] **Step 3: Verify the clone is well-formed**

```bash
head -5 ~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md
grep -c "T-XSS\|XSS Attack Executor\|class: xss" ~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md
```

Expected: frontmatter shows `class: idor`, grep returns `0` (no stale XSS references).

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/IDORAgent.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/IDORAgent.md && \
git commit -m "feat(v4): add IDORAgent.md (clone of XSSAgent template with two-account discipline)"
```

---

### Task 3.8: Write `lib/reconcile-coverage.sh` (Phase 2.5 — v1 critical)

This is the NEW infrastructure that makes Approach B work. After every attack batch, the orchestrator calls this script to verify every mandatory T-ID was attempted; gaps trigger focused follow-up agent dispatch.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/reconcile-coverage.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile/recon-capabilities.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile/agent-output-complete.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile/agent-output-gaps.json`

- [ ] **Step 1: Write the failing smoke test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${SKILL_DIR}/lib/reconcile-coverage.sh"
FIX="${SKILL_DIR}/tests/fixtures/reconcile"
KB="/home/adlt/Documents/BugBountyKB"

mkdir -p /tmp/bbh-v4-reconcile-test/agents
WORK=/tmp/bbh-v4-reconcile-test

# Stage capabilities into state.json
cat > "$WORK/state.json" <<JSON
{
  "engagement_id": "test",
  "recon": $(cat "$FIX/recon-capabilities.json")
}
JSON

echo "--- T1: complete coverage produces zero gaps ---"
cp "$FIX/agent-output-complete.json" "$WORK/agents/xss-results.json"
out=$(bash "$SCRIPT" --workdir "$WORK" --class xss --kb "$KB")
echo "$out" | grep -q "gaps=0" || { echo "FAIL: T1: $out"; exit 1; }

echo "--- T2: partial coverage produces correct gap list ---"
cp "$FIX/agent-output-gaps.json" "$WORK/agents/xss-results.json"
out=$(bash "$SCRIPT" --workdir "$WORK" --class xss --kb "$KB")
echo "$out" | grep -qE "gaps=[1-9]" || { echo "FAIL: T2: $out"; exit 1; }
echo "$out" | grep -q "T-XSS-" || { echo "FAIL: T2 missing T-IDs: $out"; exit 1; }

echo "ALL PASS"
rm -rf "$WORK"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh
```

- [ ] **Step 2: Write fixtures**

Create `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile/` directory:

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile
```

`tests/fixtures/reconcile/recon-capabilities.json` — minimal capabilities set where most XSS conditions are FALSE (so few mandatory T-IDs apply):

```json
{
  "capabilities": {
    "has_query_param_endpoints": true,
    "has_user_profile_fields": true,
    "has_user_generated_content": true,
    "has_client_side_routing": false,
    "has_postmessage_handlers": false,
    "has_markdown_render": false,
    "has_dompurify": false,
    "has_svg_upload": false,
    "has_inline_pdf": false,
    "angular_version_lt_1_6": false,
    "has_template_engine": false,
    "has_react_or_vue": false,
    "waf_detected": false,
    "csp_has_unsafe_eval_or_unsafe_inline": false,
    "has_json_endpoints": true
  }
}
```

With these capabilities, the XSS playbook's mandatory T-IDs that apply are:
- T-XSS-01 (applies_when: has_query_param_endpoints)
- T-XSS-02 (applies_when: has_user_profile_fields)
- T-XSS-03 (applies_when: has_user_generated_content)
- T-XSS-15 (applies_when: has_json_endpoints)

T-XSS-04 (client_side_routing=false), T-XSS-05 (postmessage=false), etc. — all N/A.

`tests/fixtures/reconcile/agent-output-complete.json` — agent attempted all 4 applicable:

```json
{
  "agent_id": "xss-1",
  "class": "xss",
  "engagement_id": "test",
  "coverage": [
    { "id": "T-XSS-01", "attempted": true, "evidence_artifact": "/tmp/e/F-1", "verdict": "not_exploited" },
    { "id": "T-XSS-02", "attempted": true, "evidence_artifact": "/tmp/e/F-2", "verdict": "exploited" },
    { "id": "T-XSS-03", "attempted": true, "evidence_artifact": "/tmp/e/F-3", "verdict": "not_exploited" },
    { "id": "T-XSS-15", "attempted": true, "evidence_artifact": "/tmp/e/F-4", "verdict": "not_exploited" }
  ],
  "findings": [],
  "proposed_additions": []
}
```

`tests/fixtures/reconcile/agent-output-gaps.json` — agent attempted only 2 of 4:

```json
{
  "agent_id": "xss-1",
  "class": "xss",
  "engagement_id": "test",
  "coverage": [
    { "id": "T-XSS-01", "attempted": true, "evidence_artifact": "/tmp/e/F-1", "verdict": "not_exploited" },
    { "id": "T-XSS-02", "attempted": true, "evidence_artifact": "/tmp/e/F-2", "verdict": "exploited" }
  ],
  "findings": [],
  "proposed_additions": []
}
```

- [ ] **Step 3: Run test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh
```

Expected: FAIL — `reconcile-coverage.sh` doesn't exist.

- [ ] **Step 4: Write `lib/reconcile-coverage.sh`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/reconcile-coverage.sh`:

```bash
#!/usr/bin/env bash
# reconcile-coverage.sh — Phase 2.5
# Reads the playbook for <class> from the KB, evaluates which mandatory
# T-IDs apply against state.json.recon.capabilities, then checks the
# agent's output coverage[] against the applicable set. Emits a gap
# report to stdout and writes structured JSON to ${WORKDIR}/coverage-reconcile-<class>.json.
#
# Usage:
#   reconcile-coverage.sh --workdir DIR --class <prefix-lower> --kb KB_DIR
#
# Exit codes:
#   0 — no gaps
#   1 — gaps detected (orchestrator should dispatch follow-up)
#   2 — usage / fatal error

set -euo pipefail

WORKDIR=""
CLASS=""
KB=""

while [ $# -gt 0 ]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --class)   CLASS="$2";   shift 2 ;;
    --kb)      KB="$2";      shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$WORKDIR" ] || [ -z "$CLASS" ] || [ -z "$KB" ]; then
  echo "Usage: reconcile-coverage.sh --workdir DIR --class CLASS --kb KB_DIR" >&2
  exit 2
fi

PLAYBOOK="${KB}/playbooks/${CLASS}.md"
if [ ! -f "$PLAYBOOK" ]; then
  echo "[FAIL] playbook not found: $PLAYBOOK" >&2
  exit 2
fi

STATE_JSON="${WORKDIR}/state.json"
AGENT_OUT="${WORKDIR}/agents/${CLASS}-results.json"

if [ ! -f "$STATE_JSON" ]; then
  echo "[FAIL] state.json not found at $STATE_JSON" >&2
  exit 2
fi

# Extract Coverage Checklist YAML from playbook
YAML=$(awk '
  /^## Coverage Checklist/ { in_section=1; next }
  /^## / && in_section { in_section=0 }
  in_section && /^```yaml$/ { in_block=1; next }
  in_section && /^```$/ && in_block { in_block=0; exit }
  in_block { print }
' "$PLAYBOOK")

if [ -z "$YAML" ]; then
  echo "[FAIL] no Coverage Checklist in $PLAYBOOK" >&2
  exit 2
fi

OUTFILE="${WORKDIR}/coverage-reconcile-${CLASS}.json"

python3 - "$YAML" "$STATE_JSON" "$AGENT_OUT" "$OUTFILE" "$CLASS" <<'PY'
import json, sys, yaml
from pathlib import Path

yaml_text, state_path, agent_out_path, outfile, class_name = sys.argv[1:6]
playbook = yaml.safe_load(yaml_text)
techniques = playbook.get("techniques", [])

state = json.load(open(state_path))
caps = (state.get("recon") or {}).get("capabilities") or {}

# Determine applicable mandatory techniques
def applies(tech):
    mandatory = tech.get("mandatory")
    applies_when = tech.get("applies_when")

    # mandatory: false → never required
    if mandatory is False:
        return False, "non_mandatory"

    # mandatory: { when: expr } → eval expr
    if isinstance(mandatory, dict):
        when = mandatory.get("when", "")
        return eval_expr(when, caps), f"when({when})"

    # mandatory: true with applies_when → eval applies_when
    if applies_when:
        return eval_expr(applies_when, caps), f"applies_when({applies_when})"

    # mandatory: true with no applies_when → always required
    return True, "always"

def eval_expr(expr, caps):
    # Handle two forms:
    # 1) Plain capability reference: "recon.capabilities.x"
    # 2) Comparison: "recon.capabilities.x == true" / "...== <value>"
    if not expr:
        return True
    expr = expr.strip()
    # Strip "recon.capabilities." prefix
    expr = expr.replace("recon.capabilities.", "")
    # Comparison form
    if "==" in expr:
        lhs, rhs = [s.strip() for s in expr.split("==", 1)]
        if rhs == "true":
            return bool(caps.get(lhs, False))
        if rhs == "false":
            return not bool(caps.get(lhs, False))
        # String comparison
        return str(caps.get(lhs, "")) == rhs.strip("\"'")
    # Plain reference → truthiness
    return bool(caps.get(expr, False))

applicable_mandatory = []
for t in techniques:
    ok, reason = applies(t)
    if ok:
        applicable_mandatory.append(t["id"])

# Load agent output
attempted = set()
if Path(agent_out_path).exists():
    agent = json.load(open(agent_out_path))
    for c in agent.get("coverage", []):
        if c.get("attempted") is True:
            attempted.add(c["id"])
        elif c.get("attempted") is False and c.get("gap_reason") == "condition_not_met":
            # Agent explicitly marked as N/A; count as covered
            attempted.add(c["id"])

gaps = [tid for tid in applicable_mandatory if tid not in attempted]

report = {
    "class": class_name,
    "applicable_mandatory_count": len(applicable_mandatory),
    "attempted_count": len(attempted),
    "gaps": gaps,
}
json.dump(report, open(outfile, "w"), indent=2)

print(f"class={class_name} applicable={len(applicable_mandatory)} attempted={len(attempted)} gaps={len(gaps)}")
if gaps:
    print("missing_tids: " + " ".join(gaps))
    sys.exit(1)
PY
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/reconcile-coverage.sh
```

- [ ] **Step 5: Run test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh
```

Expected: T1 `gaps=0`, T2 `gaps>=1` with `T-XSS-03` and `T-XSS-15` in missing_tids, `ALL PASS`.

- [ ] **Step 6: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/reconcile-coverage.sh skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_reconcile_coverage.sh skills/BugBountyHunter-v4/tests/smoke/ && \
mkdir -p skills/BugBountyHunter-v4/tests/fixtures/reconcile && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/reconcile/*.json skills/BugBountyHunter-v4/tests/fixtures/reconcile/ && \
git add skills/BugBountyHunter-v4/{lib/reconcile-coverage.sh,tests} && \
git commit -m "feat(v4): add reconcile-coverage.sh (Phase 2.5 gap detection) + fixtures"
```

---

### Task 3.9: Wire SKILL.md Phase 0 → 2.5

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/SKILL.md`

- [ ] **Step 1: Open SKILL.md and replace the skeleton body**

Replace the entire body of `~/.claude/skills/BugBountyHunter-v4/SKILL.md` (everything below the frontmatter) with:

````markdown
# BugBountyHunter v4 — Orchestrator

KB-driven coverage-enforced pentest orchestrator. Loads doctrine from
`~/Documents/BugBountyKB/`, dispatches per-class attack executors
(Sonnet 4.6), enforces mechanical coverage reconciliation, and runs
Advocate↔Triager↔Curator validation (Opus 4.7).

## Behavioral rules (zero exceptions)

1. Validate target scope before every HTTP request (see `check_scope`).
2. KB version mismatch produces a startup warning, not a hard fail.
3. Every phase has a gate — see Phase Gate Protocol below.
4. NEVER skip Phase 2.5 (coverage reconciliation) — it's the load-bearing primitive.
5. Sonnet 4.6 for attack/recon; Opus 4.7 for orchestration / Advocate / Triager / Curator / AppReview / auth-acquire.
6. AppProfile hypotheses set DEPTH/PRIORITY only, NOT gating.

## Engagement startup

```bash
WORKDIR=/tmp/pentest-$(date +%Y%m%d-%H%M%S)
KB=~/Documents/BugBountyKB
SKILL=~/.claude/skills/BugBountyHunter-v4

# 1. Validate the KB at startup (hard fails if any playbook is malformed)
bash "${SKILL}/lib/validate-playbook.sh" --all "${KB}" || { echo "[FATAL] KB validation failed"; exit 1; }

# 2. Compatibility check
KB_VER=$(cat "${KB}/VERSION")
SKILL_VER=$(jq -r '.version' "${SKILL}/package.json")
echo "[startup] KB=${KB_VER} Skill=${SKILL_VER}"

# 3. Create engagement
bun "${SKILL}/lib/orchestrator.ts" --create \
  --target "${TARGET}" \
  --mode "${MODE:-bounty}" \
  --workdir "${WORKDIR}" \
  --kb "${KB}"
```

## Phase 0 — Scope compliance

Parse user input (`pentest <target>` + optional flags). Build
`${WORKDIR}/scope.yaml` per
`~/Documents/BugBountyKB/checklists/target-intake.md`. Generate
`${WORKDIR}/scope-allowlist.txt`. Confirm user authorization.

Advance:

```bash
bun "${SKILL}/lib/orchestrator.ts" --advance --workdir "${WORKDIR}"
```

## Phase 1a — Passive recon

Subfinder, certificate transparency, GitHub dorks. Output to
`${WORKDIR}/passive/`. No active HTTP to in-scope targets.

## Phase 1b — Auth acquisition

Dispatch `Agents/auth-acquire.md` (Opus). After return, spawn the
matching background helper based on `auth.auth_strategy`:

```bash
case "$(jq -r '.auth.auth_strategy' ${WORKDIR}/state.json)" in
  jwt-oauth)      WORKDIR="${WORKDIR}" bash "${SKILL}/lib/refresh-monitor.sh" & ;;
  session-cookie) WORKDIR="${WORKDIR}" bash "${SKILL}/lib/session-warmer.sh" & ;;
esac
WORKDIR="${WORKDIR}" bash "${SKILL}/lib/stale-watcher.sh" &
WORKDIR="${WORKDIR}" bash "${SKILL}/lib/detect-account-mode.sh"
```

## Phase 1c — Active authenticated recon

Dispatch R1, R2, R3, R4 (Sonnet). All four return — R3 MUST emit
`state.json.recon.capabilities` per the new contract. Merge results via
`lib/phase2-merge.sh`.

## Phase 1d — AppReview (Opus, single-shot)

Dispatch `Agents/AppReviewAgent.md` (Opus). Produces `app-profile.json`
with `crown_jewels`, `flows[]`, `attack_hypotheses[]`. Hypotheses set
DEPTH/PRIORITY for downstream attack executors — NOT gating.

(See Phase 4 spec for AppReviewAgent — landed in next phase of this plan.)

## Phase 2 — Per-class attack executors

For each attack class enabled by the workflow file (`Workflows/W_HUNT_WEB.md`
at v1 dispatches XSSAgent + IDORAgent), spawn the executor as Sonnet 4.6:

```typescript
// Pseudo-spawn (orchestrator-side)
Agent({
  subagent_type: "Pentester",
  model: "sonnet",
  description: `${className} attack executor`,
  prompt: readAgentPrompt(`${SKILL}/Agents/${className}Agent.md`, templateVars),
  run_in_background: true,
})
```

Each executor emits a JSON block matching `config/finding-schema.json`.
Orchestrator parses + writes to `${WORKDIR}/agents/<class>-results.json`.

## Phase 2.5 — Coverage reconciliation (CRITICAL)

After Phase 2 batch return, for each class with an executor output:

```bash
bash "${SKILL}/lib/reconcile-coverage.sh" \
  --workdir "${WORKDIR}" --class "${CLASS}" --kb "${KB}"

if [ $? -ne 0 ]; then
  # Gaps detected — dispatch focused follow-up agent with ONLY the gap T-IDs
  # in its run queue. Max 2 follow-up rounds per class.
  # Implementation: pass `--only-tids "T-XSS-03 T-XSS-15"` in the agent
  # prompt's Step 6 instruction.
  dispatch_followup_agent "${CLASS}" "$(jq -r '.gaps[]' ${WORKDIR}/coverage-reconcile-${CLASS}.json)"
fi
```

If after 2 follow-up rounds gaps persist, append to
`${WORKDIR}/coverage-gaps.txt` with the specific reason for each
T-ID.

## Phase 2.9, 3, 3.5, 4

(Landed in subsequent plan phases — see plan Phases 5-6.)

---
````

- [ ] **Step 2: Verify**

```bash
wc -l ~/.claude/skills/BugBountyHunter-v4/SKILL.md
grep -c "Phase 2.5" ~/.claude/skills/BugBountyHunter-v4/SKILL.md
```

Expected: ~150-200 lines, multiple references to Phase 2.5.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/SKILL.md skills/BugBountyHunter-v4/ && \
git add skills/BugBountyHunter-v4/SKILL.md && \
git commit -m "feat(v4): wire SKILL.md Phase 0 → 2.5 (orchestrator + reconcile pipeline)"
```

---

### Task 3.10: Phase 3 verification

- [ ] **Step 1: All smoke tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
for t in tests/smoke/*.sh; do
  echo "=== $t ==="
  bash "$t"
done
```

Expected: 4 `ALL PASS` (finding_schema, validate_playbook, orchestrator_cli, reconcile_coverage).

- [ ] **Step 2: Unit tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test
```

Expected: 8 tests pass (types, state-machine, finding-status — same as Phase 2).

- [ ] **Step 3: Agent prompts well-formed**

```bash
for a in XSSAgent IDORAgent recon-r1-assets recon-r2-content recon-r3-fingerprint recon-r4-js-analysis auth-acquire; do
  f=~/.claude/skills/BugBountyHunter-v4/Agents/${a}.md
  if [ ! -f "$f" ]; then echo "MISSING $a"; continue; fi
  if ! head -5 "$f" | grep -q "^---"; then echo "NO FRONTMATTER $a"; continue; fi
  echo "OK $a ($(wc -l < $f) lines)"
done
```

Expected: 7 OK lines.

- [ ] **Step 4: Project repo clean**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && git status && git log --oneline -10
```

Expected: clean tree, ~10 new commits beyond Phase 2.

**Phase 3 complete when:**

- 7 agent prompts in `Agents/` (XSSAgent, IDORAgent, R1-R4, auth-acquire) with `--- ... ---` frontmatter and current path references.
- Background helpers (refresh-monitor, session-warmer, stale-watcher, detect-account-mode) ported with `${WORKDIR}` parameterization.
- `phase2-merge.sh` ported.
- `reconcile-coverage.sh` with passing fixture-driven smoke test (gaps=0 on complete, gaps>0 on partial).
- `SKILL.md` wires Phase 0 → 2.5 including KB validation at startup and coverage reconciliation after attack phase.
- All Phase 1 + Phase 2 smoke and unit tests still pass.

---

## Phase 4 — AppReview + workflow router

Add `AppReviewAgent.md` (Opus) and `Workflows/W_HUNT_WEB.md`. Wire Phase 1d into SKILL.md. Prove that AppReview hypotheses set DEPTH/PRIORITY but do NOT gate which Coverage Checklist items run.

### Task 4.1: Write `Agents/AppReviewAgent.md`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/AppReviewAgent.md`

- [ ] **Step 1: Write the agent**

Content for `~/.claude/skills/BugBountyHunter-v4/Agents/AppReviewAgent.md`:

````markdown
---
class: appreview
playbook: null
model: opus
mandate: Build app-profile.json before attack phase (depth/priority hints, NOT gating)
---

# AppReview Agent

Single-shot Opus invocation that builds `app-profile.json` from the
authenticated recon state. Output amplifies into every downstream
attack executor's priority weighting — quality here is leverage.

## Inputs

- `{{WORKDIR}}/state.json` — merged recon (R1-R4 outputs) + auth state
- `{{WORKDIR}}/scope.yaml` — engagement scope
- `~/Documents/BugBountyKB/agents/agent-operating-manual.md`
- `~/Documents/BugBountyKB/taxonomy/owasp-class-catalog.md` (class enumeration)

## Methodology

1. Read recon endpoints, JS analysis, tech fingerprint, cloud assets.
2. Identify the **application narrative**: what is this app, who uses it, what does it protect?
3. Identify **crown jewels**: top 3-5 most sensitive data types or operations.
4. Identify **trust boundaries**: where attacker-controlled input crosses into trusted contexts.
5. Identify **high-value flows**: business-critical operations.
6. For each flow, generate a per-class **attack hypothesis** with `priority: critical | high | medium | low` and a `rationale`.
7. Detect AI/LLM features (chat UI, /api/chat, "Powered by GPT", SSE streams) — flag classes `llm_prompt_injection` and `llm_rag_tool_boundary` for attack executors if present.

## Critical discipline (HARD RULE)

Your hypotheses set DEPTH and PRIORITY for downstream attack executors.
They do NOT gate which classes run. The orchestrator dispatches every
attack executor whose class is enabled by the current workflow file,
regardless of whether you flagged that class as high-priority. If you
miss a class, the orchestrator still tests it — your priority weighting
just won't help.

This means: be inclusive when generating hypotheses. False positives
(flagging a class that turns out to be uninteresting) cost a small
amount of attack-agent depth. False negatives (missing a class)
cost nothing — the class still runs.

## Output

Write to `{{WORKDIR}}/app-profile.json`. Schema:

```json
{
  "narrative": "<1-2 sentences>",
  "crown_jewels": [
    { "name": "user PII", "endpoints": ["/api/users/me", "..."] },
    { "name": "billing data", "endpoints": ["..."] }
  ],
  "trust_boundaries": [
    { "name": "anon → authenticated", "crossing_points": ["/auth/login"] }
  ],
  "flows": [
    {
      "name": "user signup",
      "endpoints": ["/auth/signup", "/auth/verify-email"],
      "crown_jewel_touched": "user PII",
      "attack_hypotheses": [
        {
          "class": "auth",
          "priority": "high",
          "rationale": "email verification race condition could enable ATO"
        },
        {
          "class": "idor",
          "priority": "medium",
          "rationale": "verification token may be enumerable"
        }
      ]
    }
  ],
  "ai_features_detected": false,
  "ai_features_detail": null
}
```

Also emit a brief JSON block at the end of your response with the same
content — the orchestrator parses both the file and your text output.

## Example output structure

```json
{
  "narrative": "Multi-tenant SaaS project-management platform. Users belong to organizations; orgs have projects; projects have members, tasks, files.",
  "crown_jewels": [
    { "name": "cross-org data (project contents, member emails)", "endpoints": ["/api/v1/projects/{id}", "/api/v1/orgs/{id}/members"] },
    { "name": "billing/payment", "endpoints": ["/api/v1/billing", "/api/v1/subscriptions"] }
  ],
  "trust_boundaries": [
    { "name": "user → org-scoped", "crossing_points": ["/api/v1/orgs/{id}/*"] },
    { "name": "user → admin", "crossing_points": ["/admin/*"] }
  ],
  "flows": [
    {
      "name": "project export",
      "endpoints": ["/api/v1/projects/{id}/export"],
      "crown_jewel_touched": "cross-org data",
      "attack_hypotheses": [
        { "class": "idor", "priority": "critical", "rationale": "project IDs are sequential integers; export endpoint may not enforce membership." },
        { "class": "ssrf", "priority": "low", "rationale": "export may fetch attachments by URL." }
      ]
    }
  ],
  "ai_features_detected": false,
  "ai_features_detail": null
}
```
````

- [ ] **Step 2: Verify**

```bash
wc -l ~/.claude/skills/BugBountyHunter-v4/Agents/AppReviewAgent.md
head -5 ~/.claude/skills/BugBountyHunter-v4/Agents/AppReviewAgent.md | grep -q "model: opus" && echo "OK opus model" || echo "FAIL"
```

Expected: ~100-120 lines, `OK opus model`.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/AppReviewAgent.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/AppReviewAgent.md && \
git commit -m "feat(v4): add AppReviewAgent.md (Opus; depth/priority not gating)"
```

---

### Task 4.2: Write `Workflows/W_HUNT_WEB.md`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md`

- [ ] **Step 1: Write the workflow**

Content for `~/.claude/skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md`:

````markdown
# W_HUNT_WEB — Web Application Workflow (default at v1)

Default workflow for web/API targets. The orchestrator selects this
workflow when no other target classifier matches (target is a URL
with HTTP responses).

## Enabled attack classes at v1

- `xss` (XSSAgent.md)
- `idor` (IDORAgent.md)

(Other 15 classes enabled once their per-class agent + playbook are
authored in Plan B + follow-on work.)

## Batch composition

Attack executors are dispatched in batches of up to 2 concurrent agents
(per the ECONNRESET-limit lesson from v3). At v1 with 2 enabled
classes, one batch covers both:

```
Batch 1: XSSAgent + IDORAgent (parallel)
```

When more classes are enabled, batch them per the v3 grouping pattern
(complementary classes batched together; classes with dependencies
sequenced).

## Class dependencies

- IDORAgent depends on `state.json.pipeline_mode != "UNPROVABLE_SINGLE_ACCOUNT"` to produce confirmed findings (single-account mode emits all cross-tenant T-IDs as `inconclusive`).
- All other classes are independent.

## Coverage gate

Phase 2.5 reconciles every enabled class's Coverage Checklist against
its agent output. Gaps trigger up to 2 follow-up rounds per class.

## AppProfile interaction

AppReview's `attack_hypotheses[]` provides priority hints per class:

| Hypothesis priority | Effect on executor |
|----------|-------------------|
| `critical` | Extended timeout (90 min); attempt all opportunistic T-IDs in addition to mandatory; variant sweep on every finding |
| `high` | Standard timeout (60 min); attempt opportunistic T-IDs |
| `medium` | Standard timeout; mandatory queue only |
| `low` | Reduced timeout (30 min); mandatory queue only |
| (no hypothesis for this class) | Same as `medium` |

Class-level priority is the max of hypothesis priorities for that class
across all flows. Per-flow hypotheses also seed the agent's
`app_profile_hint` template variable so the agent knows which endpoints
to attempt first within its run queue.
````

- [ ] **Step 2: Verify**

```bash
wc -l ~/.claude/skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md
grep -c "depth\|priority" ~/.claude/skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md
```

Expected: ~60-80 lines, multiple references to priority/depth.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
mkdir -p skills/BugBountyHunter-v4/Workflows && \
cp ~/.claude/skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md skills/BugBountyHunter-v4/Workflows/ && \
git add skills/BugBountyHunter-v4/Workflows/W_HUNT_WEB.md && \
git commit -m "feat(v4): add W_HUNT_WEB.md workflow (XSS + IDOR enabled at v1)"
```

---

### Task 4.3: Wire SKILL.md Phase 1d

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/SKILL.md`

- [ ] **Step 1: Insert Phase 1d block**

In `~/.claude/skills/BugBountyHunter-v4/SKILL.md`, find the line `## Phase 1d — AppReview (Opus, single-shot)` (already a placeholder header from Task 3.9). Replace that section (including the placeholder body) with:

````markdown
## Phase 1d — AppReview (Opus, single-shot)

After Phase 1c recon merge, dispatch the AppReviewAgent ONCE as Opus.
Output amplifies into all downstream attack executors.

```typescript
// Pseudo-spawn (orchestrator-side)
Agent({
  subagent_type: "Pentester",
  model: "opus",
  description: "AppReview profiling",
  prompt: interpolate(
    readFile(`${SKILL}/Agents/AppReviewAgent.md`),
    { WORKDIR, ENGAGEMENT_ID }
  ),
  run_in_background: false,
})
```

After AppReview returns:

1. Parse output JSON; expect schema per `AppReviewAgent.md`.
2. Write to `${WORKDIR}/app-profile.json`.
3. Compute per-class priority map:

```bash
python3 - "${WORKDIR}/app-profile.json" <<'PY'
import json, sys
profile = json.load(open(sys.argv[1]))
class_priority = {}
PRIO = {"critical": 4, "high": 3, "medium": 2, "low": 1}
for flow in profile.get("flows", []):
    for h in flow.get("attack_hypotheses", []):
        c = h["class"]
        p = PRIO.get(h["priority"], 2)
        class_priority[c] = max(class_priority.get(c, 0), p)
out_path = sys.argv[1].rsplit("/", 1)[0] + "/class-priority.json"
json.dump(class_priority, open(out_path, "w"), indent=2)
PY
```

4. Inject per-class hints into each attack executor's spawn template
   (the `{{APP_PROFILE_<CLASS>_HINT}}` variable for that class).

5. **Hard rule (re-stated for emphasis):** Coverage Checklist mandatory
   items run regardless of AppProfile coverage. If AppReview returns
   without a hypothesis for class X, the X executor still runs with
   default (medium) priority. AppReview NEVER reduces the set of
   classes that run.

Advance to Phase 2:

```bash
bun "${SKILL}/lib/orchestrator.ts" --advance --workdir "${WORKDIR}"
```
````

- [ ] **Step 2: Verify**

```bash
grep -c "Hard rule" ~/.claude/skills/BugBountyHunter-v4/SKILL.md
grep -c "class-priority.json" ~/.claude/skills/BugBountyHunter-v4/SKILL.md
```

Expected: ≥2 hard-rule mentions, 1 priority-map reference.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/SKILL.md skills/BugBountyHunter-v4/ && \
git add skills/BugBountyHunter-v4/SKILL.md && \
git commit -m "feat(v4): wire Phase 1d AppReview with depth-not-gating hard rule"
```

---

### Task 4.4: Depth-not-gating smoke test

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_depth_not_gating.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/appreview/app-profile-missing-xss.json`

- [ ] **Step 1: Write the failing test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_depth_not_gating.sh`:

```bash
#!/usr/bin/env bash
# Test: with an app-profile.json that lacks any XSS hypothesis,
# the orchestrator's coverage reconciliation must STILL produce
# the full XSS mandatory checklist as expected.
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
KB=~/Documents/BugBountyKB
FIX="${SKILL_DIR}/tests/fixtures/appreview"
WORK=/tmp/bbh-v4-depth-test
rm -rf "$WORK"
mkdir -p "$WORK/agents"

# Stage state.json with capabilities that make T-XSS-01, T-XSS-02 mandatory
cat > "$WORK/state.json" <<'JSON'
{
  "engagement_id": "depth-test",
  "recon": {
    "capabilities": {
      "has_query_param_endpoints": true,
      "has_user_profile_fields": true,
      "has_user_generated_content": false,
      "has_json_endpoints": true,
      "has_client_side_routing": false,
      "has_postmessage_handlers": false,
      "has_markdown_render": false,
      "has_dompurify": false,
      "has_svg_upload": false,
      "has_inline_pdf": false,
      "angular_version_lt_1_6": false,
      "has_template_engine": false,
      "has_react_or_vue": false,
      "waf_detected": false,
      "csp_has_unsafe_eval_or_unsafe_inline": false
    }
  }
}
JSON

# Stage an app-profile that has NO XSS hypothesis
cp "$FIX/app-profile-missing-xss.json" "$WORK/app-profile.json"

# Stage an agent output that didn't attempt any T-XSS
cat > "$WORK/agents/xss-results.json" <<'JSON'
{ "agent_id": "xss-1", "class": "xss", "engagement_id": "depth-test",
  "coverage": [], "findings": [], "proposed_additions": [] }
JSON

# Reconcile must STILL detect the gaps (T-XSS-01, T-XSS-02, T-XSS-15)
out=$(bash "${SKILL_DIR}/lib/reconcile-coverage.sh" --workdir "$WORK" --class xss --kb "$KB" || true)
echo "$out"

echo "$out" | grep -qE "gaps=[1-9]" || { echo "FAIL: AppProfile missing a class did NOT prevent reconciliation"; exit 1; }
echo "$out" | grep -q "T-XSS-01" || { echo "FAIL: T-XSS-01 not in gap list"; exit 1; }

echo "PASS: AppProfile gating does NOT short-circuit coverage reconciliation"
rm -rf "$WORK"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_depth_not_gating.sh
```

- [ ] **Step 2: Write fixture**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/appreview
```

Content for `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/appreview/app-profile-missing-xss.json`:

```json
{
  "narrative": "Test app with no XSS hypothesis",
  "crown_jewels": [],
  "trust_boundaries": [],
  "flows": [
    {
      "name": "test flow",
      "endpoints": ["/api/test"],
      "crown_jewel_touched": null,
      "attack_hypotheses": [
        { "class": "idor", "priority": "high", "rationale": "test" }
      ]
    }
  ],
  "ai_features_detected": false,
  "ai_features_detail": null
}
```

- [ ] **Step 3: Run the test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_depth_not_gating.sh
```

Expected: `gaps>=1`, T-XSS-01 in gap list, `PASS`.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_depth_not_gating.sh skills/BugBountyHunter-v4/tests/smoke/ && \
mkdir -p skills/BugBountyHunter-v4/tests/fixtures/appreview && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/appreview/*.json skills/BugBountyHunter-v4/tests/fixtures/appreview/ && \
git add skills/BugBountyHunter-v4/tests/ && \
git commit -m "feat(v4): add depth-not-gating smoke test (AppProfile cannot short-circuit coverage)"
```

---

### Task 4.5: Phase 4 verification

- [ ] **Step 1: Run all smoke tests**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
for t in tests/smoke/*.sh; do bash "$t" || { echo "FAIL $t"; exit 1; }; done
```

Expected: 5 ALL PASS / PASS lines.

- [ ] **Step 2: Unit tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test
```

Expected: 8 tests pass.

- [ ] **Step 3: All deliverables present**

```bash
for f in \
  Agents/AppReviewAgent.md \
  Workflows/W_HUNT_WEB.md \
  tests/smoke/test_depth_not_gating.sh \
  tests/fixtures/appreview/app-profile-missing-xss.json
do
  [ -f ~/.claude/skills/BugBountyHunter-v4/$f ] && echo "OK $f" || echo "MISSING $f"
done
```

Expected: 4 OK lines.

**Phase 4 complete when:**

- `AppReviewAgent.md` (Opus) authored with explicit depth/priority-not-gating discipline.
- `W_HUNT_WEB.md` workflow describes batch composition + class dependencies + priority semantics.
- SKILL.md Phase 1d wired with hard-rule re-statement.
- Depth-not-gating smoke test proves reconciliation fires regardless of AppProfile.

---

## Phase 5 — Validation pipeline (Phase 2.9 + 3 + 3.5)

Port v3 Advocate / Triager / phase29-gate / phase3-debate. Write the NEW Curator agent and `curator-batch.sh`. Wire KB git-commit flow for accepted proposals. Ensure the bounty-hallucination canary still fires.

### Task 5.1: Port v3 mechanical gates (phase29-gate.sh, phase3-debate.sh)

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/phase29-gate.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/phase3-debate.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/precedent-lookup.sh`

- [ ] **Step 1: Copy from v3**

```bash
for s in phase29-gate phase3-debate precedent-lookup; do
  cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/${s}.sh \
     ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
  chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
done
```

- [ ] **Step 2: Update path references**

```bash
for s in phase29-gate phase3-debate precedent-lookup; do
  # Replace v3 paths with v4 paths
  sed -i 's|/tmp/pentest-{{ID}}|${WORKDIR}|g' ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
  # HackerOnePrecedents moved from skill/data/ to KB references/
  sed -i 's|data/HackerOnePrecedents.jsonl|/home/adlt/Documents/BugBountyKB/references/hackerone-precedents.jsonl|g' ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh
done
```

- [ ] **Step 3: Verify**

```bash
for s in phase29-gate phase3-debate precedent-lookup; do
  if grep -q "pentest-{{ID}}\|skills/.*data/HackerOnePrecedents" \
       ~/.claude/skills/BugBountyHunter-v4/lib/${s}.sh; then
    echo "STALE $s"
  else
    echo "OK $s"
  fi
done
```

Expected: 3 OK lines.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/{phase29-gate,phase3-debate,precedent-lookup}.sh \
   skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/ && \
git commit -m "feat(v4): port phase29-gate, phase3-debate, precedent-lookup with KB paths"
```

---

### Task 5.2: Port Advocate.md + Triager.md

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/Advocate.md`
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/Triager.md`

- [ ] **Step 1: Copy from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/AgentPrompts/advocate.md \
   ~/.claude/skills/BugBountyHunter-v4/Agents/Advocate.md
cp ~/.claude/skills/BugBountyHunter-v3-experimental/AgentPrompts/triager.md \
   ~/.claude/skills/BugBountyHunter-v4/Agents/Triager.md
```

- [ ] **Step 2: Apply path/contract edits**

For each of the two files, apply the same Find/Replace table from Task 3.1 Step 2 (paths and HackerOnePrecedents location).

Then prepend frontmatter to each:

`Advocate.md`:

```yaml
---
class: advocate
playbook: null
model: opus
mandate: Per-finding case construction for HackerOne reporting
---

```

`Triager.md`:

```yaml
---
class: triager
playbook: null
model: opus
mandate: Adversarial review; find a valid close reason
---

```

- [ ] **Step 3: Verify**

```bash
for a in Advocate Triager; do
  head -7 ~/.claude/skills/BugBountyHunter-v4/Agents/${a}.md | grep -q "model: opus" && echo "OK $a" || echo "FAIL $a"
done
```

Expected: 2 OK lines.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/{Advocate,Triager}.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/ && \
git commit -m "feat(v4): port Advocate.md and Triager.md from v3 with Opus frontmatter"
```

---

### Task 5.3: Write `Agents/Curator.md` (NEW)

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/Agents/Curator.md`

- [ ] **Step 1: Write the agent**

Content for `~/.claude/skills/BugBountyHunter-v4/Agents/Curator.md`:

````markdown
---
class: curator
playbook: null
model: opus
mandate: Process proposed_additions batches; merge accepted into KB with git-commit
---

# Curator Agent

Single Opus invocation per batch of 5-8 `proposed_additions[]` from an
engagement. Maintains `~/Documents/BugBountyKB/` quality.

## Doctrine

Read `~/Documents/BugBountyKB/maintenance/curation-rules.md` for the
full verdict taxonomy and bias rules. Summary:

- `NEW` — distinct from every existing T-ID; all fields present;
  confidence ≥ medium → assign next T-ID, insert into Coverage Checklist
- `VARIANT_OF: T-X-NN` — refinement of T-X-NN → sub-bullet under that ID
- `DUPLICATE_OF: T-X-NN` — same technique under different name → discard
- `REJECT_LOW_QUALITY` — missing fields, unverifiable evidence → discard
- `DEFER_TO_HUMAN` — uncertain → drop stub in `99-Inbox/`

**Bias: conservative.** Low-confidence → DEFER. False negatives cost a
manual review. False positives corrupt the KB.

## Inputs

- `{{WORKDIR}}/proposed-batch.json` — array of 5-8 proposed_additions[] items
- `{{KB_PATH}}` — path to BugBountyKB
- `~/Documents/BugBountyKB/maintenance/curation-rules.md`
- The matching playbook for each proposal's class

## Methodology

For each proposal in the batch:

1. **Identify the matching playbook** via the proposal's `class` field
   and `~/Documents/BugBountyKB/taxonomy/owasp-class-catalog.md`.
2. **Read the playbook in full**, including the Coverage Checklist
   YAML, all existing technique families/red_flags/proof_targets/
   fix_patterns.
3. **Well-formedness check** (mandatory for NEW/VARIANT):
   - `red_flags[]` non-empty? If not → REJECT_LOW_QUALITY (missing red_flags).
   - `proof_targets[]` non-empty? If not → REJECT_LOW_QUALITY (missing proof_targets).
   - `fix_patterns[]` non-empty? If not → REJECT_LOW_QUALITY (missing fix_patterns).
   - `evidence_artifact_path` exists on disk? If not → REJECT_LOW_QUALITY (evidence missing).
4. **Novelty matrix** (mandatory before NEW):
   - For each existing T-ID in the playbook, score:
     - Same primitive (root cause)?
     - Same sink?
     - Operator-facing fix overlap ≥80%?
   - If any pair scores ≥80% on all three → VARIANT_OF or DUPLICATE_OF
     (use VARIANT_OF if proposal genuinely adds new payload/encoding/
     context; DUPLICATE_OF if it's the same thing renamed).
5. **Confidence assessment**:
   - High: clear novelty, strong evidence, clean fields.
   - Medium: probably novel, evidence acceptable, fields complete.
   - Low: ambiguous novelty OR weak evidence OR ambiguous fields → DEFER.
6. **Emit verdict** in your output JSON.

## Output contract

Your response MUST end with a fenced JSON block:

```json
{
  "batch_size": <N>,
  "verdicts": [
    {
      "proposal_index": 0,
      "verdict": "NEW" | "VARIANT_OF: T-X-NN" | "DUPLICATE_OF: T-X-NN" | "REJECT_LOW_QUALITY" | "DEFER_TO_HUMAN",
      "confidence": "high" | "medium" | "low",
      "reason": "<one sentence>",
      "assigned_id": "T-X-NN" | null,
      "commit_message": "<conventional commit msg per curation-rules.md>" | null,
      "stub_path": "<99-Inbox/...md path>" | null
    },
    { ... }
  ]
}
```

The orchestrator's `curator-batch.sh` parses this JSON and performs the
actual KB writes + git commits. You do NOT write to disk directly — your
job is the verdict + commit message; the shell script applies the
change.

## Example output

```json
{
  "batch_size": 3,
  "verdicts": [
    {
      "proposal_index": 0,
      "verdict": "NEW",
      "confidence": "high",
      "reason": "CSS Typed OM mutation observer escape is a fundamentally new sink primitive not covered by T-XSS-01..15.",
      "assigned_id": "T-XSS-16",
      "commit_message": "playbook(xss): add T-XSS-16 (CSS Typed OM mutation observer escape)\n\nEvidence: /tmp/pentest-XYZ/findings/F-A-007/evidence.har\nSource engagement: pentest-XYZ\nCurator verdict: NEW\nConfidence: high",
      "stub_path": null
    },
    {
      "proposal_index": 1,
      "verdict": "VARIANT_OF: T-XSS-13",
      "confidence": "high",
      "reason": "New Akamai bypass payload — same primitive (WAF bypass via polyglot) as T-XSS-13, different encoding.",
      "assigned_id": null,
      "commit_message": "playbook(xss): extend T-XSS-13 (Akamai bypass via constructor chain)\n\nEvidence: /tmp/.../evidence.har\nSource engagement: pentest-XYZ\nCurator verdict: VARIANT_OF: T-XSS-13\nConfidence: high",
      "stub_path": null
    },
    {
      "proposal_index": 2,
      "verdict": "DEFER_TO_HUMAN",
      "confidence": "low",
      "reason": "Proposal mentions an interesting GraphQL alias pattern but evidence is incomplete (only one request captured). Cannot confidently determine novelty vs T-IDOR-14.",
      "assigned_id": null,
      "commit_message": null,
      "stub_path": "99-Inbox/2026-05-23-idor-graphql-alias-incomplete-evidence.md"
    }
  ]
}
```
````

- [ ] **Step 2: Verify**

```bash
wc -l ~/.claude/skills/BugBountyHunter-v4/Agents/Curator.md
head -5 ~/.claude/skills/BugBountyHunter-v4/Agents/Curator.md | grep -q "model: opus" && echo "OK"
```

Expected: ~150 lines, `OK`.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/Agents/Curator.md skills/BugBountyHunter-v4/Agents/ && \
git add skills/BugBountyHunter-v4/Agents/Curator.md && \
git commit -m "feat(v4): add Curator.md (Opus; verdict taxonomy + commit message generation)"
```

---

### Task 5.4: Write `lib/curator-batch.sh`

This is the NEW shell-side script that consumes Curator's verdict JSON and applies the actual KB writes + git commits.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/curator-batch.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator/verdicts.json`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator/proposals.json`

- [ ] **Step 1: Write the failing smoke test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
FIX="${SKILL_DIR}/tests/fixtures/curator"
SCRIPT="${SKILL_DIR}/lib/curator-batch.sh"

# Stage a TEST KB clone so we don't pollute the real KB
TEST_KB=/tmp/bbh-v4-test-kb
rm -rf "$TEST_KB"
cp -r ~/Documents/BugBountyKB "$TEST_KB"
cd "$TEST_KB" && git checkout -b curator-test 2>/dev/null || true

WORK=/tmp/bbh-v4-curator-work
rm -rf "$WORK"
mkdir -p "$WORK"
cp "$FIX/verdicts.json" "$WORK/curator-verdicts.json"
cp "$FIX/proposals.json" "$WORK/proposed-batch.json"

echo "--- T1: curator-batch.sh processes verdicts ---"
bash "$SCRIPT" --workdir "$WORK" --kb "$TEST_KB" || { echo "FAIL"; exit 1; }

echo "--- T2: NEW verdict produced a git commit ---"
cd "$TEST_KB" && git log --oneline curator-test | head -3
git log curator-test --oneline | grep -q "T-XSS-16" || { echo "FAIL: no T-XSS-16 commit"; exit 1; }

echo "--- T3: DEFER_TO_HUMAN produced a stub in 99-Inbox ---"
ls "$TEST_KB/99-Inbox/" | grep -q "2026-.*-idor-" || { echo "FAIL: no inbox stub"; exit 1; }

echo "ALL PASS"
rm -rf "$WORK" "$TEST_KB"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh
```

- [ ] **Step 2: Write fixtures**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator
```

Content for `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator/proposals.json`:

```json
[
  {
    "class": "xss",
    "proposed_name": "CSS Typed OM mutation observer escape",
    "family": "dom",
    "red_flags": ["JS reads attributeStyleMap.set with attacker input"],
    "proof_targets": ["browser-executed XSS via mutation observer callback"],
    "fix_patterns": ["allowlist CSSStyleValue inputs", "avoid Typed OM for user content"],
    "evidence_artifact_path": "/tmp/proposed-evidence-1.har"
  },
  {
    "class": "idor",
    "proposed_name": "GraphQL alias incomplete-evidence pattern",
    "family": "bola",
    "red_flags": ["GraphQL alias used to batch mutations"],
    "proof_targets": ["cross-account mutation"],
    "fix_patterns": ["enforce per-alias authz"],
    "evidence_artifact_path": "/tmp/proposed-evidence-2.har"
  }
]
```

Content for `~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator/verdicts.json`:

```json
{
  "batch_size": 2,
  "verdicts": [
    {
      "proposal_index": 0,
      "verdict": "NEW",
      "confidence": "high",
      "reason": "Fundamentally new DOM sink primitive.",
      "assigned_id": "T-XSS-16",
      "commit_message": "playbook(xss): add T-XSS-16 (CSS Typed OM mutation observer escape)\n\nEvidence: /tmp/proposed-evidence-1.har\nSource engagement: test\nCurator verdict: NEW\nConfidence: high",
      "stub_path": null
    },
    {
      "proposal_index": 1,
      "verdict": "DEFER_TO_HUMAN",
      "confidence": "low",
      "reason": "Could be VARIANT_OF T-IDOR-14 but evidence incomplete.",
      "assigned_id": null,
      "commit_message": null,
      "stub_path": "99-Inbox/2026-05-23-idor-graphql-alias-incomplete-evidence.md"
    }
  ]
}
```

- [ ] **Step 3: Run test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh
```

Expected: FAIL — `curator-batch.sh` doesn't exist.

- [ ] **Step 4: Write `lib/curator-batch.sh`**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/curator-batch.sh`:

```bash
#!/usr/bin/env bash
# curator-batch.sh — Phase 3.5
# Reads curator-verdicts.json + proposed-batch.json from workdir;
# applies KB writes and git commits per Curator's verdicts.

set -euo pipefail

WORKDIR=""
KB=""

while [ $# -gt 0 ]; do
  case "$1" in
    --workdir) WORKDIR="$2"; shift 2 ;;
    --kb)      KB="$2";      shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$WORKDIR" ] && [ -n "$KB" ] || { echo "Usage: curator-batch.sh --workdir DIR --kb DIR" >&2; exit 2; }

VERDICTS="${WORKDIR}/curator-verdicts.json"
PROPOSALS="${WORKDIR}/proposed-batch.json"

[ -f "$VERDICTS" ] || { echo "[FAIL] no verdicts at $VERDICTS" >&2; exit 1; }
[ -f "$PROPOSALS" ] || { echo "[FAIL] no proposals at $PROPOSALS" >&2; exit 1; }
[ -d "$KB/.git" ] || { echo "[FAIL] KB not a git repo: $KB" >&2; exit 1; }

cd "$KB"

# Process each verdict
LOG="${WORKDIR}/curator-log.jsonl"
python3 - "$VERDICTS" "$PROPOSALS" "$KB" "$LOG" <<'PY'
import json, sys, subprocess, os, datetime
from pathlib import Path

verdicts_path, proposals_path, kb_path, log_path = sys.argv[1:5]
verdicts = json.load(open(verdicts_path))
proposals = json.load(open(proposals_path))
kb = Path(kb_path)
log = open(log_path, "a")

def cmd(args, **kw):
    return subprocess.run(args, cwd=kb_path, check=True, capture_output=True, text=True, **kw)

def log_event(evt):
    log.write(json.dumps({**evt, "ts": datetime.datetime.now(datetime.UTC).isoformat()}) + "\n")
    log.flush()

for v in verdicts["verdicts"]:
    idx = v["proposal_index"]
    proposal = proposals[idx] if idx < len(proposals) else None
    verdict = v["verdict"]
    klass = (proposal or {}).get("class", "unknown")

    if verdict == "NEW":
        tid = v["assigned_id"]
        playbook = kb / "playbooks" / f"{klass}.md"
        if not playbook.exists():
            log_event({"action": "skip_NEW_no_playbook", "tid": tid, "class": klass})
            continue

        # Append a new entry to the Coverage Checklist YAML
        content = playbook.read_text()
        new_entry = (
            f"\n  - id: {tid}\n"
            f"    name: {proposal['proposed_name']}\n"
            f"    mandatory: false\n"
            f"    proof_required: {proposal['proof_targets'][0]}\n"
        )
        # Insert before the closing ``` of the YAML block
        marker = "```\n\n## Tombstone"
        if marker in content:
            content = content.replace(marker, new_entry + "```\n\n## Tombstone", 1)
        else:
            # Fallback: append before the final ``` we find inside Coverage Checklist
            content = content.replace("```\n", new_entry + "```\n", 1)
        playbook.write_text(content)

        cmd(["git", "add", str(playbook.relative_to(kb))])
        cmd(["git", "commit", "-m", v["commit_message"]])
        log_event({"action": "NEW", "tid": tid, "class": klass})

    elif verdict.startswith("VARIANT_OF:"):
        parent = verdict.split(":", 1)[1].strip()
        # For now: append a Notes section with the variant. Curator's commit
        # message captures the parent T-ID.
        playbook = kb / "playbooks" / f"{klass}.md"
        if not playbook.exists():
            log_event({"action": "skip_VARIANT_no_playbook", "parent": parent})
            continue
        # Simple append; v4.1 will do structured inline insertion.
        with playbook.open("a") as f:
            f.write(f"\n<!-- VARIANT_OF: {parent} -->\n"
                    f"- {proposal['proposed_name']}: {'; '.join(proposal['red_flags'])}\n")
        cmd(["git", "add", str(playbook.relative_to(kb))])
        cmd(["git", "commit", "-m", v["commit_message"]])
        log_event({"action": "VARIANT_OF", "parent": parent, "class": klass})

    elif verdict.startswith("DUPLICATE_OF:") or verdict == "REJECT_LOW_QUALITY":
        log_event({"action": "discard", "verdict": verdict, "reason": v.get("reason"), "class": klass})

    elif verdict == "DEFER_TO_HUMAN":
        stub_rel = v["stub_path"]
        stub_abs = kb / stub_rel
        stub_abs.parent.mkdir(parents=True, exist_ok=True)
        stub_abs.write_text(
            f"---\nclass: {klass}\nproposed_name: {proposal['proposed_name']}\n"
            f"curator_verdict: DEFER_TO_HUMAN\nconfidence: {v['confidence']}\n"
            f"reason: {v['reason']}\n---\n\n"
            f"## Evidence\n{proposal.get('evidence_artifact_path', '')}\n\n"
            f"## Red flags\n" + "\n".join(f"- {x}" for x in proposal['red_flags']) + "\n\n"
            f"## Proof targets\n" + "\n".join(f"- {x}" for x in proposal['proof_targets']) + "\n"
        )
        cmd(["git", "add", str(stub_abs.relative_to(kb))])
        cmd(["git", "commit", "-m", f"defer({klass}): drop stub for human review — {proposal['proposed_name']}"])
        log_event({"action": "DEFER", "stub": stub_rel, "class": klass})

    else:
        log_event({"action": "unknown_verdict", "verdict": verdict})

print(f"[OK] processed {len(verdicts['verdicts'])} verdicts")
PY
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/curator-batch.sh
```

- [ ] **Step 5: Run test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh
```

Expected: T1 OK, T2 T-XSS-16 commit found, T3 inbox stub found, `ALL PASS`.

- [ ] **Step 6: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/curator-batch.sh skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_curator_batch.sh skills/BugBountyHunter-v4/tests/smoke/ && \
mkdir -p skills/BugBountyHunter-v4/tests/fixtures/curator && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/curator/*.json skills/BugBountyHunter-v4/tests/fixtures/curator/ && \
git add skills/BugBountyHunter-v4/{lib/curator-batch.sh,tests/smoke/test_curator_batch.sh,tests/fixtures/curator} && \
git commit -m "feat(v4): add curator-batch.sh (NEW/VARIANT_OF/DEFER processing with git commits)"
```

---

### Task 5.5: Wire SKILL.md Phases 2.9, 3, 3.5

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/SKILL.md`

- [ ] **Step 1: Append Phases 2.9, 3, 3.5 to SKILL.md**

Find the placeholder line in `SKILL.md`:

```
## Phase 2.9, 3, 3.5, 4

(Landed in subsequent plan phases — see plan Phases 5-6.)
```

Replace that placeholder with:

````markdown
## Phase 2.9 — Mechanical artifact gate

After Phase 2.5 reconciliation completes:

```bash
bash "${SKILL}/lib/phase29-gate.sh" --workdir "${WORKDIR}" --skill "${SKILL}"
```

`phase29-gate.sh` reads `config/ArtifactMatrix.yaml` + `PublicSafeList.yaml` and auto-rejects findings that:

- Match `program_excluded_classes`
- Lack required artifact files
- Match a `PublicSafeList` pattern
- Are chain-constituents whose parent finding got rejected

Survivors land in `state.json.validated_candidates[]`. Rejects land in `state.json.artifact_discarded[]` with the specific rule cited.

## Phase 3 — Advocate ↔ Triager debate

For each survivor from Phase 2.9:

1. Dispatch Advocate (Opus) for the finding:
   ```typescript
   Agent({ subagent_type: "Pentester", model: "opus",
           description: `Advocate for ${F.id}`,
           prompt: interpolate(`${SKILL}/Agents/Advocate.md`,
             { WORKDIR, FINDING_ID: F.id, FINDING_DIR, TARGET_PROGRAM,
               SCOPE_YAML, PRIOR_REPORTS_DIR }) })
   ```
2. Parse Advocate's `advocate-argument.json`.
3. Dispatch Triager (Opus) with the Advocate's argument as input.
4. Parse Triager's `triager-verdict.json`.
5. Run `phase3-debate.sh` to apply the decision rule:
   - ACCEPT + precedent + high/medium confidence → `validated_findings[]`
   - All other cases → `triager_closed[]` with `close_code`
   - Low-confidence ACCEPT → rewrite to `INFORMATIVE_NO_IMPACT`

```bash
bash "${SKILL}/lib/phase3-debate.sh" --workdir "${WORKDIR}"
```

Then advance:

```bash
bun "${SKILL}/lib/orchestrator.ts" --advance --workdir "${WORKDIR}"
```

## Phase 3.5 — Curator (batched 5-8)

Collect `proposed_additions[]` from every attack executor's output.
Batch in groups of 5-8 and invoke Curator (Opus) per batch:

```bash
# Pseudo-loop (orchestrator-side)
PROPOSALS=$(jq '[.[] | select(.proposed_additions) | .proposed_additions[]]' "${WORKDIR}/agents/"*-results.json)
total=$(echo "$PROPOSALS" | jq 'length')
BATCH_SIZE=8

for offset in $(seq 0 $BATCH_SIZE $((total - 1))); do
  BATCH=$(echo "$PROPOSALS" | jq ".[$offset:$((offset + BATCH_SIZE))]")
  echo "$BATCH" > "${WORKDIR}/proposed-batch.json"

  # Dispatch Curator (Opus)
  # Agent({ subagent_type: "Pentester", model: "opus",
  #         description: `Curator batch ${offset}`,
  #         prompt: interpolate(`${SKILL}/Agents/Curator.md`,
  #           { WORKDIR, KB_PATH }) })
  # Curator writes verdicts to ${WORKDIR}/curator-verdicts.json

  bash "${SKILL}/lib/curator-batch.sh" --workdir "${WORKDIR}" --kb "${KB}"
done
```

Curator commits land directly in the KB git repo. DEFER stubs land in
`${KB}/99-Inbox/` for human review.

```bash
bun "${SKILL}/lib/orchestrator.ts" --advance --workdir "${WORKDIR}"
```

## Phase 4 — Report generation

(Wired in next plan phase.)
````

- [ ] **Step 2: Verify**

```bash
grep -c "Phase 2.9\|Phase 3\|Phase 3.5" ~/.claude/skills/BugBountyHunter-v4/SKILL.md
```

Expected: ≥3.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/SKILL.md skills/BugBountyHunter-v4/ && \
git add skills/BugBountyHunter-v4/SKILL.md && \
git commit -m "feat(v4): wire SKILL.md Phases 2.9 (gate) + 3 (debate) + 3.5 (Curator)"
```

---

### Task 5.6: Port + run bounty-hallucination canary

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh`

- [ ] **Step 1: Copy from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/tests/smoke/test_bounty_hallucination_canary.sh \
   ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
```

- [ ] **Step 2: Update path references in the canary script**

```bash
sed -i 's|BugBountyHunter-v3-experimental|BugBountyHunter-v4|g' \
  ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
sed -i 's|data/HackerOnePrecedents.jsonl|/home/adlt/Documents/BugBountyKB/references/hackerone-precedents.jsonl|g' \
  ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
```

- [ ] **Step 3: Run the canary**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
```

Expected: PASS — null precedent + non-null bounty must NEVER validate. If this fails, Phase 3 debate logic regressed.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh skills/BugBountyHunter-v4/tests/smoke/ && \
git add skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh && \
git commit -m "feat(v4): port bounty-hallucination canary smoke test from v3"
```

---

### Task 5.7: Phase 5 verification

- [ ] **Step 1: All smoke tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
for t in tests/smoke/*.sh; do bash "$t" || { echo "FAIL $t"; exit 1; }; done
```

Expected: 7 PASS lines (finding_schema, validate_playbook, orchestrator_cli, reconcile_coverage, depth_not_gating, curator_batch, bounty_hallucination_canary).

- [ ] **Step 2: Unit tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test
```

Expected: 8 tests pass.

- [ ] **Step 3: All Phase 5 deliverables present**

```bash
for f in \
  lib/phase29-gate.sh \
  lib/phase3-debate.sh \
  lib/precedent-lookup.sh \
  lib/curator-batch.sh \
  Agents/Advocate.md \
  Agents/Triager.md \
  Agents/Curator.md \
  tests/smoke/test_curator_batch.sh \
  tests/smoke/test_bounty_hallucination_canary.sh
do
  [ -f ~/.claude/skills/BugBountyHunter-v4/$f ] && echo "OK $f" || echo "MISSING $f"
done
```

Expected: 9 OK lines.

**Phase 5 complete when:**

- Advocate, Triager, Curator agents authored with Opus frontmatter and KB path references.
- `phase29-gate.sh`, `phase3-debate.sh`, `precedent-lookup.sh`, `curator-batch.sh` ported/written with KB paths.
- `curator-batch.sh` smoke test exercises NEW → git commit, DEFER → inbox stub.
- `bounty-hallucination-canary.sh` still fires (null precedent + non-null bounty NEVER validates).
- SKILL.md wires Phases 2.9, 3, 3.5 with proper agent dispatch + commit handoff.

---

## Phase 6 — Reporting

Port `generate-report.sh` from v3 with the v4 adjustment: include a Coverage Gap appendix populated from `coverage-reconcile-*.json` files plus `coverage-gaps.txt`. Wire Phase 4 in SKILL.md.

### Task 6.1: Port `lib/generate-report.sh`

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh`

- [ ] **Step 1: Copy from v3**

```bash
cp ~/.claude/skills/BugBountyHunter-v3-experimental/lib/generate-report.sh \
   ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh
```

- [ ] **Step 2: Update path references**

```bash
sed -i 's|/tmp/pentest-{{ID}}|${WORKDIR}|g' \
  ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh
sed -i 's|data/HackerOnePrecedents.jsonl|/home/adlt/Documents/BugBountyKB/references/hackerone-precedents.jsonl|g' \
  ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh
# Templates moved from skill/templates/ (if any) to KB templates/
sed -i 's|skills/.*templates/finding-report\.md|/home/adlt/Documents/BugBountyKB/templates/finding-report.md|g' \
  ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh
```

- [ ] **Step 3: Verify**

```bash
grep -nE "(pentest-\{\{ID\}\}|skills/.*templates)" \
  ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh && echo "STALE" || echo "OK"
```

Expected: `OK`.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/generate-report.sh && \
git commit -m "feat(v4): port generate-report.sh with KB template + precedent paths"
```

---

### Task 6.2: Add coverage-gap appendix logic

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh`

- [ ] **Step 1: Write the failing test**

Create `~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_coverage_gap_appendix.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SCRIPT="${SKILL_DIR}/lib/generate-report.sh"
WORK=/tmp/bbh-v4-report-test
rm -rf "$WORK"
mkdir -p "$WORK/agents"

# Stage state with a validated finding + coverage gaps
cat > "$WORK/state.json" <<'JSON'
{
  "engagement_id": "test",
  "target": "example.com",
  "validated_findings": [
    {
      "id": "F-A-001",
      "class": "xss",
      "technique_id": "T-XSS-02",
      "endpoint": "POST /api/profile",
      "confidence": "Confirmed",
      "severity": "P3",
      "evidence_artifact": "/tmp/e/F-A-001"
    }
  ],
  "validated_candidates": [],
  "triager_closed": [],
  "artifact_discarded": []
}
JSON

cat > "$WORK/coverage-reconcile-xss.json" <<'JSON'
{ "class": "xss", "applicable_mandatory_count": 4, "attempted_count": 3,
  "gaps": ["T-XSS-15"] }
JSON

cat > "$WORK/coverage-reconcile-idor.json" <<'JSON'
{ "class": "idor", "applicable_mandatory_count": 12, "attempted_count": 12,
  "gaps": [] }
JSON

echo "T-XSS-15: WAF-blocked on /api/data endpoint" > "$WORK/coverage-gaps.txt"

bash "$SCRIPT" --workdir "$WORK" --output "$WORK/report.md"

echo "--- T1: report file produced ---"
[ -f "$WORK/report.md" ] || { echo "FAIL: no report"; exit 1; }

echo "--- T2: report includes Coverage Gap appendix ---"
grep -q "Coverage Gap" "$WORK/report.md" || { echo "FAIL: no Coverage Gap section"; exit 1; }

echo "--- T3: report cites the missing T-ID ---"
grep -q "T-XSS-15" "$WORK/report.md" || { echo "FAIL: missing T-ID not cited"; exit 1; }

echo "ALL PASS"
rm -rf "$WORK"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_coverage_gap_appendix.sh
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_coverage_gap_appendix.sh
```

Expected: FAIL — v3 `generate-report.sh` has no Coverage Gap section.

- [ ] **Step 3: Patch `lib/generate-report.sh`**

Append the following Coverage Gap appendix logic to `~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh` (immediately before the final report-write step; if the script structure differs, place it inside the main report-generation function):

```bash
# Coverage Gap appendix (v4 addition)
append_coverage_gap_appendix() {
  local workdir="$1"
  local out="$2"

  echo "" >> "$out"
  echo "## Coverage Gap Appendix" >> "$out"
  echo "" >> "$out"
  echo "| Class | Mandatory T-IDs | Attempted | Gaps |" >> "$out"
  echo "|-------|-----------------|-----------|------|" >> "$out"

  for f in "$workdir"/coverage-reconcile-*.json; do
    [ -f "$f" ] || continue
    klass=$(python3 -c "import json; print(json.load(open('$f'))['class'])")
    mand=$(python3 -c "import json; print(json.load(open('$f'))['applicable_mandatory_count'])")
    att=$(python3 -c "import json; print(json.load(open('$f'))['attempted_count'])")
    gaps=$(python3 -c "import json; d=json.load(open('$f')); print(', '.join(d['gaps']) or 'none')")
    echo "| $klass | $mand | $att | $gaps |" >> "$out"
  done

  if [ -f "$workdir/coverage-gaps.txt" ] && [ -s "$workdir/coverage-gaps.txt" ]; then
    echo "" >> "$out"
    echo "### Coverage gap reasons" >> "$out"
    echo "" >> "$out"
    echo '```' >> "$out"
    cat "$workdir/coverage-gaps.txt" >> "$out"
    echo '```' >> "$out"
  fi
}

# At the end of the main report-generation function, call:
# append_coverage_gap_appendix "${WORKDIR}" "${REPORT_OUT}"
```

If the existing `generate-report.sh` structure makes inserting the call tricky, locate the final `cat > "$REPORT_OUT" <<EOF` block and add a follow-up call to `append_coverage_gap_appendix "$WORKDIR" "$REPORT_OUT"` after that block.

- [ ] **Step 4: Run test, confirm it passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_coverage_gap_appendix.sh
```

Expected: T1, T2, T3 pass, `ALL PASS`.

- [ ] **Step 5: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/generate-report.sh skills/BugBountyHunter-v4/lib/ && \
cp ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_coverage_gap_appendix.sh skills/BugBountyHunter-v4/tests/smoke/ && \
git add skills/BugBountyHunter-v4/{lib/generate-report.sh,tests/smoke/test_coverage_gap_appendix.sh} && \
git commit -m "feat(v4): add Coverage Gap appendix to generate-report.sh"
```

---

### Task 6.3: Wire SKILL.md Phase 4

**Files:**
- Modify: `~/.claude/skills/BugBountyHunter-v4/SKILL.md`

- [ ] **Step 1: Replace the Phase 4 placeholder**

Find the line in SKILL.md:

```
## Phase 4 — Report generation

(Wired in next plan phase.)
```

Replace with:

````markdown
## Phase 4 — Report generation

After Phase 3.5 Curator completes:

```bash
REPORT_OUT="$HOME/Documents/Pentests/${ENGAGEMENT_ID}/report.md"
mkdir -p "$(dirname "$REPORT_OUT")"

bash "${SKILL}/lib/generate-report.sh" \
  --workdir "${WORKDIR}" \
  --output "${REPORT_OUT}"

# Cleanup background processes
for pidfile in "${WORKDIR}"/*.pid; do
  [ -f "$pidfile" ] || continue
  kill "$(cat "$pidfile")" 2>/dev/null || true
  rm -f "$pidfile"
done

# Final state
bun "${SKILL}/lib/orchestrator.ts" --advance --workdir "${WORKDIR}"
bun "${SKILL}/lib/orchestrator.ts" --status --workdir "${WORKDIR}"

echo "[DONE] Report at: ${REPORT_OUT}"
echo "[DONE] Engagement: ${ENGAGEMENT_ID}"
echo "[DONE] KB DEFER stubs (review these): ${KB}/99-Inbox/"
```

The report contains:

1. Executive summary
2. Engagement scope
3. Findings summary (validated_findings[])
4. Coverage report table (per-class mandatory / attempted / gaps)
5. Coverage gap reasons (from coverage-gaps.txt)
6. Detailed findings
7. Methodology reference (links to KB doctrine)

Findings are operator-editable before submission to the bug bounty
program.
````

- [ ] **Step 2: Verify SKILL.md has no remaining placeholders**

```bash
grep -nE "(Landed in subsequent|TODO|TBD|placeholder)" ~/.claude/skills/BugBountyHunter-v4/SKILL.md
```

Expected: zero output.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/SKILL.md skills/BugBountyHunter-v4/ && \
git add skills/BugBountyHunter-v4/SKILL.md && \
git commit -m "feat(v4): wire SKILL.md Phase 4 report generation + cleanup"
```

---

## Phase 7 — Acceptance verification

Final phase. Port remaining v3 smoke tests, run end-to-end test, verify spec Section 12 acceptance criteria, write `sync-to-project.sh` helper, final commit.

### Task 7.1: Port remaining v3 smoke tests

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/smoke/` (additional ports)

- [ ] **Step 1: Identify v3 smoke tests not yet ported**

```bash
ls ~/.claude/skills/BugBountyHunter-v3-experimental/tests/smoke/*.sh | xargs -n1 basename | sort > /tmp/v3-tests.txt
ls ~/.claude/skills/BugBountyHunter-v4/tests/smoke/*.sh 2>/dev/null | xargs -n1 basename | sort > /tmp/v4-tests.txt
diff /tmp/v3-tests.txt /tmp/v4-tests.txt
```

This lists v3 tests not in v4. Expected: several tests like `test_state_schema.sh`, `test_refresh_monitor.sh`, `test_atomic_write.sh`, `test_score_candidates.sh`, etc.

- [ ] **Step 2: Port each unported v3 smoke test**

For every v3 test not in v4:

```bash
TEST_NAME=test_state_schema   # repeat per test
cp ~/.claude/skills/BugBountyHunter-v3-experimental/tests/smoke/${TEST_NAME}.sh \
   ~/.claude/skills/BugBountyHunter-v4/tests/smoke/${TEST_NAME}.sh
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/smoke/${TEST_NAME}.sh

# Path replacements
sed -i 's|BugBountyHunter-v3-experimental|BugBountyHunter-v4|g' \
  ~/.claude/skills/BugBountyHunter-v4/tests/smoke/${TEST_NAME}.sh
sed -i 's|/tmp/pentest-{{ID}}|${WORKDIR}|g' \
  ~/.claude/skills/BugBountyHunter-v4/tests/smoke/${TEST_NAME}.sh
sed -i 's|data/HackerOnePrecedents.jsonl|/home/adlt/Documents/BugBountyKB/references/hackerone-precedents.jsonl|g' \
  ~/.claude/skills/BugBountyHunter-v4/tests/smoke/${TEST_NAME}.sh
```

Repeat for each: `test_state_schema.sh`, `test_refresh_monitor.sh`, `test_refresh_failure.sh`, `test_stale_watcher.sh`, `test_atomic_write.sh`, `test_score_candidates.sh`, `test_broker_compliance.sh`, `test_evidence_rules.sh`, `test_chain_patterns_sso.sh`, `test_race_detection.sh`, `test_account_mode_detection.sh`, `test_advocate_rules_present.sh`, `test_apr18_full_regression.sh`, `test_apr_fixtures.sh`, `test_artifact_matrix_evidence_rules_coverage.sh`, `test_artifact_matrix_schema.sh`, `test_attack_output_contract.sh`, `test_mode_injection_marker.sh`, `test_phase29_apr18_regression.sh`, `test_phase29_chain_constituent.sh`, `test_phase29_missing_artifact.sh`, `test_phase29_partial_idor_guard.sh`, `test_phase29_program_excluded.sh`, `test_phase29_public_safe_list.sh`.

- [ ] **Step 3: Port test fixtures**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/tests/fixtures
cp -r ~/.claude/skills/BugBountyHunter-v3-experimental/tests/fixtures/* \
      ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/

# Apply same path replacements to JSON fixtures
find ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/ -name "*.json" | while read f; do
  sed -i 's|/tmp/pentest-{{ID}}|/tmp/pentest-test|g' "$f"
done
```

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp -r ~/.claude/skills/BugBountyHunter-v4/tests/smoke/* skills/BugBountyHunter-v4/tests/smoke/ && \
cp -r ~/.claude/skills/BugBountyHunter-v4/tests/fixtures/* skills/BugBountyHunter-v4/tests/fixtures/ && \
git add skills/BugBountyHunter-v4/tests/ && \
git commit -m "test(v4): port v3 smoke tests + fixtures (~24 additional tests)"
```

---

### Task 7.2: Write `lib/sync-to-project.sh` helper

Avoids manual `cp` for each task by providing a single command to sync canonical skill → project mirror.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh`

- [ ] **Step 1: Write the helper**

Content for `~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh`:

```bash
#!/usr/bin/env bash
# sync-to-project.sh — copy canonical skill files to project repo mirror.
#
# Usage:
#   bash sync-to-project.sh [--check]
#
# --check: print diff between canonical and mirror; exit 1 if drift.

set -euo pipefail

SRC="$HOME/.claude/skills/BugBountyHunter-v4"
DST="/home/adlt/Documents/Projects/bug-bounty-hunter/skills/BugBountyHunter-v4"

[ -d "$SRC" ] || { echo "[FAIL] canonical missing: $SRC" >&2; exit 1; }
[ -d "$DST" ] || { echo "[FAIL] mirror missing: $DST" >&2; exit 1; }

if [ "${1:-}" = "--check" ]; then
  echo "[check] diff $SRC → $DST"
  diff -rq "$SRC" "$DST" --exclude=node_modules --exclude=bun.lockb --exclude=.scratch || true
  exit 0
fi

# Sync everything except runtime/build cruft
rsync -a --delete \
  --exclude=node_modules \
  --exclude=bun.lockb \
  --exclude=.scratch \
  --exclude=*.log \
  "$SRC"/ "$DST"/

echo "[sync] $SRC → $DST done"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh
```

- [ ] **Step 2: Test it**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh
bash ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh --check
```

Expected: sync completes, `--check` reports no drift.

- [ ] **Step 3: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
cp ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh skills/BugBountyHunter-v4/lib/ && \
git add skills/BugBountyHunter-v4/lib/sync-to-project.sh && \
git commit -m "feat(v4): add sync-to-project.sh helper for canonical↔mirror parity"
```

---

### Task 7.3: End-to-end test against synthetic target

Tests the full pipeline with a mocked HTTP target. Uses Python's `http.server` to serve a vulnerable surface.

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/e2e/test_full_pipeline.sh`
- Create: `~/.claude/skills/BugBountyHunter-v4/tests/e2e/mock-target.py`

- [ ] **Step 1: Write mock target**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter-v4/tests/e2e
```

Content for `~/.claude/skills/BugBountyHunter-v4/tests/e2e/mock-target.py`:

```python
#!/usr/bin/env python3
"""Minimal vulnerable HTTP target for v4 e2e testing.

Endpoints:
  /search?q=<text>       — reflects q in HTML response (XSS sink)
  /api/users/<id>        — returns user data; no authz check (IDOR sink)
  /                      — landing page
"""
import http.server
import socketserver
import re
import json
import sys
import urllib.parse

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765

USERS = {
    "1": {"id": "1", "name": "Account A", "email": "a@example.com", "ssn": "111-11-1111"},
    "2": {"id": "2", "name": "Account B", "email": "b@example.com", "ssn": "222-22-2222"},
}

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/":
            self._send(200, "text/html", "<h1>mock target</h1>")
        elif u.path == "/search":
            q = qs.get("q", [""])[0]
            self._send(200, "text/html", f"<p>Search results for: {q}</p>")  # reflected
        elif (m := re.match(r"^/api/users/(\d+)$", u.path)):
            uid = m.group(1)
            if uid in USERS:
                self._send(200, "application/json", json.dumps(USERS[uid]))
            else:
                self._send(404, "application/json", '{"error":"not found"}')
        else:
            self._send(404, "text/plain", "not found")

    def _send(self, status, ct, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), H) as httpd:
    print(f"mock target on http://127.0.0.1:{PORT}", flush=True)
    httpd.serve_forever()
```

- [ ] **Step 2: Write e2e test**

Content for `~/.claude/skills/BugBountyHunter-v4/tests/e2e/test_full_pipeline.sh`:

```bash
#!/usr/bin/env bash
# End-to-end pipeline test. Uses the mock target to exercise Phase 0 →
# Phase 4 with minimal real recon (the orchestrator's gates fire but
# attack-agent dispatch is mocked via fixture results).
set -euo pipefail
SKILL_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

PORT=8765
WORK=/tmp/bbh-v4-e2e
rm -rf "$WORK"

# Start mock target
python3 "${SKILL_DIR}/tests/e2e/mock-target.py" $PORT &
MOCK_PID=$!
trap "kill $MOCK_PID 2>/dev/null || true; rm -rf $WORK" EXIT
sleep 0.5

# 1. Validate KB at startup
bash "${SKILL_DIR}/lib/validate-playbook.sh" --all ~/Documents/BugBountyKB \
  || { echo "FAIL: KB invalid"; exit 1; }

# 2. Create engagement
bun "${SKILL_DIR}/lib/orchestrator.ts" --create \
  --target "http://127.0.0.1:${PORT}" \
  --mode bounty \
  --workdir "$WORK" \
  --kb ~/Documents/BugBountyKB

[ -f "$WORK/state.json" ] || { echo "FAIL: state.json not created"; exit 1; }

# 3. Stage scope-allowlist
echo "127.0.0.1" > "$WORK/scope-allowlist.txt"

# 4. Stage minimal recon capabilities (skipping live R1-R4 for e2e)
python3 - <<PY
import json
state = json.load(open("$WORK/state.json"))
state["recon"] = {
    "capabilities": {
        "has_query_param_endpoints": True,
        "has_numeric_id_endpoints": True,
        "has_user_profile_fields": False,
        "has_user_generated_content": False,
        "has_json_endpoints": True,
        "has_client_side_routing": False,
        "has_postmessage_handlers": False,
        "has_markdown_render": False,
        "has_dompurify": False,
        "has_svg_upload": False,
        "has_inline_pdf": False,
        "angular_version_lt_1_6": False,
        "has_template_engine": False,
        "has_react_or_vue": False,
        "waf_detected": False,
        "csp_has_unsafe_eval_or_unsafe_inline": False,
        "has_uuid_endpoints": False,
        "has_composite_key_endpoints": False,
        "has_versioned_api": False,
        "has_writable_json_endpoints": False,
        "has_writable_endpoints": False,
        "graphql": False,
        "websocket": False
    }
}
json.dump(state, open("$WORK/state.json", "w"), indent=2)
PY

# 5. Stage mock attack-agent outputs
mkdir -p "$WORK/agents"
cat > "$WORK/agents/xss-results.json" <<'JSON'
{ "agent_id": "xss-1", "class": "xss", "engagement_id": "test",
  "coverage": [
    { "id": "T-XSS-01", "attempted": true, "evidence_artifact": "/tmp/e/F-1", "verdict": "exploited" },
    { "id": "T-XSS-15", "attempted": true, "evidence_artifact": "/tmp/e/F-2", "verdict": "not_exploited" }
  ],
  "findings": [], "proposed_additions": [] }
JSON
cat > "$WORK/agents/idor-results.json" <<'JSON'
{ "agent_id": "idor-1", "class": "idor", "engagement_id": "test",
  "coverage": [
    { "id": "T-IDOR-01", "attempted": true, "evidence_artifact": "/tmp/e/F-3", "verdict": "exploited" },
    { "id": "T-IDOR-03", "attempted": true, "evidence_artifact": "/tmp/e/F-4", "verdict": "not_exploited" },
    { "id": "T-IDOR-05", "attempted": true, "evidence_artifact": "/tmp/e/F-5", "verdict": "not_exploited" },
    { "id": "T-IDOR-07", "attempted": false, "gap_reason": "no_matching_endpoint" },
    { "id": "T-IDOR-08", "attempted": true, "evidence_artifact": "/tmp/e/F-7", "verdict": "not_exploited" },
    { "id": "T-IDOR-09", "attempted": true, "evidence_artifact": "/tmp/e/F-8", "verdict": "not_exploited" },
    { "id": "T-IDOR-10", "attempted": true, "evidence_artifact": "/tmp/e/F-9", "verdict": "not_exploited" },
    { "id": "T-IDOR-11", "attempted": true, "evidence_artifact": "/tmp/e/F-10", "verdict": "not_exploited" },
    { "id": "T-IDOR-12", "attempted": true, "evidence_artifact": "/tmp/e/F-11", "verdict": "not_exploited" }
  ],
  "findings": [], "proposed_additions": [] }
JSON

# 6. Run coverage reconciliation
echo "--- reconcile xss ---"
bash "${SKILL_DIR}/lib/reconcile-coverage.sh" --workdir "$WORK" --class xss --kb ~/Documents/BugBountyKB || true

echo "--- reconcile idor ---"
bash "${SKILL_DIR}/lib/reconcile-coverage.sh" --workdir "$WORK" --class idor --kb ~/Documents/BugBountyKB || true

# 7. Verify reconcile produced reports
[ -f "$WORK/coverage-reconcile-xss.json" ] || { echo "FAIL: no XSS reconcile report"; exit 1; }
[ -f "$WORK/coverage-reconcile-idor.json" ] || { echo "FAIL: no IDOR reconcile report"; exit 1; }

# 8. Verify final state
bun "${SKILL_DIR}/lib/orchestrator.ts" --status --workdir "$WORK" | tail -30

echo "E2E PASS"
```

```bash
chmod +x ~/.claude/skills/BugBountyHunter-v4/tests/e2e/test_full_pipeline.sh
```

- [ ] **Step 3: Run the e2e test**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/e2e/test_full_pipeline.sh
```

Expected: KB validates, engagement created, reconcile produces reports for XSS + IDOR, status renders, `E2E PASS`.

- [ ] **Step 4: Mirror and commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
bash ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh && \
git add skills/BugBountyHunter-v4/tests/e2e/ && \
git commit -m "test(v4): add e2e test with mock HTTP target — full pipeline through reconcile"
```

---

### Task 7.4: Acceptance criteria verification

Verify every acceptance criterion from spec Section 12.

- [ ] **Step 1: `validate-playbook.sh` passes against v1 KB**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/validate-playbook.sh --all ~/Documents/BugBountyKB
echo "exit=$?"
```

Expected: 2 `[OK]` lines (xss + idor), `exit=0`.

- [ ] **Step 2: All smoke tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && \
PASS=0; FAIL=0
for t in tests/smoke/*.sh; do
  if bash "$t" > /tmp/test.out 2>&1; then
    echo "[PASS] $t"; PASS=$((PASS + 1))
  else
    echo "[FAIL] $t"; FAIL=$((FAIL + 1))
    cat /tmp/test.out
  fi
done
echo "TOTAL: pass=$PASS fail=$FAIL"
```

Expected: `fail=0`, `pass>=8` (count depends on how many v3 ports landed; minimum 8 from new tests).

- [ ] **Step 3: Bun unit tests pass**

```bash
cd ~/.claude/skills/BugBountyHunter-v4 && bun test
```

Expected: 8 unit tests pass.

- [ ] **Step 4: End-to-end test passes**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/e2e/test_full_pipeline.sh
```

Expected: `E2E PASS`.

- [ ] **Step 5: Bounty-hallucination canary fires**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/tests/smoke/test_bounty_hallucination_canary.sh
```

Expected: PASS.

- [ ] **Step 6: KB↔skill sync clean**

```bash
bash ~/.claude/skills/BugBountyHunter-v4/lib/sync-to-project.sh --check
```

Expected: no drift output.

- [ ] **Step 7: Spec Section 12 deliverables checklist**

```bash
cd ~/.claude/skills/BugBountyHunter-v4
echo "=== KB deliverables ==="
for f in \
  agents/agent-operating-manual.md playbooks/xss.md playbooks/idor.md \
  checklists/target-intake.md checklists/evidence-quality.md \
  checklists/non-dos-filter.md checklists/reportability.md \
  checklists/scope-sweep.md taxonomy/owasp-class-catalog.md \
  templates/finding-report.md templates/security-assessment-report.md \
  templates/novelty-proposal-stub.md workflows/end-to-end-pentest.md \
  references/hackerone-precedents.jsonl references/cve-research-anchors.md \
  maintenance/curation-rules.md README.md VERSION
do
  [ -f ~/Documents/BugBountyKB/$f ] && echo "OK $f" || echo "MISSING $f"
done

echo "=== Skill deliverables ==="
for f in \
  SKILL.md package.json tsconfig.json config/finding-schema.json \
  config/ArtifactMatrix.yaml config/PublicSafeList.yaml \
  Agents/AppReviewAgent.md Agents/XSSAgent.md Agents/IDORAgent.md \
  Agents/Advocate.md Agents/Triager.md Agents/Curator.md \
  Agents/recon-r1-assets.md Agents/recon-r2-content.md \
  Agents/recon-r3-fingerprint.md Agents/recon-r4-js-analysis.md \
  Agents/auth-acquire.md \
  lib/orchestrator.ts lib/types.ts lib/state-machine.ts \
  lib/validate-playbook.sh lib/reconcile-coverage.sh lib/curator-batch.sh \
  lib/phase29-gate.sh lib/phase3-debate.sh lib/precedent-lookup.sh \
  lib/refresh-monitor.sh lib/session-warmer.sh lib/stale-watcher.sh \
  lib/detect-account-mode.sh lib/phase2-merge.sh \
  lib/yaml2json.sh lib/validate-state-schema.sh \
  lib/generate-report.sh lib/sync-to-project.sh \
  Workflows/W_HUNT_WEB.md
do
  [ -f $f ] && echo "OK $f" || echo "MISSING $f"
done
```

Expected: all `OK`, zero `MISSING`.

---

### Task 7.5: Final v3 archive + cutover note

After acceptance passes, archive v3 with a deprecation marker (don't delete — preserve for fallback).

**Files:**
- Create: `~/.claude/skills/BugBountyHunter-v3-experimental/DEPRECATED.md`

- [ ] **Step 1: Write deprecation note**

Content for `~/.claude/skills/BugBountyHunter-v3-experimental/DEPRECATED.md`:

```markdown
# v3 Deprecated

Superseded by `BugBountyHunter-v4` as of 2026-05-23.

v4 lives at `~/.claude/skills/BugBountyHunter-v4/`. Spec:
`~/Documents/Projects/bug-bounty-hunter/docs/superpowers/specs/2026-05-21-bug-bounty-v4-design.md`.
Implementation plan:
`~/Documents/Projects/bug-bounty-hunter/docs/superpowers/plans/2026-05-23-bug-bounty-v4-implementation.md`.

This directory remains intact as a fallback. To re-enable v3 dispatch:

- Trigger words "v3", "auth-first pentest", "experimental pentest" still
  route here per the existing SKILL.md description.
- Plain "pentest" routes to v2 (BugBountyHunter); "v4" / "kb pentest" /
  "coverage pentest" / "bbh v4" route to v4.

v3 will be removed in a future cleanup once v4 has 3+ successful
engagements logged.
```

- [ ] **Step 2: Commit**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
mkdir -p skills/BugBountyHunter-v3-experimental && \
cp ~/.claude/skills/BugBountyHunter-v3-experimental/DEPRECATED.md skills/BugBountyHunter-v3-experimental/ && \
git add skills/BugBountyHunter-v3-experimental/DEPRECATED.md && \
git commit -m "docs(v3): mark BugBountyHunter-v3-experimental deprecated in favor of v4"
```

- [ ] **Step 3: Final repo state**

```bash
cd /home/adlt/Documents/Projects/bug-bounty-hunter && \
git status && \
git log --oneline -20
```

Expected: clean tree; ~40-50 commits since the spec commit (`bc494f6`).

**Phase 7 complete — v1 acceptance passes when:**

- `validate-playbook.sh --all` exits 0 against the v1 KB.
- All smoke tests pass (~30+ tests including ported v3 tests).
- Bun unit tests pass (8 tests).
- End-to-end test against mock target completes with `E2E PASS`.
- Bounty-hallucination canary still fires.
- Sync check between canonical skill and project mirror is clean.
- Every deliverable file from spec Section 12 is present.
- v3 marked deprecated with cutover note.

---

## Plan A Done

**End state:**

- KB v1 at `~/Documents/BugBountyKB/` with 2 seed playbooks + full doctrine + supporting checklists/templates/workflows/taxonomy/maintenance/references.
- Skill v4 at `~/.claude/skills/BugBountyHunter-v4/` with TypeScript orchestrator (`--resume`, `--status`, `--add-finding`), 17 ported/authored agents (5 recon + auth + AppReview + Advocate + Triager + Curator + XSS + IDOR), per-class executor template proven on 2 classes, 8 mechanical-gate shell scripts, validate-playbook + reconcile-coverage + curator-batch as new v1-critical infrastructure, end-to-end pipeline tests passing.
- Tracked mirror in project repo at `~/Documents/Projects/bug-bounty-hunter/skills/BugBountyHunter-v4/`.
- v3 marked deprecated, available as fallback.

**Next workstreams (out of scope for Plan A):**

- **Plan B — KB content authoring**: 16 remaining playbooks (SQLi, SSRF, Auth, CSRF, FileUpload, Deser, RaceCondition, BusinessLogic, APIRest, APIGraphQL, APIWebSocket, ClientSide, ProtocolSmuggling, ConfigExposure, LLM-PI, LLM-RAG) with Coverage Checklists. Per-class authoring with `validate-playbook.sh` as the quality gate. Estimated 40-80 hours focused.
- **Scaffold remaining 15 attack executors**: clone the XSSAgent template per class once the matching playbook is authored. Mechanical (~1 task per class, similar to Task 3.7).
- **v4.1**: vault, dashboard, Burp bridge, claude-mem integration.
- **v4.2**: mobile / cloud / network surfaces.

---

## Execution Handoff

Plan complete and committed. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task using `superpowers:subagent-driven-development`. Each subagent gets one task in isolation, reviews land between tasks, fast iteration. Best for a multi-day build where each task should be verifiable independently.

**2. Inline Execution** — I execute tasks in this session via `superpowers:executing-plans`. Batch execution with checkpoint reviews. Best when you want to watch the build happen live and intervene mid-task.

Which approach?
