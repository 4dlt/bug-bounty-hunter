---
title: BugBountyHunter v4 — KB-Driven Coverage-Enforced Pentest Orchestrator
status: locked
date: 2026-05-21
authors: Álvaro de la Torre
supersedes: BugBountyHunter-v3-experimental
related:
  - ~/.claude/skills/BugBountyHunter-v3-experimental/SKILL.md
  - ~/Documents/Projects/vuln_db/README.md
  - ~/.claude/MEMORY/WORK/20260520-231806_compare-bug-bounty-skills/PRD.md
---

# BugBountyHunter v4 — Design Spec

## 1. Problem & motivation

v3's adversarial validation (Advocate↔Triager + ArtifactMatrix + PublicSafeList +
HackerOnePrecedents) is best-in-class at blocking bounty hallucinations, but the
v3 operator surface is brittle: technique knowledge lives in long agent prompts
inside the skill, attack coverage is LLM-self-reported with no mechanical
reconciliation, there is no per-target-type routing, no first-class app
profiling phase, and no flow for the system to learn from engagements over
time.

h4ckologic/bughunter-ai ships a cleaner operator surface (state machine, per-
target workflows, AppReview-driven hypothesis attacks, agent-per-class structure)
but no mechanical validation backbone — pure CVSS + zero-day-keyword filtering,
no precedent enforcement, no required-artifact gates, no adversarial debate.

vuln_db ships a working pattern for an agent-routeable KB: doctrine in
`agents/agent-operating-manual.md`, per-class knowledge in `playbooks/`,
supporting `queries/`, `checklists/`, `taxonomy/`, `templates/`, `workflows/`,
`maintenance/`, `references/`, `evals/`. Markdown, git-tracked, human-
readable, machine-parseable.

v4 lifts h4ckologic's operator-surface improvements onto v3's mechanical
validation backbone, with a vuln_db-style external KB at the top.

## 2. Non-goals

- Not a credential vault (deferred to v4.1).
- Not mobile / cloud / network pentest at v1 (deferred to v4.2).
- Not an Obsidian-app-driven workflow (KB is markdown that Obsidian can open;
  no wikilinks, graph view, dataview, or sync are load-bearing).
- Not a vector / embedding KB (markdown + stable IDs serve both human and
  machine readers; mechanical reconciliation requires stable IDs).
- Not a real-time WebSearch-driven runtime knowledge layer (WebSearch finds
  during a run become Curator-eligible `proposed_additions`, not direct
  runtime inputs — quality controlled, one cycle delayed).

## 3. Architecture overview

Two repositories, versioned independently:

- **`~/Documents/BugBountyKB/`** — the KB. Git-tracked. Portable. Doctrine only.
  Could be consumed by any future runner. Mirrors vuln_db structure.
- **`~/.claude/skills/BugBountyHunter-v4/`** — the skill. The orchestrator,
  per-class executor agents, mechanical-gate config and shell scripts,
  smoke tests, wire-contract JSON schema. Coupled to Claude Code's Agent tool
  semantics.

v4 ships **alongside** v3-experimental, not replacing it. v3 remains
addressable until v4 is stable.

### Filesystem layout

```
~/Documents/BugBountyKB/
├── README.md
├── agents/
│   └── agent-operating-manual.md
├── playbooks/                                  (~18 at v1)
│   ├── xss.md
│   ├── sqli.md
│   ├── idor.md
│   ├── ssrf.md
│   ├── auth.md
│   ├── csrf.md
│   ├── file-upload.md
│   ├── deserialization.md
│   ├── race-condition.md
│   ├── business-logic.md
│   ├── api-rest.md
│   ├── api-graphql.md
│   ├── api-websocket.md
│   ├── client-side.md
│   ├── protocol-smuggling.md
│   ├── config-exposure.md
│   ├── llm-prompt-injection.md
│   └── llm-rag-tool-boundary.md
├── payloads/                                   (renamed from vuln_db's queries/)
├── checklists/
├── taxonomy/
├── templates/
├── workflows/
├── references/
│   ├── hackerone-precedents.jsonl              (Curator appends; was in v3 skill data/)
│   └── cve-research-anchors.md
├── maintenance/
│   └── curation-rules.md
├── evals/
│   └── fixtures/
└── 99-Inbox/                                   (Curator DEFER_TO_HUMAN drop)

~/.claude/skills/BugBountyHunter-v4/
├── SKILL.md
├── Agents/
│   ├── AppReviewAgent.md                       (Opus)
│   ├── XSSAgent.md                             (Sonnet — and similarly all attack executors)
│   ├── SQLiAgent.md
│   ├── IDORAgent.md
│   ├── SSRFAgent.md
│   ├── AuthAgent.md
│   ├── CSRFAgent.md
│   ├── FileUploadAgent.md
│   ├── DeserializationAgent.md
│   ├── RaceConditionAgent.md
│   ├── BusinessLogicAgent.md
│   ├── APIRestAgent.md
│   ├── APIGraphQLAgent.md
│   ├── APIWebSocketAgent.md
│   ├── ClientSideAgent.md
│   ├── ProtocolSmugglingAgent.md
│   ├── ConfigExposureAgent.md
│   ├── LLMSecurityAgent.md
│   ├── Advocate.md                             (Opus)
│   ├── Triager.md                              (Opus)
│   └── Curator.md                              (Opus, batched)
├── lib/
│   ├── orchestrator.ts                         (NEW — TypeScript state machine)
│   ├── validate-playbook.sh                    (NEW — v1 critical-path)
│   ├── reconcile-coverage.sh                   (NEW — Phase 2.5)
│   ├── curator-batch.sh                        (NEW — Phase 3.5)
│   ├── phase29-gate.sh                         (carried fwd from v3)
│   ├── phase3-debate.sh                        (carried fwd from v3)
│   ├── phase2-merge.sh                         (carried fwd from v3)
│   ├── refresh-monitor.sh                      (carried fwd from v3)
│   ├── session-warmer.sh                       (carried fwd from v3)
│   ├── stale-watcher.sh                        (carried fwd from v3)
│   └── (all other v3 lib utilities)
├── config/
│   ├── ArtifactMatrix.yaml                     (carried fwd — skill-side enforcement)
│   ├── PublicSafeList.yaml                     (carried fwd)
│   └── finding-schema.json                     (NEW — executor↔orchestrator wire contract)
├── Workflows/                                  (NEW — per-target-type routing)
│   ├── W_HUNT_WEB.md
│   ├── W_HUNT_API.md
│   └── W_HUNT_LLM.md
└── tests/
    └── smoke/                                  (v3 tests + new Coverage Checklist + Curator tests)
```

## 4. The Coverage Checklist contract

The load-bearing primitive of v4. Coverage is mechanically verifiable, not
LLM-self-reported.

### 4.1 Playbook YAML shape

Every playbook ends with a `## Coverage Checklist` section containing a single
fenced YAML block:

```yaml
techniques:
  - id: T-IDOR-01
    name: Sequential ID enumeration
    mandatory: true
    proof_required: cross_account_data_read
    applies_when: recon.capabilities.endpoints_with_numeric_id

  - id: T-IDOR-07
    name: Mass assignment with role/permission injection
    mandatory: true
    proof_required: privilege_escalation_or_data_corruption
    applies_when: recon.capabilities.writable_json_endpoints

  - id: T-IDOR-16
    name: GraphQL node-id enumeration via global IDs
    mandatory:
      when: recon.capabilities.graphql == true
    proof_required: cross_account_data_read
```

- **`id`**: stable identifier `T-<CLASS>-<NN>`. Never re-used after removal;
  removed IDs go to a tombstone list in the playbook footer.
- **`mandatory`**: `true` | `false` | `when: <expression>`. `false` means
  opportunistic; not part of the coverage guarantee.
- **`proof_required`**: free-form string describing the proof type. The Triager
  interprets it at validation time (LLM-judged — documented compromise in
  `agents/agent-operating-manual.md`).
- **`applies_when`**: JMESPath-style query against
  `state.json.recon.capabilities`. R3 (fingerprinting) is now responsible for
  emitting structured capability flags.

### 4.2 Validation

`lib/validate-playbook.sh` enforces:
- All playbooks have a `## Coverage Checklist` section with valid YAML.
- All `id` fields match `T-<CLASS>-<NN>` and are unique.
- All `mandatory.when` expressions parse against a stub recon capability set.
- All `proof_required` values are non-empty strings.
- Removed IDs appear in the tombstone list.

Runs at orchestrator startup (hard-fails the run) and pre-commit (blocks the
commit). Without this, malformed YAML degrades into silent partial coverage,
collapsing v4 into v3.

### 4.3 Reconciliation (Phase 2.5)

`lib/reconcile-coverage.sh` runs after every attack-phase batch:

1. Parse every Coverage Checklist for classes covered by the current workflow.
2. Filter techniques whose `applies_when` evaluates true against
   `state.json.recon.capabilities`.
3. For each filtered, `mandatory==true` technique, verify the corresponding
   agent emitted a `coverage[]` entry with `attempted: true`.
4. For each gap, dispatch a focused follow-up agent containing only the gap
   IDs as its run queue.
5. Maximum 2 follow-up rounds per agent. Remaining gaps logged to
   `coverage-gaps.txt` with the specific reason
   (WAF-blocked / no matching endpoint / agent timeout / explicit refusal).

### 4.4 Novelty channel

After exhausting the mandatory queue, the attack agent attempts creative
variants and emits each one as a `proposed_additions[]` entry:

```json
{
  "class": "xss",
  "proposed_name": "CSS Typed OM mutation observer escape",
  "family": "dom",
  "red_flags": ["..."],
  "proof_targets": ["..."],
  "fix_patterns": ["..."],
  "evidence_artifact_path": "/tmp/eng/findings/F-A-007/evidence.har"
}
```

These flow to the Curator in Phase 3.5.

## 5. Phase pipeline

```
Phase 0    Scope compliance                                    (carried fwd)
Phase 1a   Passive recon                                       (carried fwd)
Phase 1b   Auth acquisition + background helpers               (carried fwd)
Phase 1c   Active authenticated recon (R1-R4)                  (R3 NEW: emits recon.capabilities)
Phase 1d   AppReview (Opus)                                    NEW
           → app-profile.json: crown jewels + per-flow hypotheses
           → hypotheses set DEPTH/PRIORITY only, NOT gating
Phase 2    Per-class attack executors (Sonnet, batched)        (extended from v3)
           → each parses Coverage Checklist of its playbook
           → emits coverage[], findings[], proposed_additions[]
Phase 2.5  Coverage reconciliation                             NEW
           → reconcile-coverage.sh detects gaps
           → dispatches focused follow-up agents (max 2 rounds)
           → unrecovered gaps → coverage-gaps.txt
Phase 2.9  Mechanical artifact gate                            (carried fwd)
           → phase29-gate.sh: program_excluded, missing_artifact,
             public_by_design, chain-constituent rejected
Phase 3    Advocate↔Triager debate (Opus × Opus, per finding)  (carried fwd)
           → ACCEPT + precedent + high/med confidence → validated_findings[]
           → else → triager_closed[]
           → ties go to close
Phase 3.5  Curator (Opus, batched 5-8 per invocation)          NEW
           → reads proposed_additions[] across all agents
           → per proposal verdict from taxonomy:
               NEW | VARIANT_OF: T-X-NN | DUPLICATE_OF: T-X-NN
                   | REJECT_LOW_QUALITY | DEFER_TO_HUMAN
           → git-commits accepted into BugBountyKB
             (commit convention: `playbook(<class>): add T-<class>-<NN> (<name>)`)
           → DEFER drops markdown stub into BugBountyKB/99-Inbox/
           → also appends new precedent rows to
             references/hackerone-precedents.jsonl when engagement produces
             a "resolved" outcome
Phase 4    Report generation                                   (carried fwd)
           → findings report + coverage-gap appendix
```

Phase gate protocol from v3 carries forward unchanged — every transition has a
gate, no phase can be silently skipped.

## 6. Model routing

Pin model versions explicitly in the orchestrator dispatcher. As of v4 design
date, that's `claude-opus-4-7` and `claude-sonnet-4-6`. Bump in lockstep when
new model versions are validated against the smoke-test suite.

| Role | Model | Rationale |
|------|-------|-----------|
| Orchestrator (primary) | Opus 4.7 | Adversarial reasoning, debate resolution, mode classification |
| AppReviewAgent | Opus 4.7 | Single-shot per engagement; output amplifies into all downstream attacks |
| Auth-acquire | Opus 4.7 | Gates the whole pipeline; must be careful |
| Recon R1-R4 | Sonnet 4.6 | Data gathering; high-throughput |
| Attack executors (all `<Class>Agent.md`) | Sonnet 4.6 | High-throughput per-class; less blocked per Álvaro's experience; cheaper at parallel scale |
| Advocate | Opus 4.7 | Adversarial reasoning, severity calibration |
| Triager | Opus 4.7 | Adversarial reasoning, must spot weak claims |
| Curator | Opus 4.7 | KB maintenance, novelty matrix, conservative bias |

Skill-side spawn pattern:

```typescript
// Attack executor
Agent({
  subagent_type: "Pentester",
  model: "sonnet",
  description: `${className} attack executor`,
  prompt: interpolate(Agents/${className}Agent.md, templateVars),
  run_in_background: true,
})

// Validation / curation
Agent({
  subagent_type: "Pentester",
  model: "opus",
  description: "Advocate for F-A-007",
  prompt: ...,
})
```

Model is configured per-agent in the skill SKILL.md dispatch logic. KB
playbooks have no model annotation.

## 7. Per-class agent file shape

Each `Agents/<Class>Agent.md` is ~80 lines and structured:

```markdown
---
class: xss
playbook: ~/Documents/BugBountyKB/playbooks/xss.md
model: sonnet
mandate: Coverage Checklist exhaustion + novelty discovery
---

# XSS Attack Executor

## Step 1 — Load doctrine
Read ~/Documents/BugBountyKB/agents/agent-operating-manual.md
Read ~/Documents/BugBountyKB/playbooks/xss.md

## Step 2 — Parse Coverage Checklist
Extract the `techniques:` YAML. For each item where mandatory==true
(or mandatory.when evaluates true against state.json.recon.capabilities),
add it to your run queue.

## Step 3 — Context (injected by orchestrator)
TARGET={{TARGET}}, WORKDIR={{WORKDIR}}, RATE={{AGENT_RATE}}
scope-allowlist={{WORKDIR}}/scope-allowlist.txt
AppProfile hint: {{APP_PROFILE_XSS_HINT}}    # priority weighting only, NOT gating

## Step 4 — Scope check (mandatory before every HTTP request)
{{check_scope_function}}

## Step 5 — Execute mandatory queue
For each T-ID:
  - attempt the technique
  - record evidence_artifact path
  - record verdict (exploited / not_exploited / inconclusive)
  - if gap_reason (WAF / no matching endpoint / timeout), record it

## Step 6 — Novelty channel
After mandatory queue exhausted, attempt creative variants.
For each novel variant: emit one proposed_additions[] entry.

## Step 7 — Output contract
Emit one JSON block at the end of your response matching
config/finding-schema.json:
  {
    "coverage": [{id, attempted, evidence_artifact, verdict, gap_reason?}],
    "findings": [...],
    "proposed_additions": [...]
  }
```

## 8. AppReviewAgent discipline (critical)

AppReview produces `app-profile.json` with:
- Application narrative
- Crown jewels
- Per-flow attack hypotheses with `attack_class` + `priority` + `rationale`
- Trust boundaries
- Tech stack → attack surface map
- AI/LLM feature detection

**Hard rule:** AppProfile hypotheses set **depth** and **priority weighting**
for attack executors. They do NOT gate which classes run. Every Coverage
Checklist mandatory item runs against any matching surface from recon,
regardless of whether AppReview flagged it.

This is the explicit guard against inheriting h4ckologic's blindspot.

## 9. Curator design

Curator runs as Opus, post Phase 3, in batches of 5-8 `proposed_additions[]`.
Multiple Curator invocations per engagement if proposal count exceeds 8.

### Verdict taxonomy

| Verdict | Action |
|---------|--------|
| `NEW` | Assign next T-ID; insert into playbook Coverage Checklist; git-commit. |
| `VARIANT_OF: T-X-NN` | Insert as a sub-bullet under T-X-NN's family/proof_target sections; git-commit. |
| `DUPLICATE_OF: T-X-NN` | Discard; log with T-X-NN reference in curator-log.jsonl. |
| `REJECT_LOW_QUALITY` | Discard; log reason (no evidence_artifact / unverifiable / weak proof target). |
| `DEFER_TO_HUMAN` | Drop markdown stub into `BugBountyKB/99-Inbox/<date>-<class>-<short-name>.md`. |

### Commit message convention

```
playbook(<class>): add T-<CLASS>-<NN> (<short name>)

Evidence: <evidence_artifact_path or summary>
Source engagement: <pentest-id>
Curator verdict: NEW (confidence: high)
```

### Curator failure modes

- If Curator times out mid-batch: log incomplete proposals to
  `BugBountyKB/99-Inbox/` with status `CURATOR_TIMEOUT` and continue.
- If Curator cannot decide (low-confidence in novelty matrix): default to
  `DEFER_TO_HUMAN`. Bias toward conservative KB additions.

### Precedent appending

When an engagement produces a "resolved" outcome (i.e., bounty payout received
or a definitive close code), Curator appends a row to
`BugBountyKB/references/hackerone-precedents.jsonl` with the program, class,
severity, payout (or close reason), and report URL. This grows the precedent
corpus over time.

## 10. Data / config split between KB and skill

| Lives in KB | Lives in skill |
|-------------|----------------|
| All playbooks (incl. Coverage Checklists) | `ArtifactMatrix.yaml` (enforcement config — Phase 2.9 reads to reject) |
| `agent-operating-manual.md` | `PublicSafeList.yaml` (enforcement config — Phase 2.9 reads to reject) |
| `hackerone-precedents.jsonl` | `finding-schema.json` (orchestrator-parser wire contract) |
| `payloads/`, `checklists/`, `taxonomy/` | `config/scope-schema.yaml` |
| `templates/`, `workflows/`, `references/` | All `lib/*.sh` and `lib/orchestrator.ts` |
| `maintenance/curation-rules.md` | All `Agents/*.md` |
| `evals/fixtures/` | `tests/smoke/` |

Reason: enforcement configs (ArtifactMatrix, PublicSafeList) are skill-coupled
— the orchestrator parses them to mechanically reject findings. Letting them
live in the KB would let Curator inadvertently relax acceptance criteria.

Reference data (HackerOnePrecedents) is research data that grows over time and
is class-agnostic; the KB is the right home.

## 11. Adopt from h4ckologic / Carry forward from v3 / Defer to v4.1

### Adopt (h4ckologic)
- AppReviewAgent → `app-profile.json` (with depth-not-gating discipline)
- Per-target-type workflow files (`W_HUNT_WEB/API/LLM.md`)
- TypeScript orchestrator (`lib/orchestrator.ts`) with `--resume` and `--status`
- Agent prompt frontmatter convention (`class:`, `playbook:`, `model:`, `mandate:`)
- Sessions under `~/.claude/MEMORY/BugBounty/Sessions/<slug>/` instead of `/tmp/pentest-<id>/`

### Carry forward (v3)
- Advocate↔Triager adversarial debate
- ArtifactMatrix.yaml + Phase 2.9 mechanical gate
- PublicSafeList.yaml mechanical filter
- HackerOnePrecedents (moves to KB; same load-bearing precedent rule)
- 4-question reportability test
- WAF detection + per-WAF payload routing
- Refresh-monitor + session-warmer + stale-watcher background processes
- Refusal recovery protocol (3-class taxonomy, hard cap on retries)
- Pipeline-mode detection (single-account / multi-account / unauthenticated)
- Bounty-hallucination canary smoke test
- Phase gate protocol (every transition has a gate)
- scope_check function injected into every attack agent
- State-schema validator

### Defer to v4.1 (or later)
- Credential vault (with real encryption or 1Password-only — never base64)
- Live dashboard (separate `--status` is in v4; full dashboard later)
- Mobile / Cloud / Network attack surfaces
- Burp MCP bridge (health check, scope sync, Collaborator polling)
- Cross-engagement memory aggregation
- claude-mem integration for prior-engagement recall
- Vector / embedding-based KB search (markdown is fine at current scale)

## 12. v1 deliverables

### KB v1 (~40-80 hours of focused authoring; critical path)
- 18 playbooks with Coverage Checklists (~10-25 techniques each → ~250-400 mandatory items)
- `agent-operating-manual.md`
- ~5 supporting checklists (target-intake, evidence-quality, non-dos-filter, reportability, scope-sweep)
- ~3 templates (finding-report, security-assessment-report, novelty-proposal-stub)
- README route map
- Seeded `references/hackerone-precedents.jsonl` (carry over v3 data)
- `maintenance/curation-rules.md`

### Skill v4 (engineering critical path)
- `SKILL.md` (~1000 lines — orchestrator entry + phase pipeline)
- 17 attack executor agents (~80 lines each)
- AppReviewAgent, Advocate, Triager, Curator (Opus agents)
- `lib/orchestrator.ts` (TypeScript state machine, `--resume`, `--status`)
- `lib/validate-playbook.sh`, `lib/reconcile-coverage.sh`, `lib/curator-batch.sh`
- All v3 lib utilities carried forward
- 3 workflow files (`W_HUNT_WEB/API/LLM.md`)
- `config/finding-schema.json`
- Smoke tests: v3 tests + new tests for Coverage Checklist validation, Curator merge, reconcile-coverage flow, finding-schema validation

### Acceptance criteria
- `lib/validate-playbook.sh` passes against the v1 KB.
- A test engagement (against a sanctioned target) executes all 8 phases without
  manual intervention, produces a coverage report, a findings report, and a
  Curator commit log.
- Coverage reconciliation correctly identifies gaps in a synthetic agent
  output and dispatches follow-ups.
- Curator correctly applies the verdict taxonomy on a synthetic
  `proposed_additions[]` set.
- All v3 smoke tests pass against v4 ports.
- Bounty-hallucination canary still fires (null precedent + non-null bounty
  never validates).

## 13. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Malformed YAML in a playbook silently shrinks coverage | `lib/validate-playbook.sh` hard-fails on startup AND pre-commit |
| AppReview misses a flow → blindspot | Coverage Checklist runs regardless of AppProfile; explicit hard rule in SKILL.md |
| Curator over-merges (accepts duplicates as novel) | Verdict taxonomy forces explicit `VARIANT_OF` / `DUPLICATE_OF` references; commit log greppable |
| Curator under-merges (rejects novel as duplicate) | DEFER_TO_HUMAN exists; Curator biased toward DEFER on low confidence |
| KB authoring burden underestimated | v1 deliverables explicitly call out 40-80 hour budget; partial v1 is acceptable if all 18 playbooks ship even with minimal Coverage Checklists |
| Coverage-reconcile follow-up dispatch cascades | Hard cap: 2 follow-up rounds per agent; remaining gaps logged, not retried |
| Skill ↔ KB version drift | `validate-playbook.sh` runs at orchestrator startup with a `KB_MIN_VERSION` check from a KB `VERSION` file; mismatch → warning, not fail |
| Sonnet attack executors miss subtleties Opus would catch | Mitigated downstream: Advocate (Opus) rejects weak claims; Triager (Opus) closes informational findings; Curator (Opus) reviews novelty proposals |
| Engagements stop producing proposed additions → KB stagnates | Operator-side responsibility; v4.2 could add a proactive research-refresh workflow (vuln_db has a model for this in workflows/cross-domain-research-refresh-cycle.md) |

## 14. Open implementation questions (for writing-plans)

- How does `lib/orchestrator.ts` interop with the existing `lib/*.sh` utilities?
  (Plan: TS shells out to bash; bash scripts continue to do their thing.)
- Concrete shape of `recon.capabilities` — full enum of capability flags R3 emits.
- Concrete `applies_when` expression grammar — JMESPath strict subset vs custom mini-DSL.
- `finding-schema.json` complete field list — coverage[] shape, findings[] shape,
  proposed_additions[] shape.
- Curator batching algorithm — by class, by submission order, or by some priority?
- v3 → v4 cutover plan: do engagements default to v4 once `validate-playbook.sh`
  passes, or stay on v3 until explicit operator switch?

## 15. v4.1 and beyond (out of scope for v1, captured for continuity)

- **v4.1**: credential vault, live dashboard, Burp MCP bridge, claude-mem
  integration for cross-engagement recall.
- **v4.2**: Mobile (Android + iOS) attack surface; Cloud (AWS / Azure / GCP);
  Network / Active Directory.
- **v4.3**: Proactive research-refresh workflow (Curator ingests new public
  research between engagements, not just engagement-produced proposals).
- **v5**: If the KB grows past ~500 playbook entries and exact-match search
  becomes a bottleneck, revisit vector/embedding KB augmentation. Not before.
