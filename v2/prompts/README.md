# v2 agent prompts

Markdown prompts for the v2 agent roles live here, added slice by slice:

- Auth acquisition (Stage 0) — `auth-acquire.md` ✅ (Slice 1)
- Recon R1–R4 (Stage 1) — `recon-r1-assets.md`, `recon-r2-content.md`,
  `recon-r3-fingerprint.md`, `recon-r4-js-analysis.md` ✅ (Slice 2)
- Plan (Stage 2) — `plan.md` ✅ (Slice 3a)
- Tier 1 sweep hunters (Stage 3) — all 13 classes ✅ (Slice 3b: `hunters/idor.md`;
  Slice 3c: `hunters/{xss_reflected,xss_stored,sqli,ssrf,auth_bypass,
  business_logic,file_upload,api,websocket,ssti,lfi,race_condition}.md`)
- Checklist Author (Stage 3.5) — `checklist-author.md` ✅ (Slice 4) /
  Checklist Reviewer (Stage 3.6) — `checklist-reviewer.md` ✅ (Slice 4)
- Verifier (Stages 4–5) — `verifier.md` ✅ (Slice 5)
- Tier 2 deep hunters (Stage 6) — `deep-hunter.md` ✅ (Slice 6)
- Report + Resume + Budget halt (Stage 6 report, resume, runaway protection) —
  no agent prompt (deterministic) ✅ (Slice 7)
- IDOR hunting playbook (Phase 1 · Slice 2) — `idor-playbook.md` ✅ (the capable
  LLM IDOR hunter's methodology / system context)

Slice 0 shipped the scaffolding, LLM client, state machine, rate-limit
governor, and Juice Shop test target. Slice 1 adds Stage 0: the scope.yaml
schema + allowlist (`src/scope.ts`), the auth-acquire agent prompt and stage
(`src/auth.ts`), and the token-refresh monitor (`src/refresh.ts`). Slice 2 adds
Stage 1 recon: the parallel R1–R4 orchestration + merge (`src/recon.ts`), the
governor client (`acquireToken` in `src/ratelimit.ts`), and the four recon agent
prompts above. Slice 3a adds Stage 2 Plan: the hunt-plan / a-priori-hypothesis
schemas + surface-compatibility filter + seeding (`src/plan.ts`), the `bbh plan`
subcommand, and the `plan.md` prompt. Slice 3b adds Stage 3's Tier 1 hunter
framework: the append-only `ledger.jsonl` + the `(endpoint, payload_sig,
session)` dedupe primitive (`src/hunters/ledger.ts`), the hunter framework —
prompt rendering, the dedupe+token+ledger probe firer, and `findings/<id>/`
emission (`src/hunters/framework.ts`), the one concrete IDOR hunter
(`hunters/idor.md`), and the `bbh sweep --class idor` subcommand. Slice 3c
completes Stage 3: the remaining 12 Tier 1 hunter prompts, the parallel sweep
with a concurrency-capped worker pool (`src/hunters/sweep.ts`,
`scope.sweep_concurrency` default 5), the reactive hypothesis stream
(`source: "tier1_reactive"` → `hypotheses.jsonl`, capped at 15/engagement), the
ledger-derived coverage matrix (`src/hunters/coverage.ts` →
`coverage.json`, cells classified `swept` / `deep_dived` / `GAP`), and the
`bbh sweep` subcommand now sweeping every `(surface × class)` cell. Slice 4 adds
Stages 3.5 + 3.6 — the three-role structural guard: the Checklist Author
(`src/checklist/author.ts`, `checklist-author.md`) writes `checklists/<class>.md`
for each class with a Tier 1 candidate; the Checklist Reviewer
(`src/checklist/reviewer.ts`, `checklist-reviewer.md`) answers three yes/no
questions and writes `checklists/<class>.approval.json`; and the approve-or-halt
router (`src/checklist/stage.ts`) gives the Author exactly one rewrite on a
rejection before halting the engagement with an operator report at
`halted/checklist-rejection.md`. Author and Reviewer live in separate modules
and neither imports the other's writer, so no role can edit another's output.
The `bbh checklist` subcommand runs the stage over an existing engagement.

Slice 5 adds Stages 4 + 5 — the verify loop with surgical re-dispatch. The
stateless Verifier (`src/verify/verifier.ts`, `verifier.md`) applies the frozen
checklist to one finding and emits exactly one of eight verdicts (validated by
`VerdictSchema`); it reads the frozen `checklists/<class>.md` and edits nothing.
The re-fire path (`src/verify/refire.ts`) re-runs each finding's `poc.sh` against
the live target and diffs the fresh response against the captured one —
deliberately bypassing the hunter dedupe (re-firing a known PoC is the point).
The pure routing table (`src/verify/routing.ts`) maps each verdict to its action,
and the loop driver (`src/verify/stage.ts`) executes them: `confirmed` →
`verdicts/pass-N.json`; `repro_failed` / `weak_evidence` → surgical re-dispatch of
the originating Tier 1 hunter with the `reason` + `mutation_hint` prepended;
`out_of_scope` → drop; `duplicate` → merge; `severity_mismatch` → downgrade;
`non_deterministic` → escalate `ready-for-human`; `rate_limited` → backoff +
re-verify. A 10-iteration cap per finding escalates rather than drops, and the
loop exits cleanly when no re-queue verdicts remain (or the budget is exhausted).
The `bbh verify` subcommand runs the loop over an existing engagement; the
verify-loop seam tests (`tests/verify.test.ts`, fixtures under
`tests/fixtures/verify/`) cover all eight verdicts and both re-queue paths.

Slice 6 adds Stage 6 — Tier 2 deep hunters with mutation-driven iteration. The
hypothesis queue (`src/tier2/queue.ts`) reads `hypotheses.jsonl` and consumes it
in strict priority order — verifier escalations → plan a-priori → Tier 1 reactive
— capped at 15 per engagement, the overflow logged as `deferred` to
`tier2/deferred.jsonl`. Each surviving hypothesis is deep-hunted by a fresh agent
per iteration (`src/tier2/deep-hunter.ts`): iteration N+1 reads N's output from
`tier2/<hypothesis_id>/iter-N.json`, accumulates the prior `mutation_hint`s, and
re-spawns with a six-section structured recipe (`src/tier2/recipe.ts`:
HYPOTHESIS / CONTEXT / ALREADY_TRIED / MUTATION_HINTS / BUDGET / OUTPUT_SCHEMA).
Every probe fires through the same dedupe+token+ledger firer as Tier 1 — that IS
the Tier 2 hard-check: a probe whose `(endpoint, payload_sig, session)` 3-tuple is
already in `ledger.jsonl` is refused before it hits the network. A deep hunt ends
on `finding` (written to `findings/<id>/`, flowing back into the SAME verify loop),
`rejected`, or the 10-iteration cap — which escalates the hypothesis to
`ready-for-human` rather than dropping it. The verify loop's `promote_to_tier2`
verdict spawns a deep hunter inline via the injected `promoteToTier2` seam
(`src/tier2/stage.ts` + the seam in `src/verify/stage.ts`), so its findings
re-enter verify and can themselves be re-queued. The `bbh tier2` subcommand drains
the queue over an existing engagement; the seam tests (`tests/tier2.test.ts`)
cover priority ordering, the 15-cap deferral, the ledger hard-check, fresh-agent
iteration inheritance, the 10-iteration escalation, and the promote_to_tier2
routing back through verify.

Slice 7 closes the pipeline — Report (Stage 6), Resume, and Budget halt — and
adds the third and final testing seam (the stage gate). The Report generator
(`src/report/report.ts`) reads every `verdicts/pass-*.json` for `confirmed`
verdicts (deduped by finding-id, highest pass wins), pairs each with its
`findings/<id>/finding.json`, and renders `report.md`: title, P1–P4 impact
severity (NOT bounty), affected endpoint, `poc.sh`, evidence reference, and a
per-class suggested fix. Findings the verify loop escalated to `ready-for-human`
get their own section. There is NO bounty estimation anywhere — a source-grep
test proves the module never emits a `bounty_estimate` field. The three
runaway-protection budgets (`src/budget.ts`) — `max_probes` (ledger lines),
`max_llm_calls` (in-process counter), `max_minutes` (wall-clock) — halt the
engagement cleanly the moment any one is met: a partial `report.md` is written
from the findings confirmed to date and `state.json.status` flips to
`budget_exhausted`. Resume (`src/resume.ts`) reads `state.json`, snapshots the
on-disk artifacts, and validates that every stage strictly before the claimed
in-flight stage left its primary artifact — a missing one surfaces the
inconsistency rather than silently resuming from a corrupt point; re-running the
in-flight stage is safe because the ledger dedupe refuses repeat probes. The
`bbh report`, `bbh resume <dir>`, and `bbh status <dir>` subcommands surface all
three, and the full `pentest` pipeline now creates a `BudgetTracker`, feeds its
predicate into the verify loop, halts on exhaustion, and otherwise walks
`verify → report → done`. The stage-gate seam tests (`tests/state-gate.test.ts`,
fixtures under `tests/fixtures/state-gate/`) cover report contents (confirmed
only + a separate ready-for-human section, no bounty), resume from each of the 8
stages, the checklist-rejection operator artifact, a clean budget halt with a
partial report, and the in-flight-stage re-run NOT double-firing probes.

## Phase 1 · Slice 1 — End-to-end IDOR tracer + differential oracle (no LLM)

The first Phase-1 slice replaces the stubs on the critical path with the
smallest real hunting thread that produces a *proven* finding — a tracer bullet
that lights up auth, transport, hunter, oracle, verifier, and report at once,
with **zero LLM calls**. It activates whenever `scope.yaml` declares ≥2 named
identities.

- **Multi-identity auth + real HTTP transport** (`src/idor/transport.ts`).
  `captureSessions` performs a real form/JSON login for each declared identity
  (best-effort register, then login), keyed by name, plus the always-available
  implicit unauthenticated identity; every request routes through the scoped
  fetch. `createHttpTransport` is the `ProbeTransport` the hunter fires through:
  it resolves each probe against the target base, injects the chosen identity's
  credential (or none), routes through the SAME scoped fetch behind the existing
  dedupe + token + ledger firer, and returns status / body / timing. The network
  is injected as `fetch`, so both are unit-testable offline.
- **The pure IDOR differential oracle** (`src/idor/oracle.ts`). `runIdorOracle`
  is a pure function over a differential (the victim object read as the attacker
  vs unauthenticated): it CONFIRMS only when the victim's private marker leaked
  to the attacker AND was denied/absent unauthenticated — a true cross-tenant
  leak, not public-by-design and not the attacker's own data. It labels
  confidence (hard unauth deny = high, soft = medium) and NEVER drops a finding:
  a non-confirmation is a labelled verdict, not a discard.
- **The hardcoded IDOR probe** (`src/idor/probe.ts`, `src/idor/tracer.ts`).
  `createIdorHunterRunner` fires each victim object as the attacker and
  unauthenticated through `ctx.fire`, and on a successful cross-tenant read emits
  a candidate finding with a self-checking `poc.sh` (exits non-zero unless the
  cross-tenant read AND the unauth-deny both hold) and an `evidence/oracle.json`
  differential. `buildTracerSpecs` is the trivial hardcoded "recon + plan": one
  cross-tenant spec per (attacker, victim) × id-bearing endpoint.
- **The Verifier wired to the oracle** (`src/idor/oracle-verifier.ts`).
  `createOracleVerifierRunner` reads `evidence/oracle.json`, runs the oracle, and
  emits `confirmed` iff it passes — otherwise `weak_evidence`, which the verify
  loop surfaces (escalated ready-for-human at the cap), never drops. "Confirmed"
  is a mechanical fact, not an LLM opinion.

The offline seam tests (`tests/idor.test.ts`) cover the oracle decision table,
the transport (injected fetch + scope block), multi-identity auth, the hunter
writing a runnable PoC + oracle differential, the oracle-wired verifier, and the
full verify loop confirming a true IDOR while escalating an unconfirmable one.
The live `bbh pentest http://localhost:3000` run against Juice Shop still needs a
host with docker; the tracer wiring is intact behind the identities gate.

## Phase 1 · Slice 2 — Capable LLM IDOR hunter (http_request + bash)

Slice 2 replaces Slice 1's *hardcoded* probe with a real model that **discovers**
the bug itself, dropping into the same transport + oracle pipeline. Two new
pieces plus a hand-written playbook.

- **Agent tool-loop primitive** (`src/agent/tool-loop.ts`). `runToolLoop` is the
  one new orchestration primitive: a bounded multi-turn tool-use loop over the
  LLM client. Given a system prompt, tools (name + description + JSON-schema +
  handler), a turn cap, and a designated TERMINAL tool, it runs the model,
  dispatches each `tool_use` to its handler, feeds the result back as a
  `tool_result`, and returns the terminal tool's input the moment the model calls
  it. It honours the turn cap and counts every model invocation via `onLlmCall`
  (the `max_llm_calls` budget hook). The client is injected structurally, so the
  loop is unit-tested with a scripted fake (`tests/tool-loop.test.ts`).
- **The capable LLM IDOR hunter** (`src/idor/llm-hunter.ts`). A `HunterRunner`
  built on the loop, given a full toolset — deliberately NOT one tool:
  `http_request` (the identity/unauth-aware probe path, routed through `ctx.fire`
  so scope / rate-limit / dedupe / ledger hold by construction), `bash` (general
  shell for JWT-decode, `jq`, discovery tools, scratch scripts — injected as a
  `BashExecutor`), and the terminal `submit_findings`. Its system prompt is the
  injected IDOR playbook (`idor-playbook.md`) plus the cell context. The model
  reports each candidate's differential (endpoint, leaked `victim_marker`,
  attacking identity, and BOTH the attacker + unauth responses); the hunter builds
  the Slice-1 finding shape from it (`candidateToFinding` → `buildIdorFinding`), so
  the self-checking `poc.sh` + `evidence/oracle.json` are identical to Slice 1 and
  the **unchanged oracle** stays the sole confirmation gate. Unconfirmed leads
  ride along as `hypotheses`.

`src/main.ts` wires the LLM hunter into the sweep behind the same identities gate
(replacing `createIdorHunterRunner`); each hunter LLM call increments the
`BudgetTracker`. Offline seam tests (`tests/tool-loop.test.ts`,
`tests/idor-llm-hunter.test.ts`) drive the loop + hunter with a scripted fake
client through the real transport and assert an oracle-confirmable finding, the
turn cap, the LLM-call count, and the tool wiring. The live
`bbh pentest http://localhost:3000` acceptance (the model finding + proving an
IDOR unassisted) still needs a host with docker + credentials.

## Phase 1 · Slice 3 — Run agents on the subscription tier (first-party `claude` agent)

Slice 3 **supersedes Slice 2's direct-SDK tool-loop execution**. The workflow must
run on the Claude *subscription* (hard requirement — no pay-as-you-go key), but
Anthropic anti-abuse-gates Sonnet/Opus with a `429` when a subscription OAuth token
hits `/v1/messages` directly; the same token reaches premium models fine through the
first-party `claude` CLI. So the IDOR hunter is restructured as ONE `claude` agent
spawned per cell instead of an SDK tool-loop.

- **The `claude`-agent IDOR hunter** (`src/idor/claude-agent.ts`). A `HunterRunner`
  that spawns `claude --print --model <model> --output-format json
  --dangerously-skip-permissions -p -`, piping the whole brief over stdin. The
  brief = the injected IDOR playbook + engagement context: target base URL, the
  captured identity session tokens (so the agent can
  `curl -H "Authorization: Bearer …"`), the id-bearing endpoints, and the unauth
  option. The agent is the "capable agent" — it probes with its OWN `bash`/`curl`,
  not one wired tool. It ends by emitting the EXISTING candidate JSON contract
  (`SubmitFindingsSchema`), which the runner extracts (`extractSubmitJson`, robust
  to prose / fenced blocks / braces-in-strings) and feeds through the **unchanged**
  `candidateToFinding` → `buildIdorFinding` → oracle → verify → report path. The
  model discovers; the code proves. Malformed/empty agent output yields no findings
  (graceful, never a crash).
- **The injectable seam** — the `claude` invocation is a `ClaudeAgentRunner`
  (mirroring `BashExecutor` / `PocExecutor` / `MessagesClient`); the default
  `spawnClaudeAgent` shells out with the ambient `CLAUDE_CODE_OAUTH_TOKEN` (the CLI
  carries the first-party identity, so premium is served on the subscription).
  Offline tests (`tests/idor-claude-agent.test.ts`) drive it with a fake runner
  returning canned agent output and assert an oracle-confirmable finding, the
  premium model choice, the token-bearing brief, graceful handling of malformed /
  throwing / empty-findings output, and the JSON extraction edge cases — no live
  `claude`, no network.

`src/main.ts` wires the `claude` hunter into the sweep behind the same identities
gate (replacing `createLlmIdorHunterRunner`); each agent spawn increments the
`BudgetTracker`. The direct-SDK premium path is removed for the hunter; probes fired
by the agent's `bash` bypass the in-process ledger (accepted this phase). Slice 2's
`llm-hunter.ts` stays as a library — its `candidateToFinding` + `SubmitFindingsSchema`
are reused. The live subscription acceptance (`bbh pentest http://localhost:3000`
finding + oracle-proving an IDOR on Juice Shop via Sonnet/Opus) still needs a host
with docker + credentials.
