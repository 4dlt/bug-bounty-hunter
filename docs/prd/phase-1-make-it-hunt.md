# PRD — Phase 1: Make it hunt (walking skeleton)

> Status: PRD (not yet sliced into issues). Roadmap context: `docs/ROADMAP.md`.
> Full design rationale: `Plans/witty-twirling-valiant.md`.
>
> This PRD is the source document for Phase 1. Work issues (`ready-for-agent`)
> will be created **from** it; this document itself is not a work item.

## Problem Statement

The v2 orchestrator has a fully tested skeleton (state machine, scope check, ledger
dedupe, budget halts, resume, report, verify routing — 245 passing tests), but
**every agent in it is a stub**. Running `bbh pentest` today halts at Stage 0
(auth) and finds nothing. As a bug-bounty hunter, I have impressive scaffolding that
cannot find a single bug. Before investing in the full swarm, the knowledge base, or
the tool arsenal, I need proof that the core engine works: that a real hunter,
dropped into this skeleton, can find **and prove** a genuine vulnerability on a live
target.

## Solution

Replace the stubs on the critical path with the **smallest real hunting thread that
produces a proven finding**: one capable IDOR hunter, real two-identity login, a real
HTTP probe path, and a deterministic oracle that *proves* the finding. Point it at a
local OWASP Juice Shop and have it return, in `report.md`, at least one real,
oracle-reproduced cross-tenant IDOR.

Effort is deliberately concentrated where the risk is (the hunter + the oracle).
Everything that doesn't affect whether the hunter finds the bug — real recon, the
plan agent, the wider tool arsenal, the knowledge base, the learning loop, the LLM
reviewer — is intentionally trivial or deferred. From the hunter's perspective, the
target is handed to it (known id-bearing endpoints), it probes as two identities plus
unauthenticated, and any candidate it raises is confirmed only when a code oracle
mechanically reproduces the cross-tenant leak.

## User Stories

1. As a bug-bounty hunter, I want to run one command against an authorized target and
   get back any real, proven vulnerabilities, so that I can review and submit them
   without chasing false positives.
2. As a bug-bounty hunter, I want the tool to actually log in as a test user (not stub
   the login), so that it can probe authenticated surfaces the way a real attacker
   would.
3. As a bug-bounty hunter, I want to declare **two** test identities for an engagement,
   so that the hunter can test cross-tenant access (one user reaching another user's
   data).
4. As a bug-bounty hunter, I want the number of identities to be per-engagement
   (0 / 1 / 2+), so that engagements that don't need multiple accounts aren't forced
   to have them.
5. As a bug-bounty hunter, I want the hunter to be pointed at the target's id-bearing
   endpoints, so that it starts where IDOR bugs actually live.
6. As a bug-bounty hunter, I want the hunter to try incrementing, decrementing, and
   substituting object ids and to switch identities, so that it explores the IDOR
   space rather than firing one blind probe.
7. As a bug-bounty hunter, I want each reported finding to come with a runnable
   proof-of-concept, so that I can reproduce it myself before submitting.
8. As a bug-bounty hunter, I want a finding marked "confirmed" **only** when it has
   been mechanically proven by a code oracle, not merely asserted by an LLM, so that I
   trust the confirmed bucket.
9. As a bug-bounty hunter, I want the oracle to prove an IDOR is truly cross-tenant and
   not public-by-design (present when authenticated as A, absent/denied when
   unauthenticated), so that I don't waste a submission on a non-bug.
10. As a bug-bounty hunter, I want any candidate the oracle *cannot* confirm to still be
    surfaced (escalated), not silently dropped, so that no real signal is lost and I
    remain the final gate.
11. As a bug-bounty hunter, I want the engagement to stay strictly on the authorized
    target, so that I never accidentally probe out of scope.
12. As a bug-bounty hunter, I want probes to respect a rate limit, so that I don't
    hammer the target.
13. As a bug-bounty hunter, I want repeat probes deduplicated, so that iterations
    explore new ground instead of re-firing the same request.
14. As a bug-bounty hunter, I want the run to halt cleanly if it exceeds a budget
    (probes / LLM calls / minutes), so that it can't run away.
15. As a bug-bounty hunter, I want the engagement resumable after an interruption, so
    that I don't lose progress or double-fire probes.
16. As a bug-bounty hunter, I want a readable report of confirmed findings (with
    severity by impact and the PoC), so that I can act on it directly.
17. As a bug-bounty hunter, I want the target, identities, and budget declared in a
    scope file, so that an engagement is declarative and repeatable.
18. As the IDOR hunter, I want a scoped HTTP request tool that lets me choose which
    identity (or unauthenticated) each request fires as, so that I can compare
    responses across principals.
19. As the IDOR hunter, I want to see each probe's full response body, status, and
    timing, so that I can spot a cross-tenant leak.
20. As the IDOR hunter, I want to be given an IDOR playbook (methodology), so that I
    hunt with real technique rather than generic guessing.
21. As the IDOR hunter, I want to emit a **self-checking** PoC — a script that fails
    unless the bug reproduces — so that the oracle can confirm my finding
    deterministically.
22. As the IDOR hunter, I want to record interesting-but-unconfirmed signals as
    hypotheses, so that deeper hunting can pick them up in a later phase.
23. As the orchestrator, I want every probe fired through the existing
    dedupe + rate-limit-token + ledger path, so that scope, rate-limit, and
    no-repeat guarantees hold by construction rather than by the agent's goodwill.
24. As the verifier, I want to confirm an IDOR finding by running the differential
    oracle over the re-fired PoC, so that "confirmed" is a fact, not an opinion.
25. As the orchestrator, I want the agent's LLM calls counted against the budget, so
    that cost stays bounded.
26. As the orchestrator, I want each stage's real agent injected behind the existing
    seam, so that the orchestration logic stays testable without a live LLM or target.
27. As a developer, I want the new agents tested at existing seams (fake LLM client,
    injected fetch, pure oracle function), so that the suite runs offline and
    deterministically.
28. As a bug-bounty hunter, I want a live run against Juice Shop to yield at least one
    oracle-reproduced IDOR, so that Phase 1 proves the engine works before we scale.

## Implementation Decisions

All new agents are **real implementations dropped behind the orchestrator's existing
injectable seams** — the hunter runner, recon runner, plan runner, verifier runner,
the auth login function, and the probe transport. The orchestration spine (state
machine, ledger, scope check, token governor, budget, resume, report) is reused
unchanged. Only two genuinely new pieces are introduced: an agent tool-loop primitive
and a pure IDOR oracle.

- **Agent tool-loop primitive.** A new module providing a bounded multi-turn tool-use
  loop over the existing LLM client: given a system prompt, a set of tools (each a
  name + description + input schema + handler), a turn cap, and a callback to record
  LLM calls, it runs the model, dispatches each tool call to its handler, feeds the
  result back, and returns the payload of a designated terminal tool. It reuses the
  existing credential resolution and increments the engagement's `max_llm_calls`
  counter on each call. Every agent in this PRD (the hunter) is built on this loop.

- **Multi-identity auth.** The scope's auth block is extended from a single account to
  a **list of named identities** (supporting 0 / 1 / 2+). A real HTTP form-login
  replaces the browser-login stub: for each declared identity it registers
  (best-effort) then logs in against the target and captures the session token into
  the auth artifact, keyed by identity name. The stage advances only when every
  declared identity yields a usable session; MFA/captcha halts via the existing
  obstacle detection. An implicit unauthenticated "identity" is always available.

- **Real HTTP probe transport.** A real probe transport replaces the stub: it resolves
  a probe's endpoint against the target base URL, injects the chosen identity's
  credential (bearer token) — or none when the probe requests the unauthenticated
  path — routes the request through the **existing scoped fetch** (scope enforcement),
  and returns a ledger result carrying status, a response-body signature, and a
  truncated body as evidence. It also surfaces status, body, and timing back to the
  caller so the hunter can reason over the response.

- **Capable IDOR hunter.** A real hunter runner built on the tool-loop. Its system
  prompt is the injected IDOR playbook plus the cell context (endpoints, the available
  identities, the already-tried probe keys). It is given two tools: an
  `http_request` tool (backed by the orchestrator's existing fire path → transport;
  it accepts a target endpoint, method, body, and an **identity selector including an
  unauthenticated option**) and a `submit_findings` / `note_hypothesis` terminal tool.
  Method: establish a baseline as identity A, swap object ids and/or switch to
  identity B, watch for a response returning another principal's private data, and
  confirm the same request is denied unauthenticated. Each candidate finding carries a
  **self-checking PoC** — a script that exits non-zero unless the cross-tenant leak
  **and** the unauthenticated-denied condition both hold.

- **IDOR differential oracle (pure).** A pure function that is the sole authority for
  confirming an IDOR in Phase 1. Given the finding's re-fire evidence — the response
  seen by the attacking identity, the response seen unauthenticated, and the claimed
  private field — it returns **confirmed** only when the private field is present for
  the attacking identity **and** absent or access-denied unauthenticated (i.e.
  cross-tenant, not public-by-design). It emits a confidence label; it never deletes a
  finding.

- **Verifier wired to the oracle.** For Phase 1 the verifier runner emits `confirmed`
  iff the IDOR oracle passes over the re-fired PoC; any candidate the oracle cannot
  confirm receives a non-confirming verdict that **escalates (surfaces) rather than
  drops**. No LLM reviewer is used in Phase 1 — IDOR has a clean oracle, so the oracle
  is the confirmer.

- **Trivial recon and plan.** A fixed recon runner returns the target's known
  id-bearing endpoints and surfaces; a trivial plan runner emits IDOR cells for them.
  This keeps the existing recon → plan → sweep pipeline intact without building real
  recon or planning intelligence (deferred to Phase 2).

- **Report reused unchanged.** The existing report stage renders the confirmed
  finding(s). Phase 1 output is confirmed findings only; richer ranking is Phase 2.

- **Scope configuration.** A local scope file for the Juice Shop engagement declares
  the target, the two identities, and the budget. It is git-ignored (holds throwaway
  test credentials).

- **Self-checking-PoC convention (from prototype behaviour).** The decision that a
  finding's PoC doubles as the oracle input is encoded as: the hunter emits a
  `poc.sh` whose exit code is the shell-checkable verdict for classes that support it
  — `exit 0` only when the differential holds. The verify stage re-fires it (using the
  existing PoC re-fire path, which already captures the exit code) and hands the
  captured responses to the pure oracle. For IDOR this makes the PoC and the oracle
  two views of the same deterministic check.

## Testing Decisions

A good test here exercises **external behaviour at a seam**, not internal
implementation, and runs **offline and deterministically** (no live LLM, no live
target). The suite mirrors the existing v2 seam-test style, which already injects
fetch/executors and uses fixtures.

Modules to test, and how:

- **Agent tool-loop** — inject a fake LLM client; assert it dispatches tool calls to
  the right handlers, feeds results back, returns the terminal tool's payload, honours
  the turn cap, and records one LLM call per turn. *(Prior art: `tests/llm.test.ts`.)*
- **HTTP probe transport** — inject `fetch`; assert endpoint resolution against the
  base URL, identity/bearer injection, the unauthenticated path, an out-of-scope
  request being blocked by the scoped fetch, and deterministic response-signature
  computation. *(Prior art: `tests/scope.test.ts`, `tests/verify.test.ts`.)*
- **Multi-identity auth** — inject `fetch`; assert a login response is parsed into the
  auth artifact, that a session is captured per declared identity, and that a
  failed/obstacle login halts rather than advancing. *(Prior art: the existing auth
  stage tests.)*
- **IDOR differential oracle** — a pure function, table-tested directly: confirmed when
  cross-tenant + unauthenticated-denied; not-confirmed when the data is public-by-design
  or is the attacker's own data. *(Prior art: the pure `checkScope` / `isDuplicateProbe`
  table tests.)*
- **Verifier-wired-to-oracle** — assert it emits `confirmed` iff the oracle passes, and
  escalates (does not drop) otherwise.

Explicitly **not** unit-tested: whether the model actually finds the bug. That is the
**live acceptance test**, run manually:

- `bbh pentest http://localhost:3000` (with the local Juice Shop up and credentials
  loaded) produces a `report.md` containing ≥1 IDOR that the oracle reproduces;
  `ledger.jsonl` shows real probes; and a forced mid-run kill followed by resume
  completes without double-firing probes.

Definition of done: the offline seam suites above pass, and the live acceptance test
yields at least one oracle-reproduced IDOR on Juice Shop.

## Out of Scope

Deferred to later phases (see `docs/ROADMAP.md`):

- **Real recon and planning intelligence** (R1–R4, the LLM plan agent) — Phase 2.
- **The wider tool arsenal** (`nuclei`, `sqlmap`, `ffuf`, `dalfox`, `dev-browser`) and
  its tool-executor seam — Phase 2. Phase 1 tools are `http_request` + identities only.
- **The swarm** — other vuln classes, per-class specialists, and the Tier-2
  class-agnostic depth agent — Phase 2.
- **The LLM reviewer**, N-agent consensus, re-dispatch-for-evidence, and confidence
  ranking beyond "confirmed" — Phase 2.
- **The curated knowledge base as a system**, its seeding pipeline, the get-unstuck
  research loop, the Curator write-back, and the precedent/duplicate check — Phases
  3–4. (Phase 1 uses a single hand-written IDOR playbook as the hunter's context, not
  the KB system.)
- **Sandbox / network egress proxy** — explicitly not built; scope is the existing
  one-line check.

## Further Notes

- **Why Phase 1 is intentionally small.** The one unproven thing is whether a capable
  hunter can find and prove a real bug; every later phase scales that ability up.
  Phase 1 tests exactly that with the least new code, on top of a skeleton that already
  exists and is tested. Juice Shop is easy-mode, so a confirmed IDOR here proves the
  **pipeline** works end-to-end — it does not yet prove real-world recall (that comes
  with the knowledge layer on harder targets).
- **The hardened hunter + oracle are not throwaway** — they become the real modules the
  swarm and later phases grow around.
- **Risk — LLM cost/quota.** Bound the hunter's turns and use a probe-appropriate model
  tier; the subscription session limit has bitten us before.
- **Environment.** `claude` CLI, the Juice Shop docker target, and the credentials are
  already available locally; the security-tool arsenal is installed but not wired until
  Phase 2.
