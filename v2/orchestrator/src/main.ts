#!/usr/bin/env bun
// BugBountyHunter v2 orchestrator CLI.
//
// Slice 0 ships one command: `hello` — an end-to-end smoke that proves the
// runtime, the LLM client, the state layer, the rate-limit governor, and the
// Juice Shop test target all work together before any pentest logic exists.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { complete, createClient } from "./llm.ts";
import {
  initialState,
  readState,
  transition,
  writeState,
  type State,
} from "./state.ts";
import { acquireToken, startTokenServer, TokenBucket } from "./ratelimit.ts";
import {
  loadScope,
  coverageGapLogger,
  ScopeSchema,
  type Scope,
  type CoverageGap,
} from "./scope.ts";
import { acquireAuth, type LoginOutcome } from "./auth.ts";
import {
  captureSessions,
  createHttpTransport,
  isAuthenticatedSession,
  type IdentitySession,
} from "./idor/transport.ts";
import {
  createLlmIdorHunterRunner,
  loadIdorPlaybook,
  spawnBashExecutor,
} from "./idor/llm-hunter.ts";
import { createOracleVerifierRunner } from "./idor/oracle-verifier.ts";
import { buildTracerSpecs, TRACER_SURFACE } from "./idor/tracer.ts";
import {
  runRecon,
  type ReconAgentContext,
  type ReconResult,
} from "./recon.ts";
import {
  runPlan,
  readHuntPlan,
  writeHuntPlan,
  appendHypotheses,
  HypothesisSchema,
  type PlanInput,
  type PlanProposal,
} from "./plan.ts";
import {
  type HunterContext,
  type HunterYield,
  type HunterRunner,
  type ProbeTransport,
  type Payload,
} from "./hunters/framework.ts";
import { runSweep } from "./hunters/sweep.ts";
import { runChecklistStage } from "./checklist/stage.ts";
import type { AuthorInput, AuthorRunner } from "./checklist/author.ts";
import type { ReviewerInput, ReviewAnswers, ReviewerRunner } from "./checklist/reviewer.ts";
import { runVerifyStage, type SurgicalReDispatch } from "./verify/stage.ts";
import { spawnPocExecutor, type PocExecutor } from "./verify/refire.ts";
import type { VerifierInput, VerifierRunner, Verdict } from "./verify/verifier.ts";
import { runTier2Stage } from "./tier2/stage.ts";
import {
  runDeepHunter,
  DeepHunterOutputSchema,
  type DeepHunterContext,
  type DeepHunterOutput,
  type DeepHunterRunner,
} from "./tier2/deep-hunter.ts";
import {
  JUICE_SHOP_URL,
  composeDown,
  composeUp,
  waitForJuiceShop,
} from "./test-target.ts";
import { writeReport, reportPath } from "./report/report.ts";
import { BudgetTracker, haltForBudget } from "./budget.ts";
import {
  planResume,
  collectStatus,
  formatStatus,
} from "./resume.ts";

async function hello(): Promise<void> {
  const workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-hello-"));
  console.log(`[hello] workdir: ${workdir}`);

  // 1. Rate-limit governor.
  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[hello] token endpoint: ${tokens.url}/token`);

  try {
    // 2. Test target up + reachable.
    console.log("[hello] bringing up Juice Shop via docker compose...");
    await composeUp();
    await waitForJuiceShop();
    console.log(`[hello] Juice Shop reachable at ${JUICE_SHOP_URL}`);

    // 3. One LLM call through the vendored client.
    const reply = await complete({
      level: "fast",
      prompt: 'Reply with exactly the word "pong" and nothing else.',
      maxTokens: 16,
    });
    console.log(`[hello] LLM replied: ${reply.trim()}`);

    // 4. Zod-validated state.json, written then re-read.
    const state = initialState("hello-smoke", JUICE_SHOP_URL);
    await writeState(workdir, state);
    const back = await readState(workdir);
    if (back.engagement_id !== state.engagement_id) {
      throw new Error("state.json round-trip mismatch");
    }
    console.log("[hello] state.json written and re-validated OK");

    console.log("[hello] SUCCESS");
  } finally {
    // 5. Teardown — always, even on failure.
    await tokens.close().catch(() => {});
    console.log("[hello] tearing down Juice Shop...");
    await composeDown().catch((err) =>
      console.error(`[hello] teardown warning: ${String(err)}`),
    );
  }
}

/** Load scope.yaml from cwd, or synthesize a minimal target-only scope. */
async function resolveScope(target: string): Promise<Scope> {
  const scopePath = path.resolve(process.cwd(), "scope.yaml");
  try {
    const text = await fs.readFile(scopePath, "utf8");
    console.log(`[pentest] loaded scope from ${scopePath}`);
    return loadScope(text);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    console.log(
      `[pentest] no scope.yaml found; synthesizing a target-only scope for ${target}`,
    );
    return ScopeSchema.parse({ target });
  }
}

/** Value of a `--flag value` pair in argv, or undefined if absent. */
function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

/** First non-flag positional argument (skips `--flag value` pairs). */
function positional(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i += 1) {
    if (args[i]!.startsWith("--")) {
      i += 1; // skip the flag's value
      continue;
    }
    return args[i];
  }
  return undefined;
}

/**
 * Drive the dev-browser login. Delegated to the auth-acquire agent
 * (v2/prompts/auth-acquire.md) which needs a headed dev-browser — not wired in
 * this slice. Fails gracefully at that boundary, exactly as `hello` does at the
 * docker boundary, so the pipeline wiring can still be exercised end-to-end.
 */
async function browserLogin(_scope: Scope): Promise<LoginOutcome> {
  return {
    status: "failed",
    reason:
      "dev-browser login not wired in Slice 1 — see v2/prompts/auth-acquire.md",
  };
}

/**
 * Convert the captured multi-identity sessions into an auth LoginOutcome so the
 * existing `auth` gate (which requires captured session material) works
 * unchanged: every bearer credential becomes a JWT in `auth/state.json`. A run
 * where no identity authenticated fails auth, exactly as a stubbed login does.
 */
function sessionsToLoginOutcome(
  sessions: Map<string, IdentitySession>,
  now: () => string,
): LoginOutcome {
  const authed = [...sessions.values()].filter(isAuthenticatedSession);
  if (authed.length === 0) {
    return { status: "failed", reason: "no declared identity authenticated" };
  }
  return {
    status: "success",
    artifact: {
      acquired_at: now(),
      cookies: [],
      jwts: authed
        .filter((s) => s.authorization)
        .map((s) => ({ name: s.name, token: s.authorization!.replace(/^Bearer /, "") })),
    },
  };
}

/**
 * Run one recon agent (R1-R4). Delegated to the spawned agent driven by
 * `v2/prompts/recon-r{1..4}-*.md`, which crawls / scans / analyses through the
 * scope-enforced fetch and the governor's token endpoint — not wired in this
 * slice. Returns an empty result (with a note) so the pipeline advances
 * `recon → plan` gracefully, exactly as `browserLogin` stubs Stage 0.
 */
async function reconAgentStub(ctx: ReconAgentContext): Promise<ReconResult> {
  return {
    agent: ctx.agent,
    endpoints: [],
    tech: {},
    notes: [
      `recon agent ${ctx.agent} not wired in Slice 2 — see v2/prompts/recon-*.md`,
    ],
  };
}

/**
 * Run the Plan agent (Stage 2). Delegated to the smart (Opus) agent driven by
 * `v2/prompts/plan.md`, which reads the recon map and emits the hunt plan +
 * a-priori hypotheses — not wired in this slice. Returns an empty proposal (the
 * orchestrator still guarantees per-surface coverage and advances `plan →
 * sweep`), exactly as `reconAgentStub` stubs Stage 1.
 */
async function planAgentStub(_input: PlanInput): Promise<PlanProposal> {
  return { cells: [], hypotheses: [] };
}

/**
 * The IDOR payload corpus this slice sweeps with. Values are id-mutation recipes
 * the hunter applies to the sequential/opaque object ids it finds; the
 * orchestrator derives each probe's `payload_sig` from the value it fires. A
 * later slice will draw from the v1 `Payloads/*.yaml` corpus.
 */
const IDOR_PAYLOADS: Payload[] = [
  { id: "idor-decrement", value: "{id}-1", notes: "decrement a sequential id to reach a lower object" },
  { id: "idor-increment", value: "{id}+1", notes: "increment a sequential id to reach a higher object" },
  { id: "idor-known-victim", value: "victim-object-id", notes: "substitute a known other-user/tenant object id" },
  { id: "idor-uuid-swap", value: "uuid-from-another-flow", notes: "swap in a UUID captured from a different account" },
];

/**
 * Run one Tier 1 hunter (Stage 3). Delegated to the spawned Sonnet agent driven
 * by `v2/prompts/hunters/<class>.md`, which fires probes through the scoped
 * fetch + the token governor and checks the ledger before each novel probe — not
 * wired in this slice. Returns an empty result so the sweep advances end-to-end,
 * exactly as `reconAgentStub`/`planAgentStub` stub the earlier stages.
 */
const hunterStub: HunterRunner = async (_ctx: HunterContext): Promise<HunterYield> => {
  return { findings: [] };
};

/** Payload corpus per class. Only IDOR has a corpus this slice; the real hunters
 *  draw from the v1 `Payloads/*.yaml` set. */
function payloadsForClass(vulnClass: string): Payload[] {
  return vulnClass === "idor" ? IDOR_PAYLOADS : [];
}

/**
 * Placeholder network transport for the un-wired hunter. The real transport
 * routes each probe through the scope-enforced fetch against the live target;
 * here it never runs (the stub runner fires nothing).
 */
const stubTransport: ProbeTransport = async () => ({
  status: "skipped",
  trigger_match: false,
});

/**
 * Stage 3 driver, reused by the standalone `sweep` command and the full
 * `pentest` pipeline: run the parallel Tier 1 sweep over EVERY `(surface × class)`
 * cell of the hunt plan (bounded by `scope.sweep_concurrency`), seeding the
 * reactive hypothesis stream and deriving `coverage.json`, then transition
 * `sweep → author`. A cell whose class has no hunter prompt logs a coverage_gap.
 */
async function runSweepStage(
  workdir: string,
  scope: Scope,
  state: State,
  takeToken: () => Promise<boolean>,
  reportGap: (gap: CoverageGap) => void,
  overrides: { runnerFor?: (cell: { vuln_class: string }) => HunterRunner; transport?: ProbeTransport } = {},
): Promise<State> {
  const cells = await readHuntPlan(workdir).catch(() => []);

  const outcome = await runSweep(workdir, {
    scope,
    cells,
    // Every cell gets the same stub agent this slice unless the caller injects a
    // real runner (the Phase-1 IDOR tracer does); runSweep gaps a cell whose
    // class has no prompt on disk. The real wiring resolves a Sonnet agent per
    // class from `hunters/<class>.md`.
    runnerFor: overrides.runnerFor ?? (() => hunterStub),
    payloadsFor: (cell) => payloadsForClass(cell.vuln_class),
    transport: overrides.transport ?? stubTransport,
    pass: state.current_pass,
    takeToken,
    onCoverageGap: reportGap,
  });

  const next = transition(state, outcome.event);
  await writeState(workdir, next);
  console.log(
    `[sweep] ${outcome.cellsRun} cell(s) run, ${outcome.cellsGapped} gapped, ` +
      `${outcome.probesFired} probe(s) logged, ${outcome.findings.length} finding(s), ` +
      `${outcome.reactiveHypotheses.length} reactive hypothesis(es), ` +
      `${outcome.gaps} coverage GAP(s) (peak concurrency ${outcome.maxConcurrency}) ` +
      `-> advanced to ${next.current_stage}`,
  );
  return next;
}

/**
 * Run the Checklist Author (Stage 3.5). Delegated to the smart (Opus) agent
 * driven by `v2/prompts/checklist-author.md`, which reads the recon map + a
 * sample of Tier 1 candidates + program rules and writes one checklist per
 * class — not wired in this slice. Returns a minimal-but-structurally-valid
 * checklist so the stage runs end-to-end (the Reviewer stub approves it).
 */
const authorStub: AuthorRunner = async (input: AuthorInput): Promise<string> => {
  const fb = input.feedback?.length ? `\n\nRewrite addressed: ${input.feedback.join("; ")}` : "";
  return (
    `# ${input.vuln_class} verification checklist (STUB — see checklist-author.md)\n\n` +
    `- Excludes program-documented exclusion classes.\n` +
    `- Distinguishes a real bug from public-by-design endpoints.\n` +
    `- Requires a non-trivial impact gate.\n` +
    `\n${input.findings.length} candidate(s) observed on this class.` +
    fb
  );
};

/**
 * Run the Checklist Reviewer (Stage 3.6). Delegated to the standard (Sonnet)
 * agent driven by `v2/prompts/checklist-reviewer.md`, which answers three yes/no
 * questions per checklist — not wired in this slice. The stub approves (all YES)
 * so the pipeline advances `author → review → verify` end-to-end; a real
 * Reviewer can reject and trigger the Author's one rewrite / the halt path.
 */
const reviewerStub: ReviewerRunner = async (_input: ReviewerInput): Promise<ReviewAnswers> => ({
  excludes_documented_exclusions: true,
  distinguishes_public_by_design: true,
  has_impact_gate: true,
  notes: "",
});

/**
 * Stages 3.5 + 3.6 driver, reused by the standalone `checklist` command and the
 * full `pentest` pipeline. The Author writes a checklist for every class with a
 * Tier 1 candidate; the Reviewer approves-or-halts each (one Author rewrite on a
 * first rejection). On full approval the state walks `author → review → verify`;
 * on a second-attempt rejection the engagement halts with an operator report at
 * `halted/checklist-rejection.md`.
 */
async function runChecklistStageDriver(
  workdir: string,
  scope: Scope,
  state: State,
): Promise<State> {
  const outcome = await runChecklistStage(workdir, {
    authorRunner: authorStub,
    reviewerRunner: reviewerStub,
    scope,
  });

  // The Author always finishes Stage 3.5: advance author → review first.
  let next = transition(state, { type: "advance" });
  await writeState(workdir, next);
  // Then apply the Reviewer's verdict: advance review → verify, or halt.
  next = transition(next, outcome.event);
  await writeState(workdir, next);

  const approved = outcome.reviews.filter((r) => r.approved).length;
  console.log(
    `[checklist] ${outcome.authored.length} checklist(s) authored, ` +
      `${approved} approved` +
      (outcome.halted ? `, HALTED (${outcome.haltReason})` : "") +
      ` -> ${next.current_stage}`,
  );
  if (outcome.halted && outcome.rejectionReport) {
    console.error(`[checklist] operator report: ${outcome.rejectionReport}`);
  }
  return next;
}

/**
 * Run the Verifier (Stage 4). Delegated to the standard (Sonnet) agent driven by
 * `v2/prompts/verifier.md`, which re-fires the PoC, applies the frozen checklist,
 * and emits one of eight verdicts — not wired in this slice. The stub confirms
 * every finding so the loop drains and advances `verify → report` end-to-end; a
 * real Verifier can re-queue, drop, downgrade, or escalate.
 */
const verifierStub: VerifierRunner = async (input: VerifierInput): Promise<Verdict> => ({
  finding_id: input.finding_id,
  verdict: "confirmed",
  reason: "stub-confirmed (see verifier.md)",
});

/**
 * Surgical re-dispatch (Stage 5). The real path re-renders the originating Tier 1
 * hunter's prompt with the Verifier's `reason` + `mutation_hint` prepended and
 * re-runs `runHunter`, returning any new finding ids. Not wired in this slice:
 * the stub logs the request and produces no new findings.
 */
const reDispatchStub: SurgicalReDispatch = async (ctx) => {
  console.log(
    `[verify] surgical re-dispatch for ${ctx.finding.id} (${ctx.finding.vuln_class}): ` +
      `${ctx.reason}${ctx.mutation_hint ? ` — hint: ${ctx.mutation_hint}` : ""}`,
  );
  return [];
};

/**
 * Run one Tier 2 deep-hunt iteration (Stage 6). Delegated to the spawned Sonnet
 * agent driven by `v2/prompts/deep-hunter.md`, which reads the recipe, fires
 * mutation-driven probes through the scoped fetch + the ledger hard-check, and
 * returns `finding | rejected | needs_more_budget` — not wired in this slice.
 * The stub rejects every hypothesis so the deep-hunt loop drains without firing,
 * exactly as `hunterStub`/`verifierStub` stub the earlier stages.
 */
const deepHunterStub: DeepHunterRunner = async (
  ctx: DeepHunterContext,
): Promise<DeepHunterOutput> =>
  DeepHunterOutputSchema.parse({
    outcome: "rejected",
    reason: `deep hunter not wired in Slice 6 — see deep-hunter.md (iter ${ctx.iteration})`,
  });

/**
 * Promote-to-Tier-2 seam (Stages 4↔6). When the Verifier returns a re-queue
 * verdict with `next_step: 'promote_to_tier2'`, spawn a focused deep hunter on
 * the finding's hypothesis: record a `verifier_escalation` hypothesis, run the
 * fresh-agent-per-iteration deep hunt, and return any new finding ids (which flow
 * back through the SAME verify loop). Not wired in this slice: `deepHunterStub`
 * finds nothing, so the promotion is recorded but produces no new candidate.
 */
function promoteToTier2Driver(workdir: string, scope: Scope): SurgicalReDispatch {
  return async (ctx) => {
    const hypothesis = HypothesisSchema.parse({
      id: `h-esc-${ctx.finding.id}`,
      source: "verifier_escalation",
      class: ctx.finding.vuln_class,
      target_endpoint: ctx.finding.endpoint,
      hypothesis: `Promoted from ${ctx.finding.id} (${ctx.finding.title}): ${ctx.reason}`,
      signal_evidence: ctx.mutation_hint ?? "",
      estimated_payout_band: null,
      status: "queued",
    });
    // Record the escalation in the append-only queue (highest priority source).
    await appendHypotheses(workdir, [hypothesis]);
    console.log(
      `[verify] promote_to_tier2 for ${ctx.finding.id} (${ctx.finding.vuln_class}): ` +
        `${ctx.reason}${ctx.mutation_hint ? ` — hint: ${ctx.mutation_hint}` : ""}`,
    );
    const deep = await runDeepHunter(workdir, {
      runner: deepHunterStub,
      scope,
      hypothesis,
      transport: stubTransport,
      pass: 0,
    });
    return deep.findingIds;
  };
}

/**
 * Stage 4 + 5 driver, reused by the standalone `verify` command and the full
 * `pentest` pipeline: run the verify loop over every candidate finding — re-fire
 * each PoC, apply the frozen checklist, route the verdict, surgically re-dispatch
 * re-queues (capped at 10 iterations, escalating rather than dropping), and
 * advance `verify → report`.
 */
async function runVerifyStageDriver(
  workdir: string,
  scope: Scope,
  state: State,
  execute: PocExecutor,
  budgetTracker?: BudgetTracker,
  verifierRunner: VerifierRunner = verifierStub,
): Promise<State> {
  const outcome = await runVerifyStage(workdir, {
    scope,
    verifierRunner,
    execute,
    reDispatch: reDispatchStub,
    promoteToTier2: promoteToTier2Driver(workdir, scope),
    pass: state.current_pass,
    budgetExhausted: budgetTracker?.predicate(),
  });

  console.log(
    `[verify] ${outcome.confirmed.length} confirmed, ${outcome.dropped.length} dropped, ` +
      `${outcome.merged.length} merged, ${outcome.downgraded.length} downgraded, ` +
      `${outcome.escalated.length} escalated (ready-for-human), ` +
      `${outcome.reDispatched} surgical re-dispatch(es), ` +
      `${outcome.tier2Spawned} Tier 2 deep-hunt(s) ` +
      `(${outcome.deferredTier2.length} promoted)` +
      (outcome.budgetExhausted ? ", BUDGET EXHAUSTED" : ""),
  );

  // Budget exhaustion is a runaway-protection halt, NOT a normal advance: write
  // a partial report from the findings confirmed to date, mark the engagement
  // `budget_exhausted`, and stop — do not walk verify → report.
  if (budgetTracker) {
    const exceeded = await budgetTracker.exhausted();
    if (exceeded.length > 0) {
      const halt = await haltForBudget(workdir, state, exceeded);
      console.error(
        `[verify] budget exhausted (${exceeded.join(", ")}); wrote partial report, ` +
          `status=${halt.state.status}`,
      );
      return halt.state;
    }
  }

  const next = transition(state, outcome.event);
  await writeState(workdir, next);
  console.log(`[verify] -> advanced to ${next.current_stage}`);
  return next;
}

/**
 * Stage 6 (Report) driver: render `report.md` from the confirmed verdicts +
 * ready-for-human escalations on disk and advance `report → done`. Idempotent —
 * re-running it just re-renders the same report.
 */
async function runReportStage(
  workdir: string,
  state: State,
): Promise<State> {
  const markdown = await writeReport(workdir, state);
  const confirmed = (markdown.match(/^### \d+\. /gm) ?? []).length;
  const next = transition(state, { type: "advance" });
  await writeState(workdir, next);
  console.log(
    `[report] wrote report.md (${confirmed} confirmed section(s)) -> ${next.current_stage}`,
  );
  return next;
}

/**
 * `bbh report [target]` — regenerate `report.md` for an existing engagement (set
 * `BBH_WORKDIR`), so the report format can be iterated on without re-running the
 * pipeline. Reports whatever is confirmed on disk; does not advance state.
 */
async function report(args: string[]): Promise<void> {
  const workdir = process.env.BBH_WORKDIR;
  if (!workdir) {
    console.error("Usage: BBH_WORKDIR=<engagement-dir> bbh report");
    throw new Error("missing BBH_WORKDIR");
  }
  const state = await readState(workdir);
  const markdown = await writeReport(workdir, state);
  console.log(`[report] wrote ${reportPath(workdir)}`);
  console.log(markdown);
}

/**
 * `bbh verify [target]` — run only Stages 4 + 5 over an existing engagement (set
 * `BBH_WORKDIR` to point at it), so the Verifier prompt + re-fire path can be
 * iterated on without re-running the earlier stages.
 */
async function verify(args: string[]): Promise<void> {
  const target = positional(args) ?? JUICE_SHOP_URL;
  const scope = await resolveScope(target);

  const workdir =
    process.env.BBH_WORKDIR ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "bbh-verify-")));
  console.log(`[verify] workdir: ${workdir}`);

  let state = await readState(workdir).catch(() =>
    initialState(`verify-${path.basename(workdir)}`, target),
  );
  // The standalone command enters at the verify stage regardless of prior state.
  state = { ...state, current_stage: "verify" };
  await writeState(workdir, state);
  await runVerifyStageDriver(workdir, scope, state, spawnPocExecutor);
}

/**
 * Stage 6 driver, reused by the standalone `tier2` command and the full `pentest`
 * pipeline: deep-hunt the hypothesis queue in priority order (verifier escalations
 * → plan a-priori → tier1 reactive), capped at 15 (overflow logged `deferred`),
 * with a fresh-agent-per-iteration deep hunter. Findings flow back into verify.
 */
async function runTier2StageDriver(
  workdir: string,
  scope: Scope,
  state: State,
  takeToken: () => Promise<boolean>,
): Promise<void> {
  const outcome = await runTier2Stage(workdir, {
    scope,
    runner: deepHunterStub,
    transport: stubTransport,
    takeToken,
    pass: state.current_pass,
  });
  const findings = outcome.results.filter((r) => r.result === "finding").length;
  const rejected = outcome.results.filter((r) => r.result === "rejected").length;
  const escalated = outcome.results.filter((r) => r.result === "escalated").length;
  console.log(
    `[tier2] ${outcome.processed} hypothesis(es) deep-hunted, ` +
      `${findings} finding(s), ${rejected} rejected, ${escalated} escalated, ` +
      `${outcome.deferred.length} deferred (cap)` +
      (outcome.budgetExhausted ? ", BUDGET EXHAUSTED" : ""),
  );
}

/**
 * `bbh tier2 [target]` — run only the Stage 6 deep-hunt pass over an existing
 * engagement's hypothesis queue (set `BBH_WORKDIR` to point at it), so the deep
 * hunter + prompt can be iterated on without re-running the earlier stages.
 */
async function tier2(args: string[]): Promise<void> {
  const target = positional(args) ?? JUICE_SHOP_URL;
  const scope = await resolveScope(target);

  const workdir =
    process.env.BBH_WORKDIR ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "bbh-tier2-")));
  console.log(`[tier2] workdir: ${workdir}`);

  const state = await readState(workdir).catch(() =>
    initialState(`tier2-${path.basename(workdir)}`, target),
  );

  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[tier2] token endpoint: ${tokens.url}/token`);
  try {
    await runTier2StageDriver(workdir, scope, state, () => acquireToken(tokens.url));
  } finally {
    await tokens.close().catch(() => {});
  }
}

/**
 * `bbh checklist [target]` — run only Stages 3.5 + 3.6 over an existing
 * engagement (set `BBH_WORKDIR` to point at it), so the Author + Reviewer
 * prompts can be iterated on without re-running the earlier stages.
 */
async function checklist(args: string[]): Promise<void> {
  const target = positional(args) ?? JUICE_SHOP_URL;
  const scope = await resolveScope(target);

  const workdir =
    process.env.BBH_WORKDIR ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "bbh-checklist-")));
  console.log(`[checklist] workdir: ${workdir}`);

  let state = await readState(workdir).catch(() =>
    initialState(`checklist-${path.basename(workdir)}`, target),
  );
  // The standalone command enters at the author stage regardless of prior state.
  state = { ...state, current_stage: "author" };
  await writeState(workdir, state);
  await runChecklistStageDriver(workdir, scope, state);
}

/**
 * `bbh sweep [target]` — run only the Tier 1 sweep over an existing engagement's
 * hunt plan (set `BBH_WORKDIR` to point at it), so the hunters + prompts can be
 * iterated on without re-running auth/recon/plan.
 */
async function sweep(args: string[]): Promise<void> {
  const target = positional(args) ?? JUICE_SHOP_URL;
  const scope = await resolveScope(target);

  const workdir =
    process.env.BBH_WORKDIR ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "bbh-sweep-")));
  console.log(`[sweep] workdir: ${workdir}`);

  let state = await readState(workdir).catch(() =>
    initialState(`sweep-${path.basename(workdir)}`, target),
  );
  // The standalone command enters at the sweep stage regardless of prior state.
  state = { ...state, current_stage: "sweep" };
  await writeState(workdir, state);

  const logGap = coverageGapLogger(workdir);
  const reportGap = (gap: CoverageGap): void => {
    void logGap(gap);
    console.error(`[sweep] coverage_gap: ${gap.reason}`);
  };

  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[sweep] token endpoint: ${tokens.url}/token`);
  try {
    await runSweepStage(workdir, scope, state, () => acquireToken(tokens.url), reportGap);
  } finally {
    await tokens.close().catch(() => {});
  }
}

/**
 * Stage 2 driver, reused by the standalone `plan` command and the full
 * `pentest` pipeline: run the Plan agent over the recon map and transition
 * `plan → sweep`.
 */
async function runPlanStage(
  workdir: string,
  scope: Scope,
  state: State,
): Promise<State> {
  const plan = await runPlan(workdir, { scope, runner: planAgentStub });
  const next = transition(state, plan.event);
  await writeState(workdir, next);
  console.log(
    `[plan] hunt plan: ${plan.cells.length} cell(s), ` +
      `${plan.hypotheses.length} a-priori hypothesis(es) seeded ` +
      `(${plan.droppedCells} incompatible cell(s), ${plan.droppedHypotheses} below-band hypothesis(es) dropped)` +
      ` -> advanced to ${next.current_stage}`,
  );
  return next;
}

/**
 * `bbh plan <target>` — run only Stage 2, so the plan prompt can be iterated on
 * without re-running auth + recon. Reads the recon artifacts from the workdir
 * (set `BBH_WORKDIR` to point at an existing engagement; otherwise a fresh temp
 * dir is used and the plan comes out empty but valid).
 */
async function plan(args: string[]): Promise<void> {
  const target = positional(args);
  if (!target) {
    console.error("Usage: bbh plan <target-url>");
    throw new Error("missing target");
  }
  const scope = await resolveScope(target);
  const workdir =
    process.env.BBH_WORKDIR ??
    (await fs.mkdtemp(path.join(os.tmpdir(), "bbh-plan-")));
  console.log(`[plan] workdir: ${workdir}`);

  let state = await readState(workdir).catch(() =>
    initialState(`plan-${path.basename(workdir)}`, target),
  );
  // The standalone command enters at the plan stage regardless of prior state.
  state = { ...state, current_stage: "plan" };
  await writeState(workdir, state);
  await runPlanStage(workdir, scope, state);
}

/**
 * Stage 0 + Stage 1 + Stage 2 driver. Reads scope, initializes state, runs the
 * auth stage through the scope-enforced login, and — on a successful session —
 * runs Stage 1 recon (R1-R4 in parallel) then Stage 2 Plan (hunt plan +
 * a-priori hypotheses), advancing `auth → recon → plan → sweep`.
 */
async function pentest(args: string[]): Promise<void> {
  const target = positional(args);
  if (!target) {
    console.error("Usage: bbh pentest <target-url>");
    throw new Error("missing target");
  }
  const scope = await resolveScope(target);

  const workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-pentest-"));
  console.log(`[pentest] workdir: ${workdir}`);

  let state = initialState(`pentest-${path.basename(workdir)}`, target);
  await writeState(workdir, state);
  console.log(`[pentest] stage: ${state.current_stage}`);

  const logGap = coverageGapLogger(workdir);
  const reportGap = (gap: CoverageGap): void => {
    void logGap(gap);
    console.error(`[pentest] coverage_gap: ${gap.reason}`);
  };

  // Phase-1 IDOR tracer: a multi-identity engagement (≥2 named identities) drives
  // the hardcoded cross-tenant IDOR thread — real login, real HTTP probes, and
  // the deterministic oracle — with ZERO LLM calls. A single-/no-identity
  // engagement keeps the stubbed critical path (auth halts as before).
  const tracerSpecs = buildTracerSpecs(scope);
  const tracerMode = tracerSpecs.length > 0;
  const sessions = tracerMode ? await captureSessions(scope, { onCoverageGap: reportGap }) : null;
  if (tracerMode) {
    const authed = [...sessions!.values()].filter(isAuthenticatedSession).length;
    console.log(`[pentest] IDOR tracer: ${authed}/${scope.identities.length} identities authenticated`);
  }

  const login: () => Promise<LoginOutcome> = tracerMode
    ? async () => sessionsToLoginOutcome(sessions!, () => new Date().toISOString())
    : () => browserLogin(scope);
  const plan = await acquireAuth(workdir, login, {
    onCoverageGap: reportGap,
  });

  state = transition(state, plan.event);
  await writeState(workdir, state);

  if (plan.event.type !== "advance") {
    console.error(
      `[pentest] auth halted: ${plan.event.type === "halt" ? plan.event.reason : ""}`,
    );
    console.error(`[pentest] state: ${state.status}`);
    return;
  }
  console.log(`[pentest] auth OK -> advanced to ${state.current_stage}`);

  // Stage 1 — parallel recon. Consumes rate-limit tokens from the governor and
  // is scope-enforced per agent. Best-effort: a failed agent logs a
  // coverage_gap and the survivors still merge before advancing recon -> plan.
  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[pentest] token endpoint: ${tokens.url}/token`);
  // Engagement budget — the three runaway-protection thresholds. Probes are read
  // from the ledger, LLM calls counted in-process, wall-clock from construction.
  const budgetTracker = new BudgetTracker({ workdir, budget: scope.budget });
  try {
    const recon = await runRecon(workdir, {
      scope,
      runner: reconAgentStub,
      takeToken: () => acquireToken(tokens.url),
      onCoverageGap: reportGap,
    });
    state = transition(state, recon.event);
    await writeState(workdir, state);
    console.log(
      `[pentest] recon done: ${recon.endpoints.length} endpoints, ` +
        `${recon.surfaces.length} surfaces, ${recon.failed.length} agent failure(s)` +
        ` -> advanced to ${state.current_stage}`,
    );

    // Stage 2 — Plan. Reads the recon map and emits hunt-plan.json +
    // a-priori hypotheses, advancing plan -> sweep. In tracer mode the plan is
    // hardcoded: one (api × idor) cell over the handed id-bearing endpoints.
    if (tracerMode) {
      await writeHuntPlan(workdir, [
        {
          surface: TRACER_SURFACE,
          vuln_class: "idor",
          relevant_endpoints: tracerSpecs.map((s) => s.endpoint),
          priority: "high",
          expected_payout_band: null,
        },
      ]);
      state = transition(state, { type: "advance" });
      await writeState(workdir, state);
      console.log(`[pentest] tracer plan: 1 (api × idor) cell, ${tracerSpecs.length} endpoint(s) -> ${state.current_stage}`);
    } else {
      state = await runPlanStage(workdir, scope, state);
    }

    // Stage 3 — Tier 1 parallel sweep. Runs a hunter per (surface × class) cell
    // (bounded by scope.sweep_concurrency), appending probes to ledger.jsonl +
    // writing findings/<id>/, seeding reactive hypotheses, deriving coverage.json,
    // advancing sweep -> author. In tracer mode the IDOR cell gets the CAPABLE LLM
    // hunter (Slice 2): a real model on the agent tool-loop with http_request +
    // bash + the injected playbook, discovering the bug through the real HTTP
    // transport. Each LLM call counts against the engagement's max_llm_calls.
    const tracerTransport = tracerMode
      ? createHttpTransport({ scope, sessions: sessions!, onCoverageGap: reportGap })
      : undefined;
    const idorPlaybook = tracerMode ? await loadIdorPlaybook() : "";
    const hunterClient = tracerMode ? createClient() : null;
    state = await runSweepStage(
      workdir,
      scope,
      state,
      () => acquireToken(tokens.url),
      reportGap,
      tracerMode
        ? {
            runnerFor: (cell) =>
              cell.vuln_class === "idor"
                ? createLlmIdorHunterRunner({
                    client: hunterClient!,
                    sessions: sessions!,
                    base: scope.target,
                    playbook: idorPlaybook,
                    bash: spawnBashExecutor(workdir),
                    onLlmCall: () => budgetTracker.recordLlmCall(),
                  })
                : hunterStub,
            transport: tracerTransport,
          }
        : {},
    );

    // Stages 3.5 + 3.6 — Checklist Author + Reviewer. The Author writes a
    // checklist per class with a Tier 1 candidate; the Reviewer approves-or-halts
    // each (one Author rewrite on rejection). Walks author → review → verify on
    // full approval, or halts the engagement with an operator report.
    if (state.current_stage === "author") {
      state = await runChecklistStageDriver(workdir, scope, state);
    }

    // Stage 6 — Tier 2 deep-hunt pass. Drains the hypothesis queue (a-priori +
    // Tier 1 reactive) in priority order, capped at 15, deep-hunting each with a
    // fresh-agent-per-iteration hunter; new findings land in findings/<id>/ and
    // are picked up by the verify loop below. Verifier escalations are added
    // inline during verify via the promote_to_tier2 seam.
    if (state.current_stage === "verify") {
      await runTier2StageDriver(workdir, scope, state, () => acquireToken(tokens.url));
    }

    // Stages 4 + 5 — the verify loop with surgical re-dispatch + Tier 2 promotion.
    // Re-fires each candidate's PoC against the live target, applies the frozen
    // checklist, and routes each verdict; surgical re-queues re-dispatch the
    // originating hunter, promote_to_tier2 spawns a deep hunter whose findings
    // flow back through this loop. Walks verify → report on a clean drain.
    // Skipped when the checklist stage halted (state left at `halted`).
    if (state.current_stage === "verify") {
      await budgetTracker.refresh();
      // Tracer mode verifies with the deterministic IDOR oracle (no LLM): the
      // candidate is `confirmed` iff the oracle mechanically reproduces the
      // cross-tenant leak, else escalated/surfaced — never dropped.
      state = await runVerifyStageDriver(
        workdir,
        scope,
        state,
        spawnPocExecutor,
        budgetTracker,
        tracerMode ? createOracleVerifierRunner() : verifierStub,
      );
    }

    // Stage 6 — Report. Renders report.md from the confirmed verdicts (+ any
    // ready-for-human escalations) and advances report → done. Skipped when a
    // budget halt or checklist rejection already left the engagement terminal.
    if (state.current_stage === "report") {
      state = await runReportStage(workdir, state);
    }
    console.log(`[pentest] finished: stage=${state.current_stage}, status=${state.status}`);
  } finally {
    await tokens.close().catch(() => {});
  }
}

/**
 * `bbh resume <engagement-dir>` — read `state.json`, validate that the artifacts
 * on disk match the claimed stage, and report the resume plan. Re-running the
 * in-flight stage is safe (the ledger dedupe refuses repeat probes); an operator
 * can then re-invoke the relevant stage command. A missing prior-stage artifact
 * is surfaced as an inconsistency rather than silently resumed from.
 */
async function resume(args: string[]): Promise<void> {
  const workdir = positional(args) ?? process.env.BBH_WORKDIR;
  if (!workdir) {
    console.error("Usage: bbh resume <engagement-dir>");
    throw new Error("missing engagement dir");
  }
  const state = await readState(workdir);
  const plan = await planResume(workdir, state);
  console.log(`[resume] engagement ${state.engagement_id} (${state.target})`);
  console.log(`[resume] status: ${state.status}`);

  if (plan.terminal) {
    console.log(`[resume] engagement is terminal (${plan.resumeStage}); nothing to resume.`);
    return;
  }
  if (!plan.ok) {
    console.error(
      `[resume] INCONSISTENT STATE — prior-stage artifacts missing before "${plan.resumeStage}":`,
    );
    for (const m of plan.missing) {
      console.error(`  - ${m.stage}: expected ${m.artifact}`);
    }
    console.error(
      "[resume] refusing to auto-resume; inspect the engagement or force the stage manually.",
    );
    return;
  }
  console.log(
    `[resume] artifacts consistent; resume from "${plan.resumeStage}" ` +
      `(re-running it is safe — the ledger dedupe refuses repeat probes).`,
  );
}

/**
 * `bbh status <engagement-dir>` — show the current stage, pass, findings count,
 * hypothesis queue depth, and probe budget usage for an engagement.
 */
async function status(args: string[]): Promise<void> {
  const workdir = positional(args) ?? process.env.BBH_WORKDIR;
  if (!workdir) {
    console.error("Usage: bbh status <engagement-dir>");
    throw new Error("missing engagement dir");
  }
  const state = await readState(workdir);
  const scope = await resolveScope(state.target);
  const s = await collectStatus(workdir, state, scope.budget);
  console.log(formatStatus(s));
}

const COMMANDS: Record<string, (args: string[]) => Promise<void>> = {
  hello,
  pentest,
  plan,
  sweep,
  checklist,
  verify,
  tier2,
  report,
  resume,
  status,
};

async function main(argv: string[]): Promise<number> {
  const command = argv[0];
  if (!command || !(command in COMMANDS)) {
    const known = Object.keys(COMMANDS).join(", ");
    console.error(`Usage: bbh <command> [args]\nCommands: ${known}`);
    return command ? 1 : 0;
  }
  await COMMANDS[command]!(argv.slice(1));
  return 0;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`[bbh] error: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  });
