#!/usr/bin/env bun
// BugBountyHunter v2 orchestrator CLI.
//
// Slice 0 ships one command: `hello` — an end-to-end smoke that proves the
// runtime, the LLM client, the state layer, the rate-limit governor, and the
// Juice Shop test target all work together before any pentest logic exists.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { complete } from "./llm.ts";
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
  runRecon,
  type ReconAgentContext,
  type ReconResult,
} from "./recon.ts";
import { runPlan, readHuntPlan, type PlanInput, type PlanProposal } from "./plan.ts";
import {
  runHunter,
  type HunterContext,
  type HunterFinding,
  type ProbeTransport,
  type Payload,
} from "./hunters/framework.ts";
import {
  JUICE_SHOP_URL,
  composeDown,
  composeUp,
  waitForJuiceShop,
} from "./test-target.ts";

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
async function hunterStub(_ctx: HunterContext): Promise<{ findings: HunterFinding[] }> {
  return { findings: [] };
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
 * Stage 3 (IDOR only, this slice) driver, reused by the standalone `sweep`
 * command and the full `pentest` pipeline: run the IDOR hunter over every `idor`
 * cell of the hunt plan (firing probes through the dedupe+token+ledger path,
 * writing `findings/<id>/`), then transition `sweep → author`.
 */
async function runSweepStage(
  workdir: string,
  scope: Scope,
  state: State,
  takeToken: () => Promise<boolean>,
): Promise<State> {
  const cells = await readHuntPlan(workdir).catch(() => []);
  const idorCells = cells.filter((c) => c.vuln_class === "idor");

  let probes = 0;
  let findings = 0;
  for (const cell of idorCells) {
    const outcome = await runHunter(workdir, {
      runner: hunterStub,
      scope,
      surface: cell.surface,
      vuln_class: "idor",
      endpoints: cell.relevant_endpoints,
      payloads: IDOR_PAYLOADS,
      transport: stubTransport,
      pass: state.current_pass,
      takeToken,
    });
    probes += outcome.probesFired;
    findings += outcome.findings.length;
  }

  const next = transition(state, { type: "advance" });
  await writeState(workdir, next);
  console.log(
    `[sweep] idor: ${idorCells.length} cell(s), ${probes} probe(s) logged, ` +
      `${findings} finding(s) -> advanced to ${next.current_stage}`,
  );
  return next;
}

/**
 * `bbh sweep --class idor [target]` — run only the Tier 1 IDOR hunter over an
 * existing engagement's hunt plan (set `BBH_WORKDIR` to point at it), so the
 * hunter + prompt can be iterated on without re-running auth/recon/plan.
 */
async function sweep(args: string[]): Promise<void> {
  const cls = flagValue(args, "--class") ?? "idor";
  if (cls !== "idor") {
    console.error(`Only --class idor is implemented in this slice (got "${cls}")`);
    throw new Error("unsupported hunter class");
  }
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

  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[sweep] token endpoint: ${tokens.url}/token`);
  try {
    await runSweepStage(workdir, scope, state, () => acquireToken(tokens.url));
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
  const plan = await acquireAuth(workdir, () => browserLogin(scope), {
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
    // a-priori hypotheses, advancing plan -> sweep.
    state = await runPlanStage(workdir, scope, state);

    // Stage 3 — Tier 1 sweep (IDOR only, this slice). Runs the IDOR hunter over
    // each idor cell, appending probes to ledger.jsonl + writing findings/<id>/,
    // advancing sweep -> author.
    state = await runSweepStage(workdir, scope, state, () => acquireToken(tokens.url));
  } finally {
    await tokens.close().catch(() => {});
  }
}

const COMMANDS: Record<string, (args: string[]) => Promise<void>> = {
  hello,
  pentest,
  plan,
  sweep,
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
