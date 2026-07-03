// Stage 6 — the Tier 2 deep hunter framework.
//
// A deep hunter is a focused agent spawned for ONE hypothesis with a high probe
// budget (PRD user story 7). Unlike a Tier 1 sweep hunter (one bounded pass over
// a payload set), a deep hunter iterates: each iteration is a FRESH agent that
// reads the prior iterations' output from disk and re-spawns with the accumulated
// mutation hints (user story 20 — no long-lived agent state). It runs until the
// hypothesis is confirmed (`finding`), rejected (`rejected`), or the 10-iteration
// cap is hit (user story 18), which ESCALATES to ready-for-human rather than
// dropping — a stubborn hypothesis is a lead the operator should see, not lose.
//
// Every probe fires through the same dedupe+token+ledger firer the Tier 1
// framework uses (`createProbeFirer`): that IS the Tier 2 hard-check — a probe
// whose `(endpoint, payload_sig, session)` 3-tuple is already in `ledger.jsonl`
// is refused before it touches the network, so 10 iterations explore 10 variants
// rather than re-firing the same probe. The `alreadyTried` slice is pre-injected
// so the agent can steer clear before it even proposes a probe.
//
// Findings the deep hunter emits are written to `findings/<id>/` exactly like
// Tier 1's — so they flow back through the SAME verify loop (Slice 5): same
// Verifier, same frozen checklist, same routing rules.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { Scope } from "../scope.ts";
import type { Hypothesis } from "../plan.ts";
import {
  createProbeFirer,
  writeFinding,
  nextFindingSeq,
  HunterFindingSchema,
  type HunterFinding,
  type ProbeFirer,
  type ProbeTransport,
} from "../hunters/framework.ts";
import { readLedger, ledgerEntryKey, type ProbeKey } from "../hunters/ledger.ts";
import { buildRecipe, type RecipeBudget } from "./recipe.ts";
import { readyForHumanPath } from "../verify/stage.ts";

// ---------------------------------------------------------------------------
// The three deep-hunt outcomes
// ---------------------------------------------------------------------------

/** A single iteration ends in exactly one of these (PRD OUTPUT_SCHEMA). */
export const DEEP_OUTCOMES = ["finding", "rejected", "needs_more_budget"] as const;
export type DeepOutcomeKind = (typeof DEEP_OUTCOMES)[number];

/**
 * The deep hunter's structured output for one iteration. A `finding` outcome
 * MUST carry a `finding` (the poc-bearing candidate); the other two carry a
 * `reason`. `needs_more_budget` carries an optional `mutation_hint` that seeds
 * the next iteration's recipe.
 */
export const DeepHunterOutputSchema = z
  .object({
    outcome: z.enum(DEEP_OUTCOMES),
    finding: HunterFindingSchema.optional(),
    reason: z.string().default(""),
    mutation_hint: z.string().optional(),
  })
  .refine((o) => o.outcome !== "finding" || o.finding !== undefined, {
    message: "a `finding` outcome must include a `finding`",
    path: ["finding"],
  });
export type DeepHunterOutput = z.infer<typeof DeepHunterOutputSchema>;

// ---------------------------------------------------------------------------
// Iteration persistence (fresh agent reads prior output from disk)
// ---------------------------------------------------------------------------

export function tier2Dir(workdir: string): string {
  return path.join(workdir, "tier2");
}

export function hypothesisDir(workdir: string, hypothesisId: string): string {
  return path.join(tier2Dir(workdir), hypothesisId);
}

export function iterationPath(
  workdir: string,
  hypothesisId: string,
  iteration: number,
): string {
  return path.join(hypothesisDir(workdir, hypothesisId), `iter-${iteration}.json`);
}

/** Persist one iteration's output so the next (fresh) agent can read it back. */
export async function writeIteration(
  workdir: string,
  hypothesisId: string,
  iteration: number,
  output: DeepHunterOutput,
): Promise<void> {
  const validated = DeepHunterOutputSchema.parse(output);
  await fs.mkdir(hypothesisDir(workdir, hypothesisId), { recursive: true });
  await fs.writeFile(
    iterationPath(workdir, hypothesisId, iteration),
    JSON.stringify({ iteration, ...validated }, null, 2) + "\n",
    "utf8",
  );
}

/**
 * Read every prior iteration's output for a hypothesis, in order. Iteration N+1
 * calls this to inherit N's state from disk (no persistent agent memory). A
 * missing / unparseable iter file is skipped so a half-written one can't crash
 * the next spawn.
 */
export async function readPriorIterations(
  workdir: string,
  hypothesisId: string,
): Promise<DeepHunterOutput[]> {
  let entries: string[] = [];
  try {
    entries = await fs.readdir(hypothesisDir(workdir, hypothesisId));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const iters = entries
    .map((e) => /^iter-(\d+)\.json$/.exec(e))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => parseInt(m[1]!, 10))
    .sort((a, b) => a - b);
  const out: DeepHunterOutput[] = [];
  for (const n of iters) {
    try {
      const raw = await fs.readFile(
        iterationPath(workdir, hypothesisId, n),
        "utf8",
      );
      const parsed = DeepHunterOutputSchema.safeParse(JSON.parse(raw));
      if (parsed.success) out.push(parsed.data);
    } catch {
      // skip a truncated / malformed iteration file
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// ready-for-human escalation (10-iteration cap)
// ---------------------------------------------------------------------------

/** Flag a stubborn hypothesis ready-for-human, preserving its iteration trail. */
export async function escalateHypothesis(
  workdir: string,
  hypothesis: Hypothesis,
  reason: string,
): Promise<void> {
  await fs.mkdir(workdir, { recursive: true });
  const record = {
    hypothesis_id: hypothesis.id,
    label: "ready-for-human",
    reason,
    class: hypothesis.class,
    target_endpoint: hypothesis.target_endpoint,
    iterations_dir: hypothesisDir(workdir, hypothesis.id),
  };
  await fs.appendFile(
    readyForHumanPath(workdir),
    JSON.stringify(record) + "\n",
    "utf8",
  );
}

// ---------------------------------------------------------------------------
// The deep hunter agent seam
// ---------------------------------------------------------------------------

/** Everything one deep-hunt iteration is handed. Mirrors the Tier 1 HunterContext
 *  but scoped to a single hypothesis + the accumulated mutation trail. */
export interface DeepHunterContext {
  hypothesis: Hypothesis;
  /** 1-based iteration number (fresh agent each time). */
  iteration: number;
  /** The rendered six-section recipe (recipe.ts) — the agent's whole brief. */
  recipe: string;
  /** Ledger slice for this hypothesis's endpoint+class, as dedupe keys. */
  alreadyTried: ProbeKey[];
  /** The verifier's / prior iterations' rejection reasons, newest last. */
  mutationHints: string[];
  /** The dedupe+token+ledger firer — the Tier 2 hard-check path. */
  fire: ProbeFirer;
  /** The account/identity this hypothesis probes under. */
  session: string;
  /** Consume one rate-limit token (for non-probe requests). */
  takeToken: () => Promise<boolean>;
  budget: RecipeBudget;
}

/** Injected agent (Sonnet, `level: 'standard'`): probe the hypothesis via
 *  `ctx.fire`, return one of the three outcomes. */
export type DeepHunterRunner = (
  ctx: DeepHunterContext,
) => Promise<DeepHunterOutput>;

/** Default per-hypothesis iteration cap (PRD user story 18 — matches Slice 5). */
export const MAX_DEEP_ITERATIONS = 10;

export interface RunDeepHunterOptions {
  runner: DeepHunterRunner;
  scope: Scope;
  hypothesis: Hypothesis;
  transport: ProbeTransport;
  /** Cap on deep-hunt iterations (default MAX_DEEP_ITERATIONS). */
  maxIterations?: number;
  /** Per-hypothesis probe budget for the recipe's BUDGET section. */
  budget?: RecipeBudget;
  /** Prose CONTEXT for the recipe (surface/auth/tenant setup). */
  context?: string;
  takeToken?: () => Promise<boolean>;
  session?: string;
  pass?: number;
  now?: () => string;
  agent?: string;
}

export interface DeepHunterOutcome {
  hypothesisId: string;
  /** How the deep hunt ended. `escalated` = hit the iteration cap. */
  result: "finding" | "rejected" | "escalated";
  iterations: number;
  probesFired: number;
  duplicatesSkipped: number;
  /** Ids of any candidate findings written (0 or 1), enqueued for verify. */
  findingIds: string[];
}

/**
 * Deep-hunt one hypothesis. Iterates with a FRESH agent each pass — every
 * iteration reads the prior outputs from disk, accumulates their mutation hints,
 * re-computes the `alreadyTried` ledger slice, and re-spawns. Terminates on:
 *   - `finding`            → write it to `findings/<id>/`, return its id, stop;
 *   - `rejected`           → stop (hypothesis does not hold);
 *   - `needs_more_budget`  → accumulate the hint, iterate again;
 *   - iteration cap        → ESCALATE ready-for-human (never a silent drop).
 * Findings flow back into the SAME verify loop as Tier 1's.
 */
export async function runDeepHunter(
  workdir: string,
  opts: RunDeepHunterOptions,
): Promise<DeepHunterOutcome> {
  const cap = opts.maxIterations ?? MAX_DEEP_ITERATIONS;
  const takeToken = opts.takeToken ?? (async () => true);
  const pass = opts.pass ?? 0;
  const session = opts.session ?? opts.scope.auth.username ?? "default";
  const budget: RecipeBudget = opts.budget ?? {
    max_probes: opts.scope.budget.max_probes,
    max_minutes: opts.scope.budget.max_minutes,
  };
  const h = opts.hypothesis;
  const agent = opts.agent ?? `T2-${h.class}`;

  const outcome: DeepHunterOutcome = {
    hypothesisId: h.id,
    result: "rejected",
    iterations: 0,
    probesFired: 0,
    duplicatesSkipped: 0,
    findingIds: [],
  };

  for (let iteration = 1; iteration <= cap; iteration += 1) {
    outcome.iterations = iteration;

    // Fresh agent: inherit prior state from disk, accumulate the mutation trail.
    const prior = await readPriorIterations(workdir, h.id);
    const mutationHints = prior
      .map((p) => p.mutation_hint)
      .filter((s): s is string => Boolean(s && s.trim()));

    // Re-compute the ledger slice for this hypothesis (endpoint + class) every
    // iteration, so the hard-check reflects probes fired in earlier iterations.
    const ledger = await readLedger(workdir);
    const slice = ledger.filter(
      (e) => e.class === h.class && e.endpoint === h.target_endpoint,
    );
    const alreadyTried: ProbeKey[] = slice.map(ledgerEntryKey);
    const alreadyTriedIds = [...new Set(slice.map((e) => e.payload_id))];

    const recipe = buildRecipe({
      hypothesis: h,
      iteration,
      context: opts.context ?? "",
      alreadyTried: alreadyTriedIds,
      mutationHints,
      budget,
    });

    const baseFirer = createProbeFirer({
      workdir,
      pass,
      agent,
      surface: h.class,
      vuln_class: h.class,
      ledger,
      takeToken,
      transport: opts.transport,
      now: opts.now,
    });
    const fire: ProbeFirer = async (probe) => {
      const out = await baseFirer(probe);
      if (out.fired) outcome.probesFired += 1;
      else if (out.reason === "duplicate") outcome.duplicatesSkipped += 1;
      return out;
    };

    const raw = await opts.runner({
      hypothesis: h,
      iteration,
      recipe,
      alreadyTried,
      mutationHints,
      fire,
      session,
      takeToken,
      budget,
    });
    const output = DeepHunterOutputSchema.parse(raw);
    await writeIteration(workdir, h.id, iteration, output);

    if (output.outcome === "finding") {
      const id = `f-${String(await nextFindingSeq(workdir)).padStart(4, "0")}`;
      const finding: HunterFinding = HunterFindingSchema.parse(output.finding);
      await writeFinding(workdir, id, finding);
      outcome.result = "finding";
      outcome.findingIds.push(id);
      return outcome;
    }
    if (output.outcome === "rejected") {
      outcome.result = "rejected";
      return outcome;
    }
    // needs_more_budget → loop with a fresh agent (hint already on disk).
  }

  // Hit the iteration cap without a verdict: escalate rather than drop.
  outcome.result = "escalated";
  await escalateHypothesis(
    workdir,
    h,
    `deep-hunt hit the ${cap}-iteration cap without confirming or rejecting`,
  );
  return outcome;
}
