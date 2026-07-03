// Stage 6 — the Tier 2 deep-hunt driver.
//
// Reads `hypotheses.jsonl`, orders it by source priority (verifier_escalation →
// plan_apriori → tier1_reactive), caps it at 15 (the overflow logged as
// `deferred`), and deep-hunts each surviving hypothesis with a fresh-agent-per-
// iteration deep hunter (deep-hunter.ts). Findings the deep hunters emit land in
// `findings/<id>/` and flow back into the SAME verify loop (Slice 5).
//
// This is the standalone entry point (`bbh tier2` / the pipeline's Tier 2 pass).
// The verify loop also spawns a single deep hunter inline on a `promote_to_tier2`
// verdict via the `promoteToTier2` seam wired in verify/stage.ts — both paths run
// the same `runDeepHunter`.

import type { Scope } from "../scope.ts";
import type { Hypothesis } from "../plan.ts";
import type { ProbeTransport } from "../hunters/framework.ts";
import {
  readHypotheses,
  planQueue,
  logDeferred,
  MAX_TIER2_HYPOTHESES,
  type DeferredRecord,
} from "./queue.ts";
import {
  runDeepHunter,
  type DeepHunterRunner,
  type DeepHunterOutcome,
} from "./deep-hunter.ts";
import type { RecipeBudget } from "./recipe.ts";

export interface RunTier2StageOptions {
  scope: Scope;
  /** The deep-hunt agent (injected, like every other role's runner). */
  runner: DeepHunterRunner;
  transport: ProbeTransport;
  /** Override the hypotheses to process (defaults to reading hypotheses.jsonl). */
  hypotheses?: Hypothesis[];
  /** Override the 15-hypothesis cap (tests use a small cap). */
  maxHypotheses?: number;
  /** Per-hypothesis iteration cap (defaults to deep-hunter's MAX_DEEP_ITERATIONS). */
  maxIterations?: number;
  budget?: RecipeBudget;
  /** Engagement-budget predicate; when true the stage stops spawning hunters. */
  budgetExhausted?: () => boolean;
  takeToken?: () => Promise<boolean>;
  context?: string;
  pass?: number;
  session?: string;
  now?: () => string;
}

export interface Tier2StageOutcome {
  /** Deep-hunt result per processed hypothesis, in priority order. */
  results: DeepHunterOutcome[];
  /** Ids of all candidate findings produced, enqueued for verify. */
  findingIds: string[];
  /** Hypotheses deferred by the 15-cap (overflow), logged to tier2/deferred.jsonl. */
  deferred: DeferredRecord[];
  /** Number of hypotheses actually deep-hunted. */
  processed: number;
  /** True when the loop stopped early because the engagement budget ran out. */
  budgetExhausted: boolean;
}

/**
 * Run the Tier 2 deep-hunt pass. Consumes the hypothesis queue in priority order
 * up to the cap, deep-hunts each, and collects the findings for the verify loop.
 * The 15-cap overflow is logged as `deferred`; an exhausted engagement budget
 * stops spawning further hunters (the already-hunted results are kept).
 */
export async function runTier2Stage(
  workdir: string,
  opts: RunTier2StageOptions,
): Promise<Tier2StageOutcome> {
  const cap = opts.maxHypotheses ?? MAX_TIER2_HYPOTHESES;
  const budgetExhausted = opts.budgetExhausted ?? (() => false);

  const hyps = opts.hypotheses ?? (await readHypotheses(workdir));
  const { process: toProcess, deferred } = planQueue(hyps, cap);
  const deferredRecords = await logDeferred(workdir, deferred);

  const outcome: Tier2StageOutcome = {
    results: [],
    findingIds: [],
    deferred: deferredRecords,
    processed: 0,
    budgetExhausted: false,
  };

  for (const hypothesis of toProcess) {
    if (budgetExhausted()) {
      outcome.budgetExhausted = true;
      break;
    }
    const result = await runDeepHunter(workdir, {
      runner: opts.runner,
      scope: opts.scope,
      hypothesis,
      transport: opts.transport,
      maxIterations: opts.maxIterations,
      budget: opts.budget,
      context: opts.context,
      takeToken: opts.takeToken,
      pass: opts.pass,
      session: opts.session,
      now: opts.now,
    });
    outcome.results.push(result);
    outcome.findingIds.push(...result.findingIds);
    outcome.processed += 1;
  }

  return outcome;
}
