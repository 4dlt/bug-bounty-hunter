// Stage 6 — the Tier 2 hypothesis queue.
//
// `hypotheses.jsonl` is the engagement's append-only priority queue, fed from
// three sources over the pipeline's life:
//   1. Verifier escalations   (source: "verifier_escalation") — highest signal
//   2. Plan a-priori          (source: "plan_apriori")        — Opus's curated
//   3. Tier 1 reactive        (source: "tier1_reactive")      — sweep signals
//
// Tier 2 consumes it in exactly that priority order (PRD user story 8: the
// highest-signal leads get the deep-hunt budget). A hard cap of 15 hypotheses is
// processed per engagement (user story 9); the overflow is logged as `deferred`
// rather than silently dropped, so the operator can see what deep-hunting ran out
// of budget for.
//
// The ordering + cap live here as pure functions over a parsed hypothesis list,
// so the priority rule is one exhaustively-testable unit; `stage.ts` executes it.

import { promises as fs } from "node:fs";
import path from "node:path";
import {
  HypothesisSchema,
  hypothesesPath,
  HYPOTHESIS_SOURCES,
  type Hypothesis,
} from "../plan.ts";

/** Hard cap on hypotheses deep-hunted per engagement (PRD user story 9). */
export const MAX_TIER2_HYPOTHESES = 15;

/**
 * Priority of each hypothesis source, lower = processed first. Verifier
 * escalations are the highest-signal leads (a finding that nearly verified),
 * then Plan's curated a-priori list, then the Tier 1 sweep's reactive signals.
 * Derived from HYPOTHESIS_SOURCES order-independently so a new source added to
 * the enum without a priority here is a compile error.
 */
export const SOURCE_PRIORITY: Record<Hypothesis["source"], number> = {
  verifier_escalation: 0,
  plan_apriori: 1,
  tier1_reactive: 2,
};

// Exhaustiveness guard: every source in the enum must have a priority.
const _prioritiesComplete: Record<(typeof HYPOTHESIS_SOURCES)[number], number> =
  SOURCE_PRIORITY;
void _prioritiesComplete;

/**
 * Order hypotheses by source priority (verifier_escalation → plan_apriori →
 * tier1_reactive), preserving the original file order within a source — a stable
 * sort so two `plan_apriori` leads keep their seeded sequence.
 */
export function orderHypotheses(hyps: Hypothesis[]): Hypothesis[] {
  return hyps
    .map((h, i) => [h, i] as const)
    .sort(
      ([a, ai], [b, bi]) =>
        SOURCE_PRIORITY[a.source] - SOURCE_PRIORITY[b.source] || ai - bi,
    )
    .map(([h]) => h);
}

/** What the queue planner decides: the first `cap` to process, the rest deferred. */
export interface QueuePlan {
  process: Hypothesis[];
  deferred: Hypothesis[];
}

/**
 * Split the ordered hypotheses into the `cap` (default 15) that get deep-hunted
 * and the overflow that is deferred. Ordering is applied first, so the deferred
 * set is always the LOWEST-priority tail — never a high-signal verifier
 * escalation dropped because a batch of reactive signals came first in the file.
 */
export function planQueue(
  hyps: Hypothesis[],
  cap: number = MAX_TIER2_HYPOTHESES,
): QueuePlan {
  const ordered = orderHypotheses(hyps);
  return { process: ordered.slice(0, cap), deferred: ordered.slice(cap) };
}

// ---------------------------------------------------------------------------
// Reading hypotheses.jsonl
// ---------------------------------------------------------------------------

/**
 * Read + parse `hypotheses.jsonl`. A missing file yields an empty queue; an
 * unparseable or schema-invalid line is skipped (a half-written append can never
 * crash the deep-hunt stage), mirroring `readFindings`' tolerance.
 */
export async function readHypotheses(workdir: string): Promise<Hypothesis[]> {
  let raw: string;
  try {
    raw = await fs.readFile(hypothesesPath(workdir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: Hypothesis[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed = HypothesisSchema.safeParse(JSON.parse(line));
      if (parsed.success) out.push(parsed.data);
    } catch {
      // ignore a truncated / malformed line
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Deferred overflow log
// ---------------------------------------------------------------------------

export function deferredPath(workdir: string): string {
  return path.join(workdir, "tier2", "deferred.jsonl");
}

/** One deferred-overflow record: which hypothesis the 15-cap left un-hunted. */
export interface DeferredRecord {
  id: string;
  source: Hypothesis["source"];
  status: "deferred";
  reason: string;
}

/**
 * Append the deferred (overflow) hypotheses to `tier2/deferred.jsonl` so the
 * 15-cap is observable — the operator can see exactly what deep-hunting ran out
 * of budget for. Append-only + lock-free like the other jsonl artifacts.
 */
export async function logDeferred(
  workdir: string,
  deferred: Hypothesis[],
): Promise<DeferredRecord[]> {
  const records: DeferredRecord[] = deferred.map((h) => ({
    id: h.id,
    source: h.source,
    status: "deferred",
    reason: "hypothesis_cap_exceeded",
  }));
  if (records.length === 0) return records;
  await fs.mkdir(path.dirname(deferredPath(workdir)), { recursive: true });
  await fs.appendFile(
    deferredPath(workdir),
    records.map((r) => JSON.stringify(r)).join("\n") + "\n",
    "utf8",
  );
  return records;
}
