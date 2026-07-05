// Stage 3 — the parallel Tier 1 sweep.
//
// The sweep walks every `(surface × vuln class)` cell of `hunt-plan.json` and
// dispatches one hunter per cell through a bounded worker pool (concurrency cap
// = `scope.sweep_concurrency`, default 5). Each hunter fires its probes through
// the framework's dedupe+token+ledger firer and returns candidate findings plus
// reactive hypotheses.
//
// After the pool drains, the sweep:
//   - stamps the collected reactive hypotheses (`source: "tier1_reactive"`) and
//     appends them to `hypotheses.jsonl` (up to the engagement's 15-hypothesis
//     cap), so signals that did not become findings still queue for Tier 2;
//   - derives `coverage.json` from the ledger + hunt plan, marking every planned
//     cell `swept` / `deep_dived` / `GAP`;
//   - returns the `advance` event (sweep → author).
//
// A cell whose class has no hunter prompt is not silently skipped — it logs a
// `coverage_gap`, satisfying the invariant that every cell either produces
// ledger entries or a logged gap.

import {
  runHunter,
  resolveHunterClass,
  hunterPromptExists,
  type HunterRunner,
  type Payload,
  type ProbeTransport,
  type WrittenFinding,
  type ReactiveHypothesisInput,
} from "./framework.ts";
import { readLedger } from "./ledger.ts";
import {
  deriveCoverage,
  writeCoverage,
  countGaps,
  type Coverage,
} from "./coverage.ts";
import {
  appendHypotheses,
  hypothesesPath,
  HypothesisSchema,
  type Hypothesis,
  type HuntPlanCell,
} from "../plan.ts";
import { promises as fs } from "node:fs";
import type { Scope, CoverageGap } from "../scope.ts";
import type { Event } from "../state.ts";

// ---------------------------------------------------------------------------
// Bounded concurrency
// ---------------------------------------------------------------------------

/**
 * Map `fn` over `items` with at most `limit` calls in flight at once. Order of
 * results matches `items`; a worker picks the next index the moment it frees up,
 * so the pool stays saturated without ever exceeding `limit`.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workerCount = Math.max(1, Math.min(limit, items.length));
  const worker = async (): Promise<void> => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]!, i);
    }
  };
  await Promise.all(Array.from({ length: workerCount }, worker));
  return results;
}

// ---------------------------------------------------------------------------
// Reactive hypotheses
// ---------------------------------------------------------------------------

/** Hard cap on hypotheses per engagement (PRD user story 9). */
export const MAX_HYPOTHESES = 15;

const REACTIVE_ID = /^h-react-(\d+)$/;

/** Next `h-react-NNNN` sequence, continuing past any already in the file. */
export async function nextReactiveSeq(workdir: string): Promise<number> {
  let raw: string;
  try {
    raw = await fs.readFile(hypothesesPath(workdir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 1;
    throw err;
  }
  let max = 0;
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const m = REACTIVE_ID.exec((JSON.parse(line) as { id?: string }).id ?? "");
      if (m) max = Math.max(max, parseInt(m[1]!, 10));
    } catch {
      // ignore an unparseable pre-existing line
    }
  }
  return max + 1;
}

/** Count non-blank rows already in `hypotheses.jsonl` (0 if the file is absent). */
async function countHypotheses(workdir: string): Promise<number> {
  try {
    const raw = await fs.readFile(hypothesesPath(workdir), "utf8");
    return raw.split("\n").filter((l) => l.trim().length > 0).length;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw err;
  }
}

/** Stamp reactive inputs into queued `tier1_reactive` hypotheses. */
export function stampReactiveHypotheses(
  inputs: ReactiveHypothesisInput[],
  startSeq: number,
): Hypothesis[] {
  return inputs.map((h, i) =>
    HypothesisSchema.parse({
      id: `h-react-${String(startSeq + i).padStart(4, "0")}`,
      source: "tier1_reactive",
      class: h.class ?? "unknown",
      target_endpoint: h.target_endpoint,
      hypothesis: h.hypothesis,
      signal_evidence: h.signal_evidence,
      estimated_payout_band: null,
      status: "queued",
    }),
  );
}

// ---------------------------------------------------------------------------
// Sweep orchestration
// ---------------------------------------------------------------------------

export interface RunSweepOptions {
  scope: Scope;
  /** Cells to sweep — typically `readHuntPlan(workdir)`. */
  cells: HuntPlanCell[];
  /** Resolve the agent that hunts a cell; `null` → no hunter, logs a gap. */
  runnerFor: (cell: HuntPlanCell) => HunterRunner | null;
  /** Payload corpus for a cell's class. */
  payloadsFor?: (cell: HuntPlanCell) => Payload[];
  transport: ProbeTransport;
  takeToken?: () => Promise<boolean>;
  pass?: number;
  /** Override the concurrency cap (defaults to `scope.sweep_concurrency`). */
  concurrency?: number;
  session?: string;
  now?: () => string;
  onCoverageGap?: (gap: CoverageGap) => void;
  /** Prompts dir override (tests point this at a fixture dir). */
  promptsDir?: string;
}

export interface SweepOutcome {
  /** Always `advance` (sweep → author): the sweep ran every cell or gapped it. */
  event: Event;
  cellsRun: number;
  cellsGapped: number;
  probesFired: number;
  findings: WrittenFinding[];
  reactiveHypotheses: Hypothesis[];
  droppedHypotheses: number;
  coverage: Coverage;
  gaps: number;
  /** Peak number of hunters that were in flight at once. */
  maxConcurrency: number;
}

interface CellResult {
  gapped: boolean;
  probesFired: number;
  findings: WrittenFinding[];
  reactiveHypotheses: ReactiveHypothesisInput[];
}

/**
 * Run the parallel Tier 1 sweep over the hunt plan. Dispatches one hunter per
 * cell through the bounded pool, collects findings + reactive hypotheses, then
 * seeds the reactive stream, writes `coverage.json`, and advances sweep → author.
 */
export async function runSweep(
  workdir: string,
  opts: RunSweepOptions,
): Promise<SweepOutcome> {
  const concurrency = opts.concurrency ?? opts.scope.sweep_concurrency;
  const takeToken = opts.takeToken ?? (async () => true);
  const pass = opts.pass ?? 0;
  const payloadsFor = opts.payloadsFor ?? (() => []);

  let inFlight = 0;
  let maxConcurrency = 0;

  const perCell = await mapWithConcurrency(
    opts.cells,
    Math.max(1, concurrency),
    async (cell): Promise<CellResult> => {
      inFlight += 1;
      maxConcurrency = Math.max(maxConcurrency, inFlight);
      try {
        const runner = opts.runnerFor(cell);
        const hasPrompt = await hunterPromptExists(cell.vuln_class, opts.promptsDir);
        if (!runner || !hasPrompt) {
          opts.onCoverageGap?.({
            kind: "coverage_gap",
            url: null,
            host: null,
            reason: `no Tier 1 hunter for class "${cell.vuln_class}" on surface "${cell.surface}"`,
          });
          return { gapped: true, probesFired: 0, findings: [], reactiveHypotheses: [] };
        }
        const outcome = await runHunter(workdir, {
          runner,
          scope: opts.scope,
          surface: cell.surface,
          // Ledger + coverage stay keyed to the PLAN class; the resolved class
          // only picks the prompt/agent identity.
          vuln_class: cell.vuln_class,
          agent: `H-${resolveHunterClass(cell.vuln_class)}`,
          endpoints: cell.relevant_endpoints,
          payloads: payloadsFor(cell),
          transport: opts.transport,
          pass,
          session: opts.session,
          takeToken,
          now: opts.now,
        });
        // A hunter that ran but fired nothing still leaves the cell un-probed:
        // log a coverage_gap so the invariant "every cell has ledger entries OR
        // a logged gap" holds even for an empty sweep (the endpoints also show
        // up as GAP in coverage.json).
        if (outcome.probesFired === 0) {
          opts.onCoverageGap?.({
            kind: "coverage_gap",
            url: null,
            host: null,
            reason: `cell swept but no probes fired for class "${cell.vuln_class}" on surface "${cell.surface}"`,
          });
        }
        return {
          gapped: false,
          probesFired: outcome.probesFired,
          findings: outcome.findings,
          reactiveHypotheses: outcome.reactiveHypotheses,
        };
      } finally {
        inFlight -= 1;
      }
    },
  );

  const findings = perCell.flatMap((r) => r.findings);
  const probesFired = perCell.reduce((n, r) => n + r.probesFired, 0);
  const cellsGapped = perCell.filter((r) => r.gapped).length;
  const cellsRun = perCell.length - cellsGapped;
  const rawHypotheses = perCell.flatMap((r) => r.reactiveHypotheses);

  // Seed the reactive stream, respecting the 15-hypothesis engagement cap.
  const alreadyQueued = await countHypotheses(workdir);
  const room = Math.max(0, MAX_HYPOTHESES - alreadyQueued);
  const kept = rawHypotheses.slice(0, room);
  const droppedHypotheses = rawHypotheses.length - kept.length;
  const reactiveHypotheses = stampReactiveHypotheses(
    kept,
    await nextReactiveSeq(workdir),
  );
  await appendHypotheses(workdir, reactiveHypotheses);

  // Derive + persist coverage from the ledger every cell just appended to.
  const ledger = await readLedger(workdir);
  const coverage = deriveCoverage(opts.cells, ledger);
  await writeCoverage(workdir, coverage);

  return {
    event: { type: "advance" },
    cellsRun,
    cellsGapped,
    probesFired,
    findings,
    reactiveHypotheses,
    droppedHypotheses,
    coverage,
    gaps: countGaps(coverage),
    maxConcurrency,
  };
}
