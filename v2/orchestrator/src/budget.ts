// Engagement budget — the three runaway-protection thresholds (PRD user stories
// 24, 25). These are SAFETY NETS, not enforcement: the engagement halts cleanly
// the moment any one threshold is hit, writes a partial `report.md` from the
// findings confirmed to date, and marks `state.json.status: 'budget_exhausted'`.
//
//   - max_probes    — counted from `ledger.jsonl` (one line per fired probe)
//   - max_llm_calls — counted from LLM client invocations (injected reader)
//   - max_minutes   — wall-clock since the engagement started (injected clock)
//
// The pure `exceededBudgets` decision is table-testable; `BudgetTracker` wires
// it to live counters and exposes the sync predicate the verify loop consumes.

import { promises as fs } from "node:fs";
import type { Budget } from "./scope.ts";
import { ledgerPath } from "./hunters/ledger.ts";
import { writeState, type State } from "./state.ts";
import { writeReport } from "./report/report.ts";

// ---------------------------------------------------------------------------
// The pure decision
// ---------------------------------------------------------------------------

export type BudgetKind = "max_probes" | "max_llm_calls" | "max_minutes";

export interface BudgetUsage {
  probes: number;
  llm_calls: number;
  /** Wall-clock minutes elapsed since the engagement started. */
  minutes: number;
}

/**
 * Which budgets (if any) the current usage has met or exceeded. Order is stable
 * (probes, llm_calls, minutes) so a caller can report the first offender. A
 * usage exactly AT the limit counts as exhausted — the limit is a ceiling.
 */
export function exceededBudgets(
  usage: BudgetUsage,
  budget: Budget,
): BudgetKind[] {
  const hit: BudgetKind[] = [];
  if (usage.probes >= budget.max_probes) hit.push("max_probes");
  if (usage.llm_calls >= budget.max_llm_calls) hit.push("max_llm_calls");
  if (usage.minutes >= budget.max_minutes) hit.push("max_minutes");
  return hit;
}

/** True when any one budget threshold has been met or exceeded. */
export function isBudgetExhausted(usage: BudgetUsage, budget: Budget): boolean {
  return exceededBudgets(usage, budget).length > 0;
}

// ---------------------------------------------------------------------------
// Probe counting (from the append-only ledger)
// ---------------------------------------------------------------------------

/** Count fired probes = non-empty lines in `ledger.jsonl`. Missing file → 0. */
export async function countProbes(workdir: string): Promise<number> {
  let raw: string;
  try {
    raw = await fs.readFile(ledgerPath(workdir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw err;
  }
  let n = 0;
  for (const line of raw.split("\n")) if (line.trim().length > 0) n += 1;
  return n;
}

// ---------------------------------------------------------------------------
// The tracker
// ---------------------------------------------------------------------------

export interface BudgetTrackerOptions {
  workdir: string;
  budget: Budget;
  /** Epoch-ms clock (injected for tests). Defaults to `Date.now`. */
  now?: () => number;
  /** Engagement start (epoch ms). Defaults to the tracker's construction time. */
  startedAt?: number;
}

/**
 * Live budget accounting. Probes are read from the ledger on demand; LLM calls
 * are counted in-process via `recordLlmCall()`; wall-clock is derived from the
 * injected clock. `snapshot()` reads everything; `predicate()` returns the sync
 * `() => boolean` the verify loop's `budgetExhausted` hook expects, using the
 * probe count cached by the most recent `snapshot()`/`refresh()`.
 */
export class BudgetTracker {
  private readonly workdir: string;
  private readonly budget: Budget;
  private readonly now: () => number;
  private readonly startedAt: number;
  private llmCalls = 0;
  private cachedProbes = 0;

  constructor(opts: BudgetTrackerOptions) {
    this.workdir = opts.workdir;
    this.budget = opts.budget;
    this.now = opts.now ?? (() => Date.now());
    this.startedAt = opts.startedAt ?? this.now();
  }

  /** Record one LLM client invocation against the `max_llm_calls` budget. */
  recordLlmCall(n = 1): void {
    this.llmCalls += n;
  }

  get llmCallCount(): number {
    return this.llmCalls;
  }

  private elapsedMinutes(): number {
    return (this.now() - this.startedAt) / 60000;
  }

  /** Re-read the probe count from the ledger into the cache. Returns it. */
  async refresh(): Promise<number> {
    this.cachedProbes = await countProbes(this.workdir);
    return this.cachedProbes;
  }

  /** Full usage snapshot (refreshes the probe cache from the ledger). */
  async snapshot(): Promise<BudgetUsage> {
    await this.refresh();
    return {
      probes: this.cachedProbes,
      llm_calls: this.llmCalls,
      minutes: this.elapsedMinutes(),
    };
  }

  /** Budgets exhausted right now (refreshes probes first). */
  async exhausted(): Promise<BudgetKind[]> {
    return exceededBudgets(await this.snapshot(), this.budget);
  }

  /**
   * A synchronous predicate for the verify loop. Uses the LLM-call count and
   * wall-clock live, plus the probe count from the last `snapshot()`/`refresh()`
   * (the loop refreshes between findings). True when any budget is exhausted.
   */
  predicate(): () => boolean {
    return () =>
      isBudgetExhausted(
        {
          probes: this.cachedProbes,
          llm_calls: this.llmCalls,
          minutes: this.elapsedMinutes(),
        },
        this.budget,
      );
  }
}

// ---------------------------------------------------------------------------
// Clean budget halt
// ---------------------------------------------------------------------------

export interface BudgetHaltResult {
  state: State;
  exceeded: BudgetKind[];
  report: string;
}

/**
 * Halt the engagement cleanly for budget exhaustion: write a partial `report.md`
 * from the findings confirmed to date, mark `state.json.status:
 * 'budget_exhausted'`, and persist. The `current_stage` is preserved (the
 * engagement stopped where it was); only the status flips. Returns the new state
 * plus the rendered report so the caller can log/exit.
 */
export async function haltForBudget(
  workdir: string,
  state: State,
  exceeded: BudgetKind[],
): Promise<BudgetHaltResult> {
  const halted: State = { ...state, status: "budget_exhausted" };
  const report = await writeReport(workdir, halted);
  await writeState(workdir, halted);
  return { state: halted, exceeded, report };
}
