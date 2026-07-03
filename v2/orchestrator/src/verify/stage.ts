// Stages 4 ↔ 5 — the verify loop with surgical re-dispatch.
//
// This is the orchestrator that drives the stateless Verifier (verifier.ts) and
// executes the pure routing table (routing.ts). For each candidate finding it
// re-fires the PoC, gets a verdict, and acts on it:
//   - confirmed         → promoted (collected into verdicts/pass-N.json)
//   - repro_failed /
//     weak_evidence     → re-queue. `surgical` re-dispatches the ORIGINATING
//                         Tier 1 hunter with the `reason` + `mutation_hint`
//                         prepended, then re-verifies. `promote_to_tier2` is a
//                         heavier escalation deferred to Slice 6 (recorded, not
//                         looped).
//   - out_of_scope      → dropped + logged
//   - duplicate         → merged into the existing confirmed finding
//   - severity_mismatch → kept, severity downgraded one band
//   - non_deterministic → escalated ready-for-human, evidence preserved
//   - rate_limited      → backoff + re-verify (verify-only; no hunter re-dispatch)
//
// Loop control: it keeps a work queue and drains it, so it exits cleanly the
// moment no re-queue verdicts remain. Two guards bound it: a per-finding
// iteration cap (default 10) that ESCALATES rather than drops a finding that
// keeps failing, and an injectable engagement-budget predicate that stops the
// loop when the budget is exhausted. On exit it advances verify → report.

import { promises as fs } from "node:fs";
import path from "node:path";
import type { Scope } from "../scope.ts";
import type { Event } from "../state.ts";
import { findingsDir, findingDir } from "../hunters/framework.ts";
import type { FindingMeta } from "../checklist/author.ts";
import {
  verifyFinding,
  writeVerdict,
  writePassVerdicts,
  readFindingMeta,
  type Verdict,
  type VerifierRunner,
} from "./verifier.ts";
import type { PocExecutor } from "./refire.ts";
import { routeVerdict } from "./routing.ts";

// ---------------------------------------------------------------------------
// The iteration cap
// ---------------------------------------------------------------------------

/** Default cap on verify iterations per finding (PRD: 10 per hypothesis-id). */
export const MAX_ITERATIONS = 10;

// ---------------------------------------------------------------------------
// Surgical re-dispatch seam
// ---------------------------------------------------------------------------

/** What a surgical re-dispatch is handed: the finding + the Verifier's reason
 *  and expansion seed, which the caller prepends to the hunter's prompt. */
export interface SurgicalContext {
  finding: FindingMeta;
  reason: string;
  mutation_hint?: string;
}

/**
 * Re-run the originating Tier 1 hunter for a re-queued finding, with the
 * rejection `reason` + `mutation_hint` prepended to its prompt. Returns the ids
 * of any NEW findings the re-dispatch produced (each enqueued for verification);
 * the empty array means "no new candidate, just re-verify the existing one".
 */
export type SurgicalReDispatch = (ctx: SurgicalContext) => Promise<string[]>;

// ---------------------------------------------------------------------------
// Severity downgrade (severity_mismatch action)
// ---------------------------------------------------------------------------

const SEVERITY_LADDER: Record<string, string> = {
  critical: "high",
  high: "medium",
  medium: "low",
  low: "info",
  info: "info",
  unknown: "low",
};

/** Rewrite `finding.json` severity one band down (severity_mismatch). */
export async function downgradeSeverity(
  workdir: string,
  findingId: string,
): Promise<string> {
  const file = path.join(findingsDir(workdir), findingId, "finding.json");
  const meta = JSON.parse(await fs.readFile(file, "utf8")) as { severity?: string };
  const current = (meta.severity ?? "unknown").toLowerCase();
  const next = SEVERITY_LADDER[current] ?? "low";
  await fs.writeFile(file, JSON.stringify({ ...meta, severity: next }, null, 2) + "\n", "utf8");
  return next;
}

// ---------------------------------------------------------------------------
// ready-for-human escalation log
// ---------------------------------------------------------------------------

export function readyForHumanPath(workdir: string): string {
  return path.join(workdir, "ready-for-human.jsonl");
}

/** Flag a finding ready-for-human, preserving its evidence (already on disk). */
export async function escalateToHuman(
  workdir: string,
  findingId: string,
  reason: string,
): Promise<void> {
  await fs.mkdir(workdir, { recursive: true });
  const record = { finding_id: findingId, label: "ready-for-human", reason, evidence_dir: path.join(findingDir(workdir, findingId), "evidence") };
  await fs.appendFile(readyForHumanPath(workdir), JSON.stringify(record) + "\n", "utf8");
}

// ---------------------------------------------------------------------------
// The verify loop
// ---------------------------------------------------------------------------

export interface RunVerifyStageOptions {
  scope: Scope;
  verifierRunner: VerifierRunner;
  /** PoC re-fire executor (spawns `bash poc.sh` in production). */
  execute: PocExecutor;
  /** Re-run the originating hunter for a surgical re-queue. */
  reDispatch: SurgicalReDispatch;
  /** Cap on verify iterations per finding (default MAX_ITERATIONS). */
  maxIterations?: number;
  /** Engagement-budget predicate; when it returns true the loop stops. */
  budgetExhausted?: () => boolean;
  /** Backoff before a rate_limited re-verify (noop in tests). */
  backoff?: () => Promise<void>;
  /** The current pass number, stamped on verdicts/pass-N.json. */
  pass?: number;
}

export interface VerifyStageOutcome {
  /** Always `advance` (verify → report): the loop drained or the budget/cap hit. */
  event: Event;
  confirmed: string[];
  dropped: string[];
  merged: string[];
  downgraded: string[];
  /** ready-for-human (non_deterministic, or a finding that hit the cap). */
  escalated: string[];
  /** promote_to_tier2 re-queues, deferred to Slice 6. */
  deferredTier2: string[];
  /** Number of surgical hunter re-dispatches performed. */
  reDispatched: number;
  /** Verify iterations spent per finding id. */
  iterations: Record<string, number>;
  /** True when the loop stopped because the engagement budget was exhausted. */
  budgetExhausted: boolean;
}

/** List the candidate finding ids currently on disk, sorted. */
async function listFindingIds(workdir: string): Promise<string[]> {
  try {
    const entries = await fs.readdir(findingsDir(workdir));
    return entries.filter((e) => /^f-\d+$/.test(e)).sort();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
}

/**
 * Run the verify loop over every candidate finding. Re-fires each PoC, applies
 * the frozen checklist via the Verifier, routes the verdict, and loops until no
 * re-queue verdicts remain, every re-queuing finding hit the cap, or the budget
 * is exhausted. Always returns the `advance` event (verify → report).
 */
export async function runVerifyStage(
  workdir: string,
  opts: RunVerifyStageOptions,
): Promise<VerifyStageOutcome> {
  const cap = opts.maxIterations ?? MAX_ITERATIONS;
  const budgetExhausted = opts.budgetExhausted ?? (() => false);
  const backoff = opts.backoff ?? (async () => {});
  const pass = opts.pass ?? 0;

  const outcome: VerifyStageOutcome = {
    event: { type: "advance" },
    confirmed: [],
    dropped: [],
    merged: [],
    downgraded: [],
    escalated: [],
    deferredTier2: [],
    reDispatched: 0,
    iterations: {},
    budgetExhausted: false,
  };
  const confirmedVerdicts: Verdict[] = [];
  const iterations = new Map<string, number>();

  const queue = await listFindingIds(workdir);
  while (queue.length > 0) {
    if (budgetExhausted()) {
      outcome.budgetExhausted = true;
      break;
    }
    const id = queue.shift()!;
    const n = (iterations.get(id) ?? 0) + 1;
    iterations.set(id, n);

    const { verdict } = await verifyFinding(workdir, id, {
      runner: opts.verifierRunner,
      execute: opts.execute,
    });
    await writeVerdict(workdir, verdict);
    const route = routeVerdict(verdict);

    switch (route.action) {
      case "promote":
        outcome.confirmed.push(id);
        confirmedVerdicts.push(verdict);
        break;
      case "drop":
        outcome.dropped.push(id);
        break;
      case "merge":
        outcome.merged.push(id);
        break;
      case "downgrade":
        await downgradeSeverity(workdir, id);
        outcome.downgraded.push(id);
        break;
      case "escalate":
        // non_deterministic — flagged ready-for-human, evidence preserved.
        await escalateToHuman(workdir, id, verdict.reason);
        outcome.escalated.push(id);
        break;
      case "backoff":
        // rate_limited — verify-only re-verify, no hunter re-dispatch. The cap
        // guards against a permanently-throttled finding looping forever.
        if (n >= cap) {
          await escalateToHuman(workdir, id, verdict.reason);
          outcome.escalated.push(id);
        } else {
          await backoff();
          queue.push(id);
        }
        break;
      case "requeue":
        if (route.next_step === "promote_to_tier2") {
          // Tier 2 promotion is Slice 6 — record and stop looping this finding.
          outcome.deferredTier2.push(id);
          break;
        }
        // surgical: re-dispatch the originating hunter, then re-verify. On cap
        // exhaustion the finding is ESCALATED (ready-for-human), never dropped.
        if (n >= cap) {
          await escalateToHuman(workdir, id, verdict.reason);
          outcome.escalated.push(id);
          break;
        }
        {
          const meta = await readFindingMeta(workdir, id);
          const newIds = await opts.reDispatch({
            finding: meta,
            reason: verdict.reason,
            mutation_hint: verdict.mutation_hint,
          });
          outcome.reDispatched += 1;
          queue.push(id, ...newIds);
        }
        break;
    }
  }

  await writePassVerdicts(workdir, pass, confirmedVerdicts);
  outcome.iterations = Object.fromEntries(iterations);
  return outcome;
}
