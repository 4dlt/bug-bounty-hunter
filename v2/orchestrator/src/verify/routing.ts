// Stage 5 — pure verdict routing.
//
// One total, side-effect-free function maps each of the eight verdicts onto the
// orchestrator action it triggers. Keeping it pure (verdict in, action out) makes
// the whole routing table one exhaustively-tested unit — the stage driver
// (stage.ts) executes the actions; this decides them.
//
// The routing table (PRD Stage 5):
//   - confirmed         → promote   (→ verdicts/pass-N.json → report queue)
//   - repro_failed      → requeue   (surgical re-dispatch by default)
//   - weak_evidence     → requeue   (surgical re-dispatch by default)
//   - out_of_scope      → drop      (+ logged)
//   - duplicate         → merge     (into the existing confirmed finding)
//   - severity_mismatch → downgrade (kept, severity lowered)
//   - non_deterministic → escalate  (ready-for-human, evidence preserved)
//   - rate_limited      → backoff   (verify-only re-verify, no hunter re-dispatch)

import type { Verdict, NextStep } from "./verifier.ts";

export type VerdictAction =
  | { action: "promote" }
  | { action: "requeue"; next_step: NextStep }
  | { action: "drop" }
  | { action: "merge" }
  | { action: "downgrade" }
  | { action: "escalate" }
  | { action: "backoff" };

/**
 * Map a verdict onto its orchestrator action. `repro_failed` / `weak_evidence`
 * are the two re-queue verdicts; a re-queue verdict that omits `next_step`
 * defaults to `surgical` (re-dispatch the originating Tier 1 hunter) — the
 * conservative choice, since `promote_to_tier2` is a heavier escalation.
 */
export function routeVerdict(verdict: Verdict): VerdictAction {
  switch (verdict.verdict) {
    case "confirmed":
      return { action: "promote" };
    case "repro_failed":
    case "weak_evidence":
      return { action: "requeue", next_step: verdict.next_step ?? "surgical" };
    case "out_of_scope":
      return { action: "drop" };
    case "duplicate":
      return { action: "merge" };
    case "severity_mismatch":
      return { action: "downgrade" };
    case "non_deterministic":
      return { action: "escalate" };
    case "rate_limited":
      return { action: "backoff" };
    default: {
      // Exhaustiveness guard: adding a verdict without a route is a compile error.
      const never: never = verdict.verdict;
      throw new Error(`Unrouted verdict: ${String(never)}`);
    }
  }
}

/** True for the two verdicts that put a finding back through the loop. */
export function isRequeueVerdict(verdict: Verdict): boolean {
  return verdict.verdict === "repro_failed" || verdict.verdict === "weak_evidence";
}
