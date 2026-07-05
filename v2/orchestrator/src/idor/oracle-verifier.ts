// The Verifier wired to the IDOR oracle (no LLM this phase).
//
// A `VerifierRunner` that replaces the Sonnet verifier for IDOR findings: it
// reads the differential the hunter stashed in `evidence/oracle.json`, runs the
// PURE oracle over it, and emits exactly one verdict:
//   - oracle confirms  → `confirmed`   (→ promote → report)
//   - oracle cannot    → `weak_evidence` (→ re-queue → escalated ready-for-human
//                        at the iteration cap; the candidate is SURFACED, never
//                        dropped — the operator stays the final gate)
//
// "confirmed" is therefore a mechanical fact (the oracle reproduced the leak),
// not an LLM's opinion (PRD user story 8).

import type { Verdict, VerifierInput, VerifierRunner } from "../verify/verifier.ts";
import { runIdorOracle, type IdorObservation } from "./oracle.ts";

/** The oracle input the hunter wrote to `evidence/oracle.json`. */
export const ORACLE_EVIDENCE_FILE = "oracle.json";

/** Parse the stashed differential; a missing/garbled file is a non-confirmation
 *  (weak_evidence), not a crash — a candidate is never lost to a parse error. */
export function readOracleObservation(input: VerifierInput): IdorObservation | null {
  const raw = input.evidence[ORACLE_EVIDENCE_FILE];
  if (!raw) return null;
  try {
    return JSON.parse(raw) as IdorObservation;
  } catch {
    return null;
  }
}

/**
 * Build the oracle-backed Verifier. For a finding carrying an oracle differential
 * it rules mechanically; a finding with no differential (a non-IDOR class, or a
 * malformed one) falls back to `weak_evidence` so it is surfaced rather than
 * silently confirmed or dropped.
 */
export function createOracleVerifierRunner(): VerifierRunner {
  return async (input: VerifierInput): Promise<Verdict> => {
    const observation = readOracleObservation(input);
    if (!observation) {
      return {
        finding_id: input.finding_id,
        verdict: "weak_evidence",
        reason: "no oracle differential on this finding — surfaced for human review",
      };
    }

    const ruling = runIdorOracle(observation);
    if (ruling.confirmed) {
      return {
        finding_id: input.finding_id,
        verdict: "confirmed",
        reason: `oracle confirmed (${ruling.confidence}): ${ruling.reason}`,
      };
    }
    return {
      finding_id: input.finding_id,
      verdict: "weak_evidence",
      reason: `oracle could not confirm: ${ruling.reason}`,
    };
  };
}
