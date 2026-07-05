// Stage 3.6 — Checklist Reviewer (the second of v2's three separated LLM roles).
//
// The Reviewer reads ONE authored checklist, the program rules, and 1-2 sample
// sweep findings, and answers exactly three yes/no questions about it:
//   1. Does the checklist exclude program-documented exclusion classes?
//   2. Is there a criterion that distinguishes a real bug from public-by-design
//      endpoints?
//   3. Is there a non-trivial impact gate?
// All three YES → approve. Any NO → reject (the orchestrator routes the retry;
// see stage.ts).
//
// STRUCTURAL RULE (the guard against v3's "LLM grades own work" trap): the
// Reviewer approves or halts and NOTHING ELSE. This module must NEVER write a
// `checklists/<class>.md` (that is the Author's writer, in author.ts) and must
// NEVER import the Author. The Reviewer can only ever write its own verdict —
// `checklists/<class>.approval.json`. See PRD "Three separated roles".

import { promises as fs } from "node:fs";
import { z } from "zod";
import type { Scope } from "../scope.ts";
import { checklistsDir, approvalPath } from "./paths.ts";
import type { FindingMeta } from "./author.ts";

// Re-exported so callers can find the Reviewer's artifact path via this module.
export { approvalPath } from "./paths.ts";

// This module imports the shared path helpers from paths.ts (a directory-path
// function that writes nothing) and the `FindingMeta` type from author.ts (a
// type-only import, erased at compile time). It NEVER imports the Author's
// checklist writer — the structural rule forbids one role editing the other's
// output, and a type carries no mutable state and cannot author a checklist.

// ---------------------------------------------------------------------------
// The three yes/no answers
// ---------------------------------------------------------------------------

/** The Reviewer's structured answer: exactly three yes/no verdicts + optional
 *  free-text notes explaining a NO (fed back to the Author on the retry). */
export const ReviewAnswersSchema = z.object({
  /** Q1 — excludes program-documented exclusion classes? */
  excludes_documented_exclusions: z.boolean(),
  /** Q2 — distinguishes a real bug from public-by-design endpoints? */
  distinguishes_public_by_design: z.boolean(),
  /** Q3 — has a non-trivial impact gate? */
  has_impact_gate: z.boolean(),
  notes: z.string().default(""),
});
export type ReviewAnswers = z.infer<typeof ReviewAnswersSchema>;

/** Approval requires ALL three questions answered YES. */
export function allYes(answers: ReviewAnswers): boolean {
  return (
    answers.excludes_documented_exclusions &&
    answers.distinguishes_public_by_design &&
    answers.has_impact_gate
  );
}

/**
 * Turn a rejecting answer set into concrete feedback lines for the Author's
 * rewrite — one line per NO, naming the failed criterion, plus the Reviewer's
 * notes. Ordered, deterministic; empty when the answers are all YES.
 */
export function feedbackFrom(answers: ReviewAnswers): string[] {
  const fb: string[] = [];
  if (!answers.excludes_documented_exclusions) {
    fb.push(
      "Q1 NO: the checklist must explicitly exclude program-documented exclusion classes.",
    );
  }
  if (!answers.distinguishes_public_by_design) {
    fb.push(
      "Q2 NO: add a criterion that distinguishes a real bug from public-by-design endpoints.",
    );
  }
  if (!answers.has_impact_gate) {
    fb.push("Q3 NO: add a non-trivial impact gate.");
  }
  if (answers.notes.trim()) fb.push(`Reviewer notes: ${answers.notes.trim()}`);
  return fb;
}

// ---------------------------------------------------------------------------
// The Reviewer agent seam
// ---------------------------------------------------------------------------

/** Everything the Reviewer agent reads to judge one checklist. */
export interface ReviewerInput {
  vuln_class: string;
  scope: Scope;
  /** The authored checklist markdown, verbatim. */
  checklist: string;
  /** 1-2 sample sweep findings for this class. */
  findings: FindingMeta[];
}

/** Injected agent implementation (Sonnet, `level: 'standard'`): read the
 *  checklist, return the three yes/no answers. */
export type ReviewerRunner = (input: ReviewerInput) => Promise<ReviewAnswers>;

/** Max sample findings shown to the Reviewer (the issue's "1-2 sample findings"). */
export const REVIEWER_SAMPLE = 2;

export interface ReviewChecklistOptions {
  runner: ReviewerRunner;
  scope: Scope;
  checklist: string;
  findings: FindingMeta[];
}

export interface ReviewResult {
  answers: ReviewAnswers;
  approved: boolean;
}

/**
 * Ask the Reviewer to judge one checklist. Returns the validated three-answer
 * verdict and whether it approves (all YES). This does NOT persist anything —
 * writing the approval verdict is a separate, explicit step (`writeApproval`)
 * so the answer-gathering stays a pure function of its inputs.
 */
export async function reviewChecklist(
  vulnClass: string,
  opts: ReviewChecklistOptions,
): Promise<ReviewResult> {
  const answers = ReviewAnswersSchema.parse(
    await opts.runner({
      vuln_class: vulnClass,
      scope: opts.scope,
      checklist: opts.checklist,
      findings: opts.findings.slice(0, REVIEWER_SAMPLE),
    }),
  );
  return { answers, approved: allYes(answers) };
}

// ---------------------------------------------------------------------------
// Approval verdict — the ONLY artifact this role writes
// ---------------------------------------------------------------------------

/**
 * `checklists/<class>.approval.json` — the Reviewer's verdict on a checklist.
 * `approved: true` freezes the checklist; `approved: false` (only ever written
 * after the one retry has also failed) records the halt.
 */
export const ApprovalSchema = z.object({
  class: z.string().min(1),
  approved: z.boolean(),
  /** Which Author attempt (1 or 2) this verdict judged. */
  attempt: z.number().int().positive(),
  answers: ReviewAnswersSchema,
});
export type Approval = z.infer<typeof ApprovalSchema>;

/** Persist the Reviewer's verdict. This is the Reviewer role's ONLY writer. */
export async function writeApproval(
  workdir: string,
  approval: Approval,
): Promise<string> {
  const validated = ApprovalSchema.parse(approval);
  await fs.mkdir(checklistsDir(workdir), { recursive: true });
  const file = approvalPath(workdir, validated.class);
  await fs.writeFile(file, JSON.stringify(validated, null, 2) + "\n", "utf8");
  return file;
}

export async function readApproval(
  workdir: string,
  vulnClass: string,
): Promise<Approval> {
  const raw = await fs.readFile(approvalPath(workdir, vulnClass), "utf8");
  return ApprovalSchema.parse(JSON.parse(raw));
}
