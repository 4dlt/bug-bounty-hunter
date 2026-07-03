// Stages 3.5 + 3.6 routing — the approve-or-halt orchestrator over the two
// separated roles (Author in author.ts, Reviewer in reviewer.ts).
//
// This module is the ONLY place that touches both roles: it drives the Author
// to write checklists, drives the Reviewer to judge them, and routes on the
// verdict. It never authors a checklist itself and never writes an approval
// itself — it calls the roles' own writers (`authorChecklist`, `writeApproval`)
// so the structural rule (each role owns exactly one artifact) is preserved even
// in the coordinator. The only artifact this coordinator writes directly is the
// operator-facing halt report, which belongs to neither role.
//
// Routing (per class, PRD Stage 3.6):
//   - All 3 YES              → freeze the checklist, write approval{approved:true}.
//   - Any NO (attempt 1)     → hand the Reviewer's NO answers to the Author as
//                              feedback for ONE rewrite; re-review.
//   - Any NO (attempt 2)     → halt: write approval{approved:false}, dump both
//                              Author attempts + both Reviewer verdicts to
//                              `halted/checklist-rejection.md`, surface to operator.

import { promises as fs } from "node:fs";
import path from "node:path";
import type { Scope } from "../scope.ts";
import type { Event } from "../state.ts";
import {
  runAuthor,
  authorChecklist,
  readChecklist,
  type AuthorRunner,
  type FindingMeta,
  type ReconSummary,
} from "./author.ts";
import {
  reviewChecklist,
  writeApproval,
  feedbackFrom,
  type ReviewerRunner,
  type ReviewAnswers,
} from "./reviewer.ts";

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

export interface ClassReviewResult {
  class: string;
  approved: boolean;
  /** How many Author attempts it took (1, or 2 when a retry happened). */
  attempts: number;
  /** The verdict that decided this class (attempt-`attempts` answers). */
  answers: ReviewAnswers;
  /** The attempt-1 verdict, present only when a retry was triggered. */
  firstAnswers?: ReviewAnswers;
}

export interface ChecklistStageOutcome {
  authored: string[];
  reviews: ClassReviewResult[];
  halted: boolean;
  haltReason?: string;
  /** Path to `halted/checklist-rejection.md` when the stage halted. */
  rejectionReport?: string;
  /**
   * The transition to apply at the review→next boundary: `advance`
   * (review → verify) on full approval, or `halt` on a second-attempt rejection.
   * The author→review advance is applied first by the caller unconditionally.
   */
  event: Event;
}

// ---------------------------------------------------------------------------
// Halt report (operator-facing; belongs to neither role)
// ---------------------------------------------------------------------------

export function haltedDir(workdir: string): string {
  return path.join(workdir, "halted");
}

export function rejectionReportPath(workdir: string): string {
  return path.join(haltedDir(workdir), "checklist-rejection.md");
}

function answerLine(label: string, value: boolean): string {
  return `- ${label}: ${value ? "YES" : "NO"}`;
}

function renderVerdict(title: string, a: ReviewAnswers): string {
  return [
    `### ${title}`,
    answerLine("Q1 excludes program-documented exclusions", a.excludes_documented_exclusions),
    answerLine("Q2 distinguishes real bug from public-by-design", a.distinguishes_public_by_design),
    answerLine("Q3 has a non-trivial impact gate", a.has_impact_gate),
    ...(a.notes.trim() ? ["", `Notes: ${a.notes.trim()}`] : []),
  ].join("\n");
}

/**
 * Write the single operator-facing rejection artifact: both Author attempts and
 * both Reviewer verdicts for the class that could not pass review, so the human
 * can see exactly what was tried and why it was rejected twice.
 */
export async function writeRejectionReport(
  workdir: string,
  info: {
    vuln_class: string;
    attempt1Checklist: string;
    attempt2Checklist: string;
    review1: ReviewAnswers;
    review2: ReviewAnswers;
  },
): Promise<string> {
  const md = [
    `# Checklist rejected — engagement halted`,
    "",
    `The Checklist Reviewer rejected the \`${info.vuln_class}\` checklist twice`,
    `(initial author pass + one rewrite). The engagement is halted for operator`,
    `review — no verify loop runs against an unapproved checklist.`,
    "",
    "---",
    "",
    `## Attempt 1 — Author`,
    "",
    "```markdown",
    info.attempt1Checklist.trimEnd(),
    "```",
    "",
    renderVerdict("Attempt 1 — Reviewer verdict (rejected)", info.review1),
    "",
    "---",
    "",
    `## Attempt 2 — Author (rewrite with Reviewer feedback)`,
    "",
    "```markdown",
    info.attempt2Checklist.trimEnd(),
    "```",
    "",
    renderVerdict("Attempt 2 — Reviewer verdict (rejected)", info.review2),
    "",
  ].join("\n");

  await fs.mkdir(haltedDir(workdir), { recursive: true });
  const file = rejectionReportPath(workdir);
  await fs.writeFile(file, md, "utf8");
  return file;
}

// ---------------------------------------------------------------------------
// The stage
// ---------------------------------------------------------------------------

export interface RunChecklistStageOptions {
  authorRunner: AuthorRunner;
  reviewerRunner: ReviewerRunner;
  scope: Scope;
}

/**
 * Review one class through the approve-or-halt path with its single retry.
 * Returns the per-class result plus (on a double rejection) the report inputs.
 */
async function reviewOneClass(
  workdir: string,
  vulnClass: string,
  sample: FindingMeta[],
  recon: ReconSummary,
  opts: RunChecklistStageOptions,
): Promise<{
  result: ClassReviewResult;
  halt?: { attempt1Checklist: string; attempt2Checklist: string; review1: ReviewAnswers; review2: ReviewAnswers };
}> {
  // Attempt 1 — the checklist the Author already wrote in runAuthor().
  const attempt1Checklist = await readChecklist(workdir, vulnClass);
  const first = await reviewChecklist(vulnClass, {
    runner: opts.reviewerRunner,
    scope: opts.scope,
    checklist: attempt1Checklist,
    findings: sample,
  });

  if (first.approved) {
    await writeApproval(workdir, {
      class: vulnClass,
      approved: true,
      attempt: 1,
      answers: first.answers,
    });
    return {
      result: { class: vulnClass, approved: true, attempts: 1, answers: first.answers },
    };
  }

  // Attempt 2 — ONE rewrite, handing the Reviewer's NO answers back to the Author.
  const attempt2Checklist = await authorChecklist(workdir, vulnClass, {
    runner: opts.authorRunner,
    scope: opts.scope,
    findings: sample,
    recon,
    feedback: feedbackFrom(first.answers),
  });
  const second = await reviewChecklist(vulnClass, {
    runner: opts.reviewerRunner,
    scope: opts.scope,
    checklist: attempt2Checklist,
    findings: sample,
  });

  if (second.approved) {
    await writeApproval(workdir, {
      class: vulnClass,
      approved: true,
      attempt: 2,
      answers: second.answers,
    });
    return {
      result: {
        class: vulnClass,
        approved: true,
        attempts: 2,
        answers: second.answers,
        firstAnswers: first.answers,
      },
    };
  }

  // Second-attempt failure → halt. The Reviewer records approved:false; the
  // coordinator dumps the operator report.
  await writeApproval(workdir, {
    class: vulnClass,
    approved: false,
    attempt: 2,
    answers: second.answers,
  });
  return {
    result: {
      class: vulnClass,
      approved: false,
      attempts: 2,
      answers: second.answers,
      firstAnswers: first.answers,
    },
    halt: { attempt1Checklist, attempt2Checklist, review1: first.answers, review2: second.answers },
  };
}

/**
 * Run Stages 3.5 + 3.6. The Author writes a checklist for every class with a
 * Tier 1 candidate; the Reviewer approves-or-halts each, with one Author rewrite
 * on a first rejection. On any second-attempt rejection the whole engagement
 * halts (a single bad checklist must not let the verify loop validate noise).
 *
 * The returned `event` is applied at the review→next boundary; the caller
 * applies the author→review advance first. On full approval `event` is
 * `advance` (review → verify); on halt it is `halt`.
 */
export async function runChecklistStage(
  workdir: string,
  opts: RunChecklistStageOptions,
): Promise<ChecklistStageOutcome> {
  const author = await runAuthor(workdir, {
    runner: opts.authorRunner,
    scope: opts.scope,
  });

  const reviews: ClassReviewResult[] = [];
  for (const vulnClass of author.authored) {
    const { result, halt } = await reviewOneClass(
      workdir,
      vulnClass,
      author.samples[vulnClass] ?? [],
      author.recon,
      opts,
    );
    reviews.push(result);
    if (halt) {
      const rejectionReport = await writeRejectionReport(workdir, {
        vuln_class: vulnClass,
        ...halt,
      });
      return {
        authored: author.authored,
        reviews,
        halted: true,
        haltReason: `checklist for "${vulnClass}" rejected after retry`,
        rejectionReport,
        event: { type: "halt", reason: `checklist "${vulnClass}" rejected after retry` },
      };
    }
  }

  return {
    authored: author.authored,
    reviews,
    halted: false,
    event: { type: "advance" },
  };
}
