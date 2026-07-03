// Resume + status — the operator-facing stage-gate surface (PRD user stories 32,
// 33) and the third named testing seam (the stage gate).
//
// `bbh resume <id>` reads `state.json`, validates that the artifacts on disk
// match the claimed stage, and resumes from the in-flight stage. Re-running an
// in-flight stage is safe because the ledger dedupe (hunters/ledger.ts) refuses
// a repeat probe — resume never double-fires at the target.
//
// The validation is split into a pure decision (`validateResume`, table-driven
// over an artifact snapshot) and a disk reader (`collectArtifacts`). The stage
// gate is: every stage STRICTLY BEFORE the claimed in-flight stage must have
// produced its primary artifact; a missing one means the state is inconsistent
// and resume surfaces it rather than silently re-running from a corrupt point.

import { promises as fs } from "node:fs";
import path from "node:path";
import { authArtifactPath } from "./auth.ts";
import { reconDir } from "./recon.ts";
import { huntPlanPath } from "./plan.ts";
import { coveragePath } from "./hunters/coverage.ts";
import { findingsDir } from "./hunters/framework.ts";
import { checklistsDir } from "./checklist/paths.ts";
import { verdictsDir } from "./verify/verifier.ts";
import { readHypotheses } from "./tier2/queue.ts";
import { reportPath } from "./report/report.ts";
import { countProbes } from "./budget.ts";
import { STAGES, type Stage, type State } from "./state.ts";
import type { Budget } from "./scope.ts";

// ---------------------------------------------------------------------------
// Artifact snapshot
// ---------------------------------------------------------------------------

/** What each stage left on disk — the input to the pure resume decision. */
export interface ArtifactSnapshot {
  hasAuthState: boolean;
  hasReconEndpoints: boolean;
  hasReconSurfaces: boolean;
  hasHuntPlan: boolean;
  hasCoverage: boolean;
  findingsCount: number;
  checklistCount: number;
  approvalCount: number;
  verdictPasses: number;
  hasReport: boolean;
}

async function exists(p: string): Promise<boolean> {
  try {
    await fs.stat(p);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw err;
  }
}

/** Count directory entries matching a predicate; a missing dir yields 0. */
async function countEntries(
  dir: string,
  match: (name: string) => boolean,
): Promise<number> {
  try {
    return (await fs.readdir(dir)).filter(match).length;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw err;
  }
}

/** Read the on-disk artifact snapshot for an engagement workdir. */
export async function collectArtifacts(
  workdir: string,
): Promise<ArtifactSnapshot> {
  const reconD = reconDir(workdir);
  return {
    hasAuthState: await exists(authArtifactPath(workdir)),
    hasReconEndpoints: await exists(path.join(reconD, "endpoints.json")),
    hasReconSurfaces: await exists(path.join(reconD, "surfaces.json")),
    hasHuntPlan: await exists(huntPlanPath(workdir)),
    hasCoverage: await exists(coveragePath(workdir)),
    findingsCount: await countEntries(findingsDir(workdir), (n) => /^f-\d+$/.test(n)),
    checklistCount: await countEntries(
      checklistsDir(workdir),
      (n) => n.endsWith(".md"),
    ),
    approvalCount: await countEntries(
      checklistsDir(workdir),
      (n) => n.endsWith(".approval.json"),
    ),
    verdictPasses: await countEntries(verdictsDir(workdir), (n) =>
      /^pass-\d+\.json$/.test(n),
    ),
    hasReport: await exists(reportPath(workdir)),
  };
}

// ---------------------------------------------------------------------------
// The per-stage artifact gate (pure)
// ---------------------------------------------------------------------------

/** A stage's completion check: is its primary artifact present in the snapshot? */
interface StageGate {
  artifact: string;
  present: (snap: ArtifactSnapshot) => boolean;
}

/**
 * The artifact each stage produces when it COMPLETES. A stage is only validated
 * when a LATER stage is claimed in-flight (i.e. this stage should already be
 * done). `author`/`review` are conditional: a sweep that produced zero candidate
 * findings authors no checklist, so their gate is satisfied by "no candidates".
 * `done`/`halted` are terminal — never a prior stage — so they carry no gate.
 */
const STAGE_GATES: Record<Stage, StageGate | null> = {
  auth: { artifact: "auth/state.json", present: (s) => s.hasAuthState },
  recon: {
    artifact: "recon/endpoints.json",
    present: (s) => s.hasReconEndpoints && s.hasReconSurfaces,
  },
  plan: { artifact: "hunt-plan.json", present: (s) => s.hasHuntPlan },
  sweep: { artifact: "coverage.json", present: (s) => s.hasCoverage },
  author: {
    artifact: "checklists/<class>.md",
    present: (s) => s.checklistCount > 0 || s.findingsCount === 0,
  },
  review: {
    artifact: "checklists/<class>.approval.json",
    present: (s) => s.approvalCount > 0 || s.checklistCount === 0,
  },
  verify: {
    artifact: "verdicts/pass-N.json",
    present: (s) => s.verdictPasses > 0,
  },
  report: { artifact: "report.md", present: (s) => s.hasReport },
  done: null,
  halted: null,
};

/** Pipeline order (linear stages only — `halted` is off the line). */
const PIPELINE: Stage[] = STAGES.filter((s) => s !== "halted");

export interface MissingArtifact {
  stage: Stage;
  artifact: string;
}

export interface ResumePlan {
  /** The stage to resume execution from (the claimed in-flight stage). */
  resumeStage: Stage;
  /** True when every prior stage's artifact is present (a clean resume). */
  ok: boolean;
  /** Prior-stage artifacts that are missing (an inconsistent state). */
  missing: MissingArtifact[];
  /** True when the engagement is already terminal (done/halted) — nothing to do. */
  terminal: boolean;
}

/**
 * Validate a resume against an artifact snapshot. Resume re-enters at
 * `state.current_stage`; every stage strictly before it must have left its
 * artifact on disk. Missing artifacts do not block the returned `resumeStage`
 * (the operator can force it) but flip `ok` to false and are itemised so the
 * caller can warn about an inconsistent state. A terminal state resumes to
 * itself with nothing to run.
 */
export function validateResume(
  state: State,
  snap: ArtifactSnapshot,
): ResumePlan {
  const resumeStage = state.current_stage;
  const terminal = resumeStage === "done" || resumeStage === "halted";
  if (terminal) {
    return { resumeStage, ok: true, missing: [], terminal: true };
  }

  const idx = PIPELINE.indexOf(resumeStage);
  const missing: MissingArtifact[] = [];
  for (let i = 0; i < idx; i += 1) {
    const stage = PIPELINE[i]!;
    const gate = STAGE_GATES[stage];
    if (gate && !gate.present(snap)) {
      missing.push({ stage, artifact: gate.artifact });
    }
  }
  return { resumeStage, ok: missing.length === 0, missing, terminal: false };
}

/** Read state + artifacts and validate the resume in one call. */
export async function planResume(workdir: string, state: State): Promise<ResumePlan> {
  return validateResume(state, await collectArtifacts(workdir));
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

export interface EngagementStatus {
  engagement_id: string;
  target: string;
  stage: Stage;
  pass: number;
  status: State["status"];
  findings_count: number;
  confirmed_passes: number;
  hypothesis_queue_depth: number;
  budget: {
    probes: number;
    max_probes: number;
    max_llm_calls: number;
    max_minutes: number;
  };
}

/**
 * Gather a real engagement status from `state.json` + the artifacts on disk:
 * current stage, pass, findings count, hypothesis queue depth, and probe budget
 * usage. LLM-call and wall-clock usage are process-local (not persisted), so the
 * status shows the probe count — the one usage figure recoverable from disk.
 */
export async function collectStatus(
  workdir: string,
  state: State,
  budget: Budget,
): Promise<EngagementStatus> {
  const snap = await collectArtifacts(workdir);
  const hyps = await readHypotheses(workdir).catch(() => []);
  const probes = await countProbes(workdir);
  return {
    engagement_id: state.engagement_id,
    target: state.target,
    stage: state.current_stage,
    pass: state.current_pass,
    status: state.status,
    findings_count: snap.findingsCount,
    confirmed_passes: snap.verdictPasses,
    hypothesis_queue_depth: hyps.length,
    budget: {
      probes,
      max_probes: budget.max_probes,
      max_llm_calls: budget.max_llm_calls,
      max_minutes: budget.max_minutes,
    },
  };
}

/** Render an engagement status as an operator-facing multi-line string. */
export function formatStatus(s: EngagementStatus): string {
  return [
    `engagement:  ${s.engagement_id}`,
    `target:      ${s.target}`,
    `stage:       ${s.stage}  (pass ${s.pass})`,
    `status:      ${s.status}`,
    `findings:    ${s.findings_count} candidate(s), ${s.confirmed_passes} verify pass(es)`,
    `hypotheses:  ${s.hypothesis_queue_depth} queued`,
    `budget:      ${s.budget.probes}/${s.budget.max_probes} probes ` +
      `(caps: ${s.budget.max_llm_calls} LLM calls, ${s.budget.max_minutes} min)`,
  ].join("\n");
}
