// Stage 4 — the Verifier (the third of v2's separated LLM roles).
//
// The Verifier is STATELESS: given one finding's `(finding_id, frozen checklist,
// poc re-fire output, evidence files)`, it applies the checklist and emits
// exactly one of eight structured verdicts. It reasons; it does not act — the
// orchestrator (stage.ts) routes on the verdict.
//
// STRUCTURAL RULE: the Verifier CANNOT edit the checklist. This module reads the
// frozen `checklists/<class>.md` through the shared path helper (a reader), and
// references none of the checklist/finding writers — a source-level test greps
// this file to prove those writer symbols never appear here. The checklist that
// gates the verify loop is frozen at Stage 3.6 approval; the role that verifies
// against it cannot rewrite it. This is the same "no role edits another role's
// output" guard the Author/Reviewer split enforces.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { findingDir, findingsDir } from "../hunters/framework.ts";
import { checklistPath } from "../checklist/paths.ts";
import { FindingMetaSchema, type FindingMeta } from "../checklist/author.ts";
import { type PocExecutor, type PocRefireOutput, refirePoc } from "./refire.ts";

// ---------------------------------------------------------------------------
// The eight verdicts + the verdict schema
// ---------------------------------------------------------------------------

/** The eight verdicts the Verifier can emit — exhaustive and closed. */
export const VERDICTS = [
  "confirmed",
  "repro_failed",
  "weak_evidence",
  "out_of_scope",
  "duplicate",
  "severity_mismatch",
  "non_deterministic",
  "rate_limited",
] as const;
export type VerdictKind = (typeof VERDICTS)[number];

/** The two re-queue routes a re-queue verdict can request. */
export const NEXT_STEPS = ["surgical", "promote_to_tier2"] as const;
export type NextStep = (typeof NEXT_STEPS)[number];

/**
 * The Verifier's single structured output. `reason` is a short failure-bullet
 * name; `mutation_hint` is an expansion seed for the next iteration; `next_step`
 * is present only on the re-queue verdicts (`repro_failed` / `weak_evidence`).
 */
export const VerdictSchema = z.object({
  finding_id: z.string().min(1),
  verdict: z.enum(VERDICTS),
  reason: z.string().min(1),
  mutation_hint: z.string().optional(),
  next_step: z.enum(NEXT_STEPS).optional(),
});
export type Verdict = z.infer<typeof VerdictSchema>;

// ---------------------------------------------------------------------------
// Verdict persistence
// ---------------------------------------------------------------------------

export function verdictsDir(workdir: string): string {
  return path.join(workdir, "verdicts");
}

/** `verdicts/<finding_id>.json` — the latest verdict for a finding. */
export function verdictPath(workdir: string, findingId: string): string {
  return path.join(verdictsDir(workdir), `${findingId}.json`);
}

/** `verdicts/pass-N.json` — the confirmed findings promoted in pass N. */
export function passVerdictPath(workdir: string, pass: number): string {
  return path.join(verdictsDir(workdir), `pass-${pass}.json`);
}

/** Persist a single verdict to `verdicts/<finding_id>.json`. */
export async function writeVerdict(
  workdir: string,
  verdict: Verdict,
): Promise<string> {
  const validated = VerdictSchema.parse(verdict);
  await fs.mkdir(verdictsDir(workdir), { recursive: true });
  const file = verdictPath(workdir, validated.finding_id);
  await fs.writeFile(file, JSON.stringify(validated, null, 2) + "\n", "utf8");
  return file;
}

export async function readVerdict(
  workdir: string,
  findingId: string,
): Promise<Verdict> {
  const raw = await fs.readFile(verdictPath(workdir, findingId), "utf8");
  return VerdictSchema.parse(JSON.parse(raw));
}

/** Persist pass N's promoted (confirmed) verdicts to `verdicts/pass-N.json`. */
export async function writePassVerdicts(
  workdir: string,
  pass: number,
  verdicts: Verdict[],
): Promise<string> {
  await fs.mkdir(verdictsDir(workdir), { recursive: true });
  const file = passVerdictPath(workdir, pass);
  await fs.writeFile(
    file,
    JSON.stringify({ pass, verdicts: verdicts.map((v) => VerdictSchema.parse(v)) }, null, 2) + "\n",
    "utf8",
  );
  return file;
}

// ---------------------------------------------------------------------------
// Reading the inputs the Verifier reasons over
// ---------------------------------------------------------------------------

/** Read one `findings/<id>/finding.json`. Throws a clear error if absent. */
export async function readFindingMeta(
  workdir: string,
  findingId: string,
): Promise<FindingMeta> {
  const file = path.join(findingsDir(workdir), findingId, "finding.json");
  try {
    return FindingMetaSchema.parse(JSON.parse(await fs.readFile(file, "utf8")));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`No finding.json for "${findingId}" (looked in ${file})`);
    }
    throw err;
  }
}

/**
 * Read the FROZEN checklist for a class — the one Stage 3.6 approved. Read-only:
 * the Verifier applies it, it never rewrites it. A missing checklist yields ""
 * (a class can reach verify without one only when it had no candidate at 3.5).
 */
export async function readFrozenChecklist(
  workdir: string,
  vulnClass: string,
): Promise<string> {
  try {
    return await fs.readFile(checklistPath(workdir, vulnClass), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw err;
  }
}

/** Read a finding's `evidence/<name>` files into a `{ name: contents }` map. */
export async function readEvidence(
  workdir: string,
  findingId: string,
): Promise<Record<string, string>> {
  const evDir = path.join(findingDir(workdir, findingId), "evidence");
  let names: string[] = [];
  try {
    names = await fs.readdir(evDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw err;
  }
  const out: Record<string, string> = {};
  for (const name of names.sort()) {
    out[name] = await fs.readFile(path.join(evDir, name), "utf8");
  }
  return out;
}

// ---------------------------------------------------------------------------
// The Verifier agent seam
// ---------------------------------------------------------------------------

/** Everything the Verifier reads to verify one finding. */
export interface VerifierInput {
  finding_id: string;
  vuln_class: string;
  /** The frozen checklist markdown, verbatim (read-only). */
  checklist: string;
  /** The fresh PoC re-fire output diffed against the captured response. */
  refire: PocRefireOutput;
  /** The finding's `evidence/<name>` files. */
  evidence: Record<string, string>;
}

/** Injected agent implementation (Sonnet, `level: 'standard'`): apply the
 *  checklist, return exactly one verdict. */
export type VerifierRunner = (input: VerifierInput) => Promise<Verdict>;

export interface VerifyFindingOptions {
  runner: VerifierRunner;
  /** The PoC re-fire executor (defaults to spawning `bash poc.sh`). */
  execute: PocExecutor;
}

/**
 * Verify one finding: re-fire its PoC, read the frozen checklist + evidence, ask
 * the Verifier for a verdict, and validate it. The returned verdict's
 * `finding_id` MUST match the finding under test — a Verifier that answers about
 * the wrong finding is a bug, not a verdict, so it throws rather than routing.
 */
export async function verifyFinding(
  workdir: string,
  findingId: string,
  opts: VerifyFindingOptions,
): Promise<{ verdict: Verdict; refire: PocRefireOutput }> {
  const meta = await readFindingMeta(workdir, findingId);
  const checklist = await readFrozenChecklist(workdir, meta.vuln_class);
  const refire = await refirePoc(workdir, findingId, { execute: opts.execute });
  const evidence = await readEvidence(workdir, findingId);

  const verdict = VerdictSchema.parse(
    await opts.runner({
      finding_id: findingId,
      vuln_class: meta.vuln_class,
      checklist,
      refire,
      evidence,
    }),
  );
  if (verdict.finding_id !== findingId) {
    throw new Error(
      `Verifier verdict finding_id "${verdict.finding_id}" != finding under test "${findingId}"`,
    );
  }
  return { verdict, refire };
}
