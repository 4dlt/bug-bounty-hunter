// Stage 3.5 — Checklist Author (the first of v2's three separated LLM roles).
//
// The Author reads the recon map, a representative sample of the Tier 1
// candidate findings, and the program rules from scope.yaml, and writes ONE
// engagement-specific verification checklist per vuln class that produced at
// least one candidate — `checklists/<class>.md`. Checklists are authored from
// observed evidence AFTER the first sweep, not pre-baked, so the IDOR marker on
// this target ("email" vs "transactionHistory" vs "ssn") reflects reality.
//
// STRUCTURAL RULE (the guard against v3's "LLM grades own work" trap): the
// Author writes checklists and NOTHING ELSE. This module must NEVER write an
// `approval.json` (that is the Reviewer's writer, in reviewer.ts) and must NEVER
// import the Reviewer. The two roles live in separate modules with no shared
// mutable state so neither can edit the other's output. See PRD "Three
// separated roles".

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { Scope } from "../scope.ts";
import {
  EndpointsFileSchema,
  SurfacesFileSchema,
  reconDir,
  type MergedEndpoint,
  type Surface,
} from "../recon.ts";
import { findingsDir } from "../hunters/framework.ts";
import { checklistsDir, checklistPath } from "./paths.ts";

// Path helpers are re-exported so existing importers keep working; they live in
// paths.ts so the Reviewer can find the same directory without importing this
// (the Author's) module. See the structural rule below.
export { checklistsDir, checklistPath } from "./paths.ts";

// ---------------------------------------------------------------------------
// Sample sizes
// ---------------------------------------------------------------------------

/** Max candidate findings per class handed to the Author as a sample. */
export const AUTHOR_SAMPLE = 5;

// ---------------------------------------------------------------------------
// Candidate finding metadata (read back from findings/<id>/finding.json)
// ---------------------------------------------------------------------------

/** The subset of a written finding the Author + Reviewer read to author/review
 *  a checklist. Mirrors what `writeFinding` persists to `finding.json`. */
export const FindingMetaSchema = z.object({
  id: z.string().min(1),
  title: z.string().min(1),
  severity: z.string().default("unknown"),
  vuln_class: z.string().min(1),
  endpoint: z.string().min(1),
  method: z.string().default("GET"),
  notes: z.string().optional(),
});
export type FindingMeta = z.infer<typeof FindingMetaSchema>;

/**
 * Read every `findings/<id>/finding.json`, skipping any that is missing or
 * unparseable (a half-written finding dir cannot crash the Author). Returns the
 * validated metadata, sorted by id so the sample is deterministic.
 */
export async function readFindings(workdir: string): Promise<FindingMeta[]> {
  let entries: string[] = [];
  try {
    entries = await fs.readdir(findingsDir(workdir));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: FindingMeta[] = [];
  for (const id of entries.sort()) {
    const file = path.join(findingsDir(workdir), id, "finding.json");
    let raw: string;
    try {
      raw = await fs.readFile(file, "utf8");
    } catch {
      continue; // not a finding dir, or no metadata yet
    }
    const parsed = FindingMetaSchema.safeParse(JSON.parse(raw));
    if (parsed.success) out.push(parsed.data);
  }
  return out;
}

/** Group findings by their vuln class, preserving the (sorted) id order. */
export function groupFindingsByClass(
  findings: FindingMeta[],
): Map<string, FindingMeta[]> {
  const byClass = new Map<string, FindingMeta[]>();
  for (const f of findings) {
    const list = byClass.get(f.vuln_class) ?? [];
    list.push(f);
    byClass.set(f.vuln_class, list);
  }
  return byClass;
}

// ---------------------------------------------------------------------------
// Recon summary (context the Author reads to specialise the checklist)
// ---------------------------------------------------------------------------

export interface ReconSummary {
  endpoints: MergedEndpoint[];
  surfaces: Surface[];
  tech: Record<string, unknown>;
}

/** Read recon's consolidated artifacts; a missing file yields the empty shape. */
export async function readReconSummary(workdir: string): Promise<ReconSummary> {
  const dir = reconDir(workdir);
  const readJson = async (file: string, fallback: unknown): Promise<unknown> => {
    try {
      return JSON.parse(await fs.readFile(path.join(dir, file), "utf8"));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return fallback;
      throw err;
    }
  };
  const endpoints = EndpointsFileSchema.parse(
    await readJson("endpoints.json", { endpoints: [] }),
  ).endpoints;
  const surfaces = SurfacesFileSchema.parse(
    await readJson("surfaces.json", { surfaces: [] }),
  ).surfaces;
  const tech = (await readJson("tech.json", {})) as Record<string, unknown>;
  return { endpoints, surfaces, tech };
}

// ---------------------------------------------------------------------------
// Checklist persistence
// ---------------------------------------------------------------------------

/** Write (or overwrite, on the one allowed retry) `checklists/<class>.md`. */
export async function writeChecklist(
  workdir: string,
  vulnClass: string,
  content: string,
): Promise<string> {
  const file = checklistPath(workdir, vulnClass);
  await fs.mkdir(checklistsDir(workdir), { recursive: true });
  const body = content.endsWith("\n") ? content : content + "\n";
  await fs.writeFile(file, body, "utf8");
  return file;
}

/** Read back a frozen/authored checklist. */
export async function readChecklist(
  workdir: string,
  vulnClass: string,
): Promise<string> {
  return fs.readFile(checklistPath(workdir, vulnClass), "utf8");
}

// ---------------------------------------------------------------------------
// The Author agent seam
// ---------------------------------------------------------------------------

/** Everything the Author agent reads to write one class's checklist. */
export interface AuthorInput {
  vuln_class: string;
  scope: Scope;
  /** Representative candidate findings for this class (capped at AUTHOR_SAMPLE). */
  findings: FindingMeta[];
  recon: ReconSummary;
  /**
   * On the one allowed retry (attempt 2), the Reviewer's specific NO answers,
   * handed back verbatim so the Author can address exactly what failed. Absent
   * on the first attempt.
   */
  feedback?: string[];
}

/** Injected agent implementation (Opus, `level: 'smart'`): read the evidence,
 *  return the checklist markdown. The orchestrator owns file writes. */
export type AuthorRunner = (input: AuthorInput) => Promise<string>;

export interface AuthorChecklistOptions {
  runner: AuthorRunner;
  scope: Scope;
  findings: FindingMeta[];
  recon: ReconSummary;
  feedback?: string[];
}

/**
 * Author one class's checklist and write it to `checklists/<class>.md`. Used
 * both for the initial pass and for the single rewrite the Reviewer can trigger
 * (pass the Reviewer's NO answers as `feedback`). Returns the markdown written.
 */
export async function authorChecklist(
  workdir: string,
  vulnClass: string,
  opts: AuthorChecklistOptions,
): Promise<string> {
  const content = await opts.runner({
    vuln_class: vulnClass,
    scope: opts.scope,
    findings: opts.findings.slice(0, AUTHOR_SAMPLE),
    recon: opts.recon,
    feedback: opts.feedback,
  });
  await writeChecklist(workdir, vulnClass, content);
  return content;
}

// ---------------------------------------------------------------------------
// Stage 3.5 — author every class with a candidate
// ---------------------------------------------------------------------------

export interface RunAuthorOptions {
  runner: AuthorRunner;
  scope: Scope;
}

export interface AuthorOutcome {
  /** Classes that got a `checklists/<class>.md` — exactly those with >=1 candidate. */
  authored: string[];
  /** The sample handed to the Author per class, reused downstream (Reviewer +
   *  the rewrite path) so the whole stage reads findings from disk only once. */
  samples: Record<string, FindingMeta[]>;
  recon: ReconSummary;
}

/**
 * Stage 3.5. Reads the Tier 1 candidate findings, and for each vuln class that
 * produced at least one candidate, asks the Author to write a checklist. A class
 * with zero candidates gets NO checklist (acceptance 1). Classes are processed
 * in sorted order so the artifacts are stable.
 */
export async function runAuthor(
  workdir: string,
  opts: RunAuthorOptions,
): Promise<AuthorOutcome> {
  const findings = await readFindings(workdir);
  const byClass = groupFindingsByClass(findings);
  const recon = await readReconSummary(workdir);

  const authored: string[] = [];
  const samples: Record<string, FindingMeta[]> = {};
  for (const vulnClass of [...byClass.keys()].sort()) {
    const sample = byClass.get(vulnClass)!.slice(0, AUTHOR_SAMPLE);
    samples[vulnClass] = sample;
    await authorChecklist(workdir, vulnClass, {
      runner: opts.runner,
      scope: opts.scope,
      findings: sample,
      recon,
    });
    authored.push(vulnClass);
  }
  return { authored, samples, recon };
}
