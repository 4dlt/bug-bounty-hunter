// Stage 2 — Plan.
//
// A single smart (Opus) LLM call reads the consolidated recon artifacts and
// emits the hunt plan: a (surface × vuln class) matrix telling the Tier 1
// hunters which classes to sweep on which surface, plus an initial a-priori
// list of hypotheses for Slice 6's deep-dive promotion.
//
//   - `hunt-plan.json`   — array of cells `{surface, vuln_class,
//     relevant_endpoints, priority, expected_payout_band}`. Classes that make
//     no sense on a surface (XSS on a pure JSON API, client-render classes on a
//     WebSocket) are dropped, and every recon surface is guaranteed at least one
//     assigned class so no part of the map goes un-swept.
//   - `hypotheses.jsonl` — append-only priority queue. Plan seeds the a-priori
//     entries (`source: "plan_apriori"`, `status: "queued"`); Tier 1 reactive
//     entries land in 3c and Verifier escalations in Slice 6. Entries below
//     `scope.yaml.min_payout_band` are filtered out before seeding.
//
// As with Stage 0 (auth) and Stage 1 (recon), the agent mechanics are injected
// as a `PlanRunner` seam so the filtering / coverage / seeding logic here is
// pure and unit-testable without a live LLM. The stage always advances
// `plan → sweep` once `hunt-plan.json` is built and validates.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { Scope } from "./scope.ts";
import type { Event } from "./state.ts";
import {
  EndpointsFileSchema,
  SurfacesFileSchema,
  reconDir,
  type MergedEndpoint,
  type Surface,
} from "./recon.ts";

// ---------------------------------------------------------------------------
// Payout bands
// ---------------------------------------------------------------------------

/** Severity / payout bands, most-severe first. P1 > P2 > P3 > P4. */
export const PAYOUT_BANDS = ["P1", "P2", "P3", "P4"] as const;
export const PayoutBandSchema = z.enum(PAYOUT_BANDS);
export type PayoutBand = z.infer<typeof PayoutBandSchema>;

/** 1-based rank; a higher number is a lower payout (P1 = 1 … P4 = 4). */
function bandRank(band: PayoutBand): number {
  return PAYOUT_BANDS.indexOf(band) + 1;
}

/**
 * Is `band` strictly below the engagement's `min_payout_band` floor? A null
 * band is unknown severity, not "below" — it is kept (a high-value a-priori
 * lead should still be seeded even before its payout is pinned). An unparseable
 * floor disables filtering rather than dropping everything.
 */
export function isBelowBand(band: PayoutBand | null, min: string): boolean {
  if (band === null) return false;
  const parsed = PayoutBandSchema.safeParse(min);
  if (!parsed.success) return false;
  return bandRank(band) > bandRank(parsed.data);
}

// ---------------------------------------------------------------------------
// Vuln classes + surface compatibility (pure)
// ---------------------------------------------------------------------------

/** The vuln classes the Tier 1 sweep understands. */
export const VULN_CLASSES = [
  "xss",
  "sqli",
  "idor",
  "ssrf",
  "csrf",
  "rce",
  "auth",
  "business_logic",
  "open_redirect",
  "info_disclosure",
  "xxe",
  "ssti",
  "path_traversal",
] as const;

type SurfaceKind = "json_api" | "websocket" | "oauth" | "web_ui" | "web_generic";

/**
 * Classify a named surface into a coarse kind that drives compatibility. Named
 * tags (api/rest/graphql/websocket/oauth/admin) are recognised; anything else —
 * notably a bare host surface like `api.target.com` — is `web_generic`, which
 * is treated permissively because we cannot know what it serves.
 */
function surfaceKind(name: string): SurfaceKind {
  const n = name.toLowerCase();
  if (n === "api" || n === "rest" || n === "graphql") return "json_api";
  if (n === "websocket") return "websocket";
  if (n === "oauth") return "oauth";
  if (n === "admin") return "web_ui";
  return "web_generic";
}

/** Classes that need an HTML rendering context to make sense. */
const CLIENT_RENDER_CLASSES = new Set(["xss", "clickjacking"]);

/**
 * Is `vulnClass` sensible to sweep on `surface`? The confident, code-enforced
 * rule the issue calls out: a client-render class (XSS) on a pure JSON API or a
 * raw WebSocket has no DOM to fire in — drop it. Broader surface-appropriateness
 * (e.g. SSRF on a static marketing site) is the planner's judgment, guided by
 * the prompt; the filter only removes the pairs we are certain about, so it can
 * never strip a surface of coverage it legitimately has.
 */
export function isCompatible(vulnClass: string, surface: string): boolean {
  const kind = surfaceKind(surface);
  if (
    (kind === "json_api" || kind === "websocket") &&
    CLIENT_RENDER_CLASSES.has(vulnClass.toLowerCase())
  ) {
    return false;
  }
  return true;
}

/** A broadly-applicable default class for a surface with no assigned cell. */
function defaultClassForSurface(name: string): string {
  switch (surfaceKind(name)) {
    case "web_ui":
      return "xss";
    case "oauth":
      return "auth";
    case "web_generic":
      return "info_disclosure";
    default:
      // json_api / websocket — IDOR is compatible and near-universal on APIs.
      return "idor";
  }
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const PrioritySchema = z.enum(["high", "medium", "low"]);
export type Priority = z.infer<typeof PrioritySchema>;

/**
 * One cell of the hunt plan: sweep `vuln_class` on `surface`. Doubles as the
 * agent-proposal schema (all fields but `surface`/`vuln_class` default) and the
 * validated output schema.
 */
export const HuntPlanCellSchema = z.object({
  surface: z.string().min(1),
  vuln_class: z.string().min(1),
  relevant_endpoints: z.array(z.string()).default([]),
  priority: PrioritySchema.default("medium"),
  expected_payout_band: PayoutBandSchema.nullable().default(null),
});
export type HuntPlanCell = z.infer<typeof HuntPlanCellSchema>;

export const HuntPlanFileSchema = z.object({
  cells: z.array(HuntPlanCellSchema),
});

export const HYPOTHESIS_SOURCES = [
  "plan_apriori",
  "tier1_reactive",
  "verifier_escalation",
] as const;

/** The fields the Plan agent supplies for an a-priori hypothesis. */
export const PlanHypothesisInputSchema = z.object({
  class: z.string().min(1),
  target_endpoint: z.string().min(1),
  hypothesis: z.string().min(1),
  signal_evidence: z.string().default(""),
  budget_hint: z.string().optional(),
  estimated_payout_band: PayoutBandSchema.nullable().default(null),
});
export type PlanHypothesisInput = z.infer<typeof PlanHypothesisInputSchema>;

/** A seeded row of `hypotheses.jsonl` (append-only priority queue). */
export const HypothesisSchema = z.object({
  id: z.string().min(1),
  source: z.enum(HYPOTHESIS_SOURCES),
  class: z.string().min(1),
  target_endpoint: z.string().min(1),
  hypothesis: z.string().min(1),
  signal_evidence: z.string().default(""),
  budget_hint: z.string().optional(),
  estimated_payout_band: PayoutBandSchema.nullable(),
  status: z.literal("queued"),
});
export type Hypothesis = z.infer<typeof HypothesisSchema>;

// ---------------------------------------------------------------------------
// Building the hunt plan (pure)
// ---------------------------------------------------------------------------

/** Bare hostname from a URL, or null for a relative/opaque path. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Endpoints belonging to a surface: tagged with it, or hosted under it. */
export function relevantEndpointsFor(
  surface: string,
  endpoints: MergedEndpoint[],
): string[] {
  const urls = new Set<string>();
  for (const ep of endpoints) {
    if (ep.surface_tags.includes(surface) || hostOf(ep.url) === surface) {
      urls.add(ep.url);
    }
  }
  return [...urls].sort();
}

/**
 * Turn the agent's proposed cells into the validated hunt plan. Incompatible
 * (surface, class) pairs are dropped; then every surface from recon is
 * guaranteed at least one cell — a surface the planner left uncovered gets a
 * default compatible class so no part of the attack surface goes un-swept.
 * Cells are sorted (surface, class) so the artifact is stable across runs.
 */
export function buildHuntPlan(
  proposed: HuntPlanCell[],
  surfaces: Surface[],
  endpoints: MergedEndpoint[],
): { cells: HuntPlanCell[]; droppedCells: number } {
  const kept = proposed.filter((c) => isCompatible(c.vuln_class, c.surface));
  const droppedCells = proposed.length - kept.length;

  const covered = new Set(kept.map((c) => c.surface));
  for (const surface of surfaces) {
    if (covered.has(surface.name)) continue;
    kept.push(
      HuntPlanCellSchema.parse({
        surface: surface.name,
        vuln_class: defaultClassForSurface(surface.name),
        relevant_endpoints: relevantEndpointsFor(surface.name, endpoints),
        priority: "low",
      }),
    );
    covered.add(surface.name);
  }

  kept.sort(
    (a, b) =>
      a.surface.localeCompare(b.surface) ||
      a.vuln_class.localeCompare(b.vuln_class),
  );
  return { cells: kept, droppedCells };
}

/**
 * Stamp the agent's a-priori inputs into seeded hypotheses, filtering out any
 * whose estimated payout is below the engagement floor. Ids are index-derived
 * (`h-plan-0001`, …) so the output is deterministic (no clock/random).
 */
export function seedHypotheses(
  inputs: PlanHypothesisInput[],
  minPayoutBand: string,
): { hypotheses: Hypothesis[]; droppedHypotheses: number } {
  const hypotheses: Hypothesis[] = [];
  let seq = 0;
  let dropped = 0;
  for (const input of inputs) {
    if (isBelowBand(input.estimated_payout_band, minPayoutBand)) {
      dropped += 1;
      continue;
    }
    seq += 1;
    hypotheses.push(
      HypothesisSchema.parse({
        ...input,
        id: `h-plan-${String(seq).padStart(4, "0")}`,
        source: "plan_apriori",
        status: "queued",
      }),
    );
  }
  return { hypotheses, droppedHypotheses: dropped };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function huntPlanPath(workdir: string): string {
  return path.join(workdir, "hunt-plan.json");
}

export function hypothesesPath(workdir: string): string {
  return path.join(workdir, "hypotheses.jsonl");
}

export async function writeHuntPlan(
  workdir: string,
  cells: HuntPlanCell[],
): Promise<void> {
  const validated = HuntPlanFileSchema.parse({ cells });
  await fs.mkdir(workdir, { recursive: true });
  await fs.writeFile(
    huntPlanPath(workdir),
    JSON.stringify(validated, null, 2) + "\n",
    "utf8",
  );
}

export async function readHuntPlan(workdir: string): Promise<HuntPlanCell[]> {
  const raw = await fs.readFile(huntPlanPath(workdir), "utf8");
  return HuntPlanFileSchema.parse(JSON.parse(raw)).cells;
}

/** Append seeded hypotheses to the append-only `hypotheses.jsonl`. */
export async function appendHypotheses(
  workdir: string,
  hypotheses: Hypothesis[],
): Promise<void> {
  if (hypotheses.length === 0) return;
  await fs.mkdir(workdir, { recursive: true });
  const lines = hypotheses.map((h) => JSON.stringify(h)).join("\n") + "\n";
  await fs.appendFile(hypothesesPath(workdir), lines, "utf8");
}

/** Read recon's consolidated artifacts; a missing file yields the empty shape. */
async function readReconArtifacts(workdir: string): Promise<{
  endpoints: MergedEndpoint[];
  surfaces: Surface[];
  tech: Record<string, unknown>;
}> {
  const dir = reconDir(workdir);
  const readJson = async <T>(file: string, fallback: T): Promise<unknown> => {
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
// Stage orchestration
// ---------------------------------------------------------------------------

/** Everything the Plan agent reads to author the plan. */
export interface PlanInput {
  scope: Scope;
  endpoints: MergedEndpoint[];
  surfaces: Surface[];
  tech: Record<string, unknown>;
}

/** What the Plan agent proposes: raw cells + raw a-priori hypotheses. */
export interface PlanProposal {
  cells: HuntPlanCell[];
  hypotheses: PlanHypothesisInput[];
}

/** Injected agent implementation: read the recon map, return a proposal. */
export type PlanRunner = (input: PlanInput) => Promise<PlanProposal>;

export interface RunPlanOptions {
  runner: PlanRunner;
  scope: Scope;
}

export interface PlanOutcome {
  /** Always `advance` (plan -> sweep): the plan is built from validated pieces. */
  event: Event;
  cells: HuntPlanCell[];
  hypotheses: Hypothesis[];
  droppedCells: number;
  droppedHypotheses: number;
}

/**
 * Run Stage 2. Reads recon's consolidated artifacts, asks the injected runner
 * for a proposal, filters incompatible cells + guarantees per-surface coverage,
 * seeds the payout-filtered a-priori hypotheses, writes `hunt-plan.json` +
 * appends `hypotheses.jsonl`, and returns the `advance` event (plan -> sweep).
 */
export async function runPlan(
  workdir: string,
  opts: RunPlanOptions,
): Promise<PlanOutcome> {
  const { endpoints, surfaces, tech } = await readReconArtifacts(workdir);

  const proposal = await opts.runner({
    scope: opts.scope,
    endpoints,
    surfaces,
    tech,
  });

  const proposedCells = proposal.cells.map((c) => HuntPlanCellSchema.parse(c));
  const proposedHyps = proposal.hypotheses.map((h) =>
    PlanHypothesisInputSchema.parse(h),
  );

  const { cells, droppedCells } = buildHuntPlan(
    proposedCells,
    surfaces,
    endpoints,
  );
  const { hypotheses, droppedHypotheses } = seedHypotheses(
    proposedHyps,
    opts.scope.min_payout_band,
  );

  await writeHuntPlan(workdir, cells);
  await appendHypotheses(workdir, hypotheses);

  return {
    event: { type: "advance" },
    cells,
    hypotheses,
    droppedCells,
    droppedHypotheses,
  };
}
