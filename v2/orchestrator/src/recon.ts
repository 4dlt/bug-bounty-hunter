// Stage 1 — parallel recon (R1 assets, R2 content, R3 fingerprint, R4 JS
// analysis).
//
// Four agents run concurrently, each mapping the attack surface a different
// way and writing its own `recon/rN.json` artifact incrementally (so a crash
// loses at most one agent's work). After all four settle, the orchestrator
// merges them into two consolidated artifacts the Plan stage consumes:
//   - `recon/endpoints.json`  — deduped endpoints, each tagged with the surfaces
//     it belongs to and the agents that discovered it.
//   - `recon/surfaces.json`   — named attack surfaces (api, rest, admin, oauth,
//     websocket, graphql, and each distinct host) with example endpoints.
//
// The agent mechanics (crawlers, port scans, JS extraction) are injected as a
// `ReconRunner`, exactly as Stage 0 injects `login`: the decision/merge logic
// here stays pure and unit-testable without a live target. Every real agent
// issues its outbound requests through `scopedFetch` (Slice 1) and consumes a
// rate-limit token from the governor (Slice 0) via the injected context, so no
// out-of-scope host is ever hit and the swarm respects the program's req/s.
//
// The stage is best-effort: a per-agent failure is logged as a `coverage_gap`
// and the remaining agents' results are still merged. Recon always advances to
// Plan (`recon` -> `plan`) — the map is as complete as the agents made it.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { CoverageGap, Scope } from "./scope.ts";
import type { Event } from "./state.ts";

export type { CoverageGap } from "./scope.ts";

// ---------------------------------------------------------------------------
// Agent identity
// ---------------------------------------------------------------------------

export const RECON_AGENTS = ["R1", "R2", "R3", "R4"] as const;
export const ReconAgentIdSchema = z.enum(RECON_AGENTS);
export type ReconAgentId = z.infer<typeof ReconAgentIdSchema>;

// ---------------------------------------------------------------------------
// Artifact schemas
// ---------------------------------------------------------------------------

/** An endpoint as emitted by a single agent (source is stamped on merge). */
export const RawEndpointSchema = z.object({
  url: z.string().min(1),
  method: z.string().default("GET"),
  // Agent-supplied hints; merge unions these with the derived tags.
  surface_tags: z.array(z.string()).default([]),
  notes: z.string().optional(),
});
export type RawEndpoint = z.infer<typeof RawEndpointSchema>;

/** Per-agent output artifact: `recon/r1.json` … `recon/r4.json`. */
export const ReconResultSchema = z.object({
  agent: ReconAgentIdSchema,
  endpoints: z.array(RawEndpointSchema).default([]),
  // R3 (fingerprint) fills this; other agents leave it empty. Written verbatim
  // to `recon/tech.json` on merge (issue: R3 writes tech.json).
  tech: z.record(z.string(), z.unknown()).default({}),
  notes: z.array(z.string()).default([]),
});
export type ReconResult = z.infer<typeof ReconResultSchema>;

/** A consolidated endpoint in `recon/endpoints.json`. */
export const MergedEndpointSchema = z.object({
  url: z.string().min(1),
  method: z.string(),
  // Every agent that discovered this (endpoint, method). A URL found only by R4
  // and not R2 carries `sources: ["R4"]` — the JS-extraction value made visible.
  sources: z.array(ReconAgentIdSchema).min(1),
  surface_tags: z.array(z.string()),
  notes: z.string().optional(),
});
export type MergedEndpoint = z.infer<typeof MergedEndpointSchema>;

export const EndpointsFileSchema = z.object({
  endpoints: z.array(MergedEndpointSchema),
});

/** A named attack surface in `recon/surfaces.json`. */
export const SurfaceSchema = z.object({
  name: z.string().min(1),
  count: z.number().int().nonnegative(),
  examples: z.array(z.string()),
});
export type Surface = z.infer<typeof SurfaceSchema>;

export const SurfacesFileSchema = z.object({
  surfaces: z.array(SurfaceSchema),
});

// ---------------------------------------------------------------------------
// Surface tagging (pure)
// ---------------------------------------------------------------------------

/** Bare hostname from a URL, or null for a relative/opaque path. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

/** Lowercased path component of a URL, or the whole string if it is relative. */
function pathOf(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return url.toLowerCase();
  }
}

/**
 * Classify an endpoint into zero or more named attack surfaces. Pure and
 * deterministic. Recognizes the surfaces the issue calls out explicitly —
 * `/api/*`, `/rest/*`, WebSocket, OAuth, admin, GraphQL — which are exactly the
 * ones Juice Shop exposes.
 */
export function surfaceTagsFor(url: string): string[] {
  const tags = new Set<string>();
  const lower = url.toLowerCase();
  const host = hostOf(url) ?? "";
  const p = pathOf(url);

  if (lower.startsWith("ws://") || lower.startsWith("wss://")) tags.add("websocket");
  if (p.startsWith("/api") || p.includes("/api/")) tags.add("api");
  if (p.startsWith("/rest") || p.includes("/rest/")) tags.add("rest");
  if (p.includes("graphql")) tags.add("graphql");
  if (host.startsWith("admin.") || p.startsWith("/admin") || p.includes("/admin/")) {
    tags.add("admin");
  }
  if (p.includes("/oauth") || p.includes("/callback") || p.includes("/authorize")) {
    tags.add("oauth");
  }
  return [...tags];
}

// ---------------------------------------------------------------------------
// Merge (pure)
// ---------------------------------------------------------------------------

const endpointKey = (method: string, url: string): string =>
  `${method.toUpperCase()} ${url}`;

/**
 * Merge every agent's endpoints into one deduped, source-attributed list.
 * Dedupe key is (method, url). Surface tags union the agent's hints with the
 * tags derived from the URL; sources union the agents that found it. Sorted by
 * url then method so the artifact is stable across runs (no clock/random).
 */
export function mergeEndpoints(results: ReconResult[]): MergedEndpoint[] {
  const byKey = new Map<string, MergedEndpoint>();

  for (const result of results) {
    for (const ep of result.endpoints) {
      const method = (ep.method || "GET").toUpperCase();
      const key = endpointKey(method, ep.url);
      const derived = surfaceTagsFor(ep.url);
      const existing = byKey.get(key);

      if (existing) {
        if (!existing.sources.includes(result.agent)) {
          existing.sources.push(result.agent);
        }
        for (const tag of [...ep.surface_tags, ...derived]) {
          if (!existing.surface_tags.includes(tag)) existing.surface_tags.push(tag);
        }
        if (!existing.notes && ep.notes) existing.notes = ep.notes;
      } else {
        byKey.set(key, {
          url: ep.url,
          method,
          sources: [result.agent],
          surface_tags: [...new Set([...ep.surface_tags, ...derived])],
          ...(ep.notes ? { notes: ep.notes } : {}),
        });
      }
    }
  }

  return [...byKey.values()].sort(
    (a, b) => a.url.localeCompare(b.url) || a.method.localeCompare(b.method),
  );
}

/**
 * Derive the named-surface index from merged endpoints. Each endpoint feeds its
 * surface tags and its host (so `api.target.com` shows up as a surface just as
 * `api` does). Sorted by name; examples capped so the artifact stays small.
 */
export function deriveSurfaces(
  endpoints: MergedEndpoint[],
  maxExamples = 5,
): Surface[] {
  const urls = new Map<string, Set<string>>();
  const add = (name: string, url: string): void => {
    let set = urls.get(name);
    if (!set) urls.set(name, (set = new Set()));
    set.add(url);
  };

  for (const ep of endpoints) {
    for (const tag of ep.surface_tags) add(tag, ep.url);
    const host = hostOf(ep.url);
    if (host) add(host, ep.url);
  }

  return [...urls.entries()]
    .map(([name, set]) => ({
      name,
      count: set.size,
      examples: [...set].sort().slice(0, maxExamples),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function reconDir(workdir: string): string {
  return path.join(workdir, "recon");
}

async function writeJson(file: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, JSON.stringify(value, null, 2) + "\n", "utf8");
}

/** Persist one agent's result to `recon/<agent>.json` (lowercased id). */
export async function writeReconResult(
  workdir: string,
  result: ReconResult,
): Promise<void> {
  const validated = ReconResultSchema.parse(result);
  await writeJson(
    path.join(reconDir(workdir), `${validated.agent.toLowerCase()}.json`),
    validated,
  );
}

export async function readReconResult(
  workdir: string,
  agent: ReconAgentId,
): Promise<ReconResult> {
  const file = path.join(reconDir(workdir), `${agent.toLowerCase()}.json`);
  return ReconResultSchema.parse(JSON.parse(await fs.readFile(file, "utf8")));
}

// ---------------------------------------------------------------------------
// Stage orchestration
// ---------------------------------------------------------------------------

/** Context handed to each agent runner. */
export interface ReconAgentContext {
  agent: ReconAgentId;
  workdir: string;
  scope: Scope;
  /**
   * Consume one rate-limit token from the governor before firing a request.
   * Resolves true when granted, false when throttled. Real agents call this
   * ahead of every outbound request; the governor enforces the shared req/s.
   */
  takeToken: () => Promise<boolean>;
}

/** Injected agent implementation: map the surface, return a result. */
export type ReconRunner = (ctx: ReconAgentContext) => Promise<ReconResult>;

export interface RunReconOptions {
  runner: ReconRunner;
  scope: Scope;
  /** Rate-limit token source shared by all agents (default: always granted). */
  takeToken?: () => Promise<boolean>;
  onCoverageGap?: (gap: CoverageGap) => void;
  /** Override the agent set (tests); defaults to all four. */
  agents?: readonly ReconAgentId[];
}

export interface ReconOutcome {
  /** Always `advance` (recon -> plan): the stage is best-effort. */
  event: Event;
  results: ReconResult[];
  failed: ReconAgentId[];
  endpoints: MergedEndpoint[];
  surfaces: Surface[];
}

/**
 * Run Stage 1. Launches all agents concurrently, persists each result as it
 * settles, logs a `coverage_gap` for any agent that throws (without crashing
 * the stage), merges the survivors into `recon/endpoints.json` +
 * `recon/surfaces.json` (+ `recon/tech.json`), and returns the `advance` event.
 */
export async function runRecon(
  workdir: string,
  opts: RunReconOptions,
): Promise<ReconOutcome> {
  const agents = opts.agents ?? RECON_AGENTS;
  const takeToken = opts.takeToken ?? (async () => true);

  const settled = await Promise.allSettled(
    agents.map(async (agent) => {
      const ctx: ReconAgentContext = {
        agent,
        workdir,
        scope: opts.scope,
        takeToken,
      };
      const result = ReconResultSchema.parse({ ...(await opts.runner(ctx)), agent });
      // Incremental persistence: written the moment this agent returns, so a
      // later agent crashing the process cannot lose this one's work.
      await writeReconResult(workdir, result);
      return result;
    }),
  );

  const results: ReconResult[] = [];
  const failed: ReconAgentId[] = [];
  settled.forEach((outcome, i) => {
    const agent = agents[i]!;
    if (outcome.status === "fulfilled") {
      results.push(outcome.value);
    } else {
      failed.push(agent);
      const err =
        outcome.reason instanceof Error
          ? outcome.reason.message
          : String(outcome.reason);
      opts.onCoverageGap?.({
        kind: "coverage_gap",
        url: null,
        host: null,
        reason: `recon_agent_failed: ${agent}: ${err}`,
      });
    }
  });

  const endpoints = mergeEndpoints(results);
  const surfaces = deriveSurfaces(endpoints);
  const tech = Object.assign({}, ...results.map((r) => r.tech));

  await writeJson(path.join(reconDir(workdir), "endpoints.json"), { endpoints });
  await writeJson(path.join(reconDir(workdir), "surfaces.json"), { surfaces });
  await writeJson(path.join(reconDir(workdir), "tech.json"), tech);

  return { event: { type: "advance" }, results, failed, endpoints, surfaces };
}
