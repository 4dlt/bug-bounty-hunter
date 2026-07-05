import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  surfaceTagsFor,
  mergeEndpoints,
  deriveSurfaces,
  runRecon,
  writeReconResult,
  readReconResult,
  reconDir,
  RECON_AGENTS,
  type ReconResult,
  type ReconAgentContext,
  type CoverageGap,
} from "../src/recon.ts";
import {
  TokenBucket,
  startTokenServer,
  acquireToken,
  type TokenServer,
} from "../src/ratelimit.ts";
import { ScopeSchema, type Scope } from "../src/scope.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://target.com" });

const result = (over: Partial<ReconResult> & { agent: ReconResult["agent"] }): ReconResult => ({
  endpoints: [],
  tech: {},
  notes: [],
  ...over,
});

describe("surfaceTagsFor", () => {
  it("tags the surfaces the issue calls out", () => {
    expect(surfaceTagsFor("https://target.com/api/users")).toContain("api");
    expect(surfaceTagsFor("https://target.com/rest/products")).toContain("rest");
    expect(surfaceTagsFor("wss://target.com/socket")).toContain("websocket");
    expect(surfaceTagsFor("https://target.com/oauth/callback")).toEqual(
      expect.arrayContaining(["oauth"]),
    );
    expect(surfaceTagsFor("https://admin.target.com/")).toContain("admin");
    expect(surfaceTagsFor("https://target.com/graphql")).toContain("graphql");
  });

  it("tags relative paths too (agents emit relative endpoints)", () => {
    expect(surfaceTagsFor("/api/v1/orders")).toContain("api");
    expect(surfaceTagsFor("/admin/panel")).toContain("admin");
  });

  it("returns no tags for a plain page", () => {
    expect(surfaceTagsFor("https://target.com/about")).toEqual([]);
  });
});

describe("mergeEndpoints", () => {
  it("dedupes by (method, url) and unions the discovering agents", () => {
    const merged = mergeEndpoints([
      result({ agent: "R2", endpoints: [{ url: "/api/x", method: "get", surface_tags: [] }] }),
      result({ agent: "R4", endpoints: [{ url: "/api/x", method: "GET", surface_tags: [] }] }),
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.sources.sort()).toEqual(["R2", "R4"]);
    expect(merged[0]!.method).toBe("GET");
    expect(merged[0]!.surface_tags).toContain("api");
  });

  it("surfaces an R4-only endpoint absent from R2 (JS-extraction value)", () => {
    const merged = mergeEndpoints([
      result({ agent: "R2", endpoints: [{ url: "/", method: "GET", surface_tags: [] }] }),
      result({
        agent: "R4",
        endpoints: [{ url: "/api/hidden/internal", method: "GET", surface_tags: [] }],
      }),
    ]);
    const hidden = merged.find((e) => e.url === "/api/hidden/internal");
    expect(hidden).toBeDefined();
    expect(hidden!.sources).toEqual(["R4"]);
    expect(hidden!.sources).not.toContain("R2");
  });

  it("unions agent-supplied tags with derived tags", () => {
    const merged = mergeEndpoints([
      result({
        agent: "R1",
        endpoints: [{ url: "/api/y", method: "GET", surface_tags: ["custom"] }],
      }),
    ]);
    expect(merged[0]!.surface_tags.sort()).toEqual(["api", "custom"]);
  });
});

describe("deriveSurfaces", () => {
  it("enumerates named surfaces with examples per surface", () => {
    const surfaces = deriveSurfaces(
      mergeEndpoints([
        result({
          agent: "R2",
          endpoints: [
            { url: "https://api.target.com/api/a", method: "GET", surface_tags: [] },
            { url: "https://api.target.com/api/b", method: "GET", surface_tags: [] },
            { url: "wss://target.com/ws", method: "GET", surface_tags: [] },
          ],
        }),
      ]),
    );
    const api = surfaces.find((s) => s.name === "api");
    expect(api!.count).toBe(2);
    expect(api!.examples).toContain("https://api.target.com/api/a");
    expect(surfaces.find((s) => s.name === "websocket")).toBeDefined();
    expect(surfaces.find((s) => s.name === "api.target.com")).toBeDefined();
  });
});

describe("recon artifact round-trip", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-recon-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("writes recon/<agent>.json and reads it back", async () => {
    await writeReconResult(dir, result({ agent: "R3", tech: { framework: "Angular" } }));
    const back = await readReconResult(dir, "R3");
    expect(back.tech.framework).toBe("Angular");
  });
});

describe("runRecon", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-recon-run-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const runnerFor = (byAgent: Partial<Record<string, ReconResult>>): {
    runner: (ctx: ReconAgentContext) => Promise<ReconResult>;
  } => ({
    runner: async (ctx) => {
      const r = byAgent[ctx.agent];
      if (!r) throw new Error(`agent ${ctx.agent} boom`);
      return r;
    },
  });

  it("runs all four agents concurrently", async () => {
    let inFlight = 0;
    let peak = 0;
    const gate: Array<() => void> = [];
    const outcomeP = runRecon(dir, {
      scope,
      runner: async (ctx) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise<void>((res) => gate.push(res));
        inFlight -= 1;
        return result({ agent: ctx.agent });
      },
    });
    // Let all four start before any resolves.
    await new Promise((r) => setTimeout(r, 10));
    expect(peak).toBe(4);
    gate.forEach((release) => release());
    const outcome = await outcomeP;
    expect(outcome.results).toHaveLength(4);
    expect(outcome.event).toEqual({ type: "advance" });
  });

  it("consumes a rate-limit token per agent from a live governor", async () => {
    let server: TokenServer | undefined;
    try {
      server = await startTokenServer(new TokenBucket(4));
      const taken: boolean[] = [];
      await runRecon(dir, {
        scope,
        takeToken: () => acquireToken(server!.url),
        runner: async (ctx) => {
          taken.push(await ctx.takeToken());
          return result({ agent: ctx.agent });
        },
      });
      expect(taken.filter(Boolean)).toHaveLength(4);
      // Bucket of 4 fully drained by the four agents.
      const after = await fetch(`${server.url}/token`);
      expect(after.status).toBe(429);
    } finally {
      await server?.close();
    }
  });

  it("advances after merge and writes endpoints.json + surfaces.json", async () => {
    const outcome = await runRecon(dir, {
      scope,
      ...runnerFor({
        R1: result({ agent: "R1", endpoints: [{ url: "https://admin.target.com/admin", method: "GET", surface_tags: [] }] }),
        R2: result({ agent: "R2", endpoints: [{ url: "/", method: "GET", surface_tags: [] }] }),
        R3: result({ agent: "R3", tech: { cdn: "cloudflare" } }),
        R4: result({ agent: "R4", endpoints: [{ url: "/rest/user/whoami", method: "GET", surface_tags: [] }] }),
      }),
    });
    expect(outcome.event).toEqual({ type: "advance" });

    const endpoints = JSON.parse(
      await fs.readFile(path.join(reconDir(dir), "endpoints.json"), "utf8"),
    );
    expect(endpoints.endpoints).toHaveLength(3);

    const surfaces = JSON.parse(
      await fs.readFile(path.join(reconDir(dir), "surfaces.json"), "utf8"),
    );
    const names = surfaces.surfaces.map((s: { name: string }) => s.name);
    expect(names).toEqual(expect.arrayContaining(["admin", "rest"]));

    const tech = JSON.parse(
      await fs.readFile(path.join(reconDir(dir), "tech.json"), "utf8"),
    );
    expect(tech.cdn).toBe("cloudflare");
  });

  it("does not crash on a per-agent failure: logs a coverage_gap and merges the rest", async () => {
    const gaps: CoverageGap[] = [];
    const outcome = await runRecon(dir, {
      scope,
      onCoverageGap: (g) => gaps.push(g),
      ...runnerFor({
        R1: result({ agent: "R1", endpoints: [{ url: "/api/a", method: "GET", surface_tags: [] }] }),
        R2: result({ agent: "R2" }),
        R4: result({ agent: "R4", endpoints: [{ url: "/rest/b", method: "GET", surface_tags: [] }] }),
        // R3 missing -> runner throws.
      }),
    });
    expect(outcome.failed).toEqual(["R3"]);
    expect(outcome.results).toHaveLength(3);
    expect(outcome.event).toEqual({ type: "advance" });
    expect(gaps).toHaveLength(1);
    expect(gaps[0]!.reason).toMatch(/recon_agent_failed: R3/);
    // Survivors still merged and persisted.
    expect(outcome.endpoints).toHaveLength(2);
  });

  it("defaults to the full R1-R4 agent set", async () => {
    const seen: string[] = [];
    await runRecon(dir, {
      scope,
      runner: async (ctx) => {
        seen.push(ctx.agent);
        return result({ agent: ctx.agent });
      },
    });
    expect(seen.sort()).toEqual([...RECON_AGENTS].sort());
  });
});
