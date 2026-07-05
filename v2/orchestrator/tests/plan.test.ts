import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  isBelowBand,
  isCompatible,
  buildHuntPlan,
  seedHypotheses,
  relevantEndpointsFor,
  runPlan,
  readHuntPlan,
  hypothesesPath,
  huntPlanPath,
  HuntPlanFileSchema,
  HypothesisSchema,
  PAYOUT_BANDS,
  type HuntPlanCell,
  type PlanHypothesisInput,
  type PlanProposal,
} from "../src/plan.ts";
import { reconDir, type MergedEndpoint, type Surface } from "../src/recon.ts";
import { ScopeSchema, type Scope } from "../src/scope.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://target.com" });

const cell = (over: Partial<HuntPlanCell> & Pick<HuntPlanCell, "surface" | "vuln_class">): HuntPlanCell => ({
  relevant_endpoints: [],
  priority: "medium",
  expected_payout_band: null,
  ...over,
});

const surface = (name: string, examples: string[] = []): Surface => ({
  name,
  count: examples.length,
  examples,
});

const endpoint = (over: Partial<MergedEndpoint> & Pick<MergedEndpoint, "url">): MergedEndpoint => ({
  method: "GET",
  sources: ["R2"],
  surface_tags: [],
  ...over,
});

describe("isBelowBand", () => {
  it("drops entries strictly below the floor", () => {
    expect(isBelowBand("P4", "P3")).toBe(true);
    expect(isBelowBand("P3", "P3")).toBe(false);
    expect(isBelowBand("P2", "P3")).toBe(false);
    expect(isBelowBand("P1", "P3")).toBe(false);
  });

  it("keeps an unknown (null) band — unknown is not below", () => {
    expect(isBelowBand(null, "P3")).toBe(false);
  });

  it("disables filtering on an unparseable floor", () => {
    expect(isBelowBand("P4", "bogus")).toBe(false);
  });
});

describe("isCompatible", () => {
  it("rejects XSS on a pure JSON API surface (acceptance: no nonsensical pairs)", () => {
    expect(isCompatible("xss", "api")).toBe(false);
    expect(isCompatible("xss", "rest")).toBe(false);
    expect(isCompatible("xss", "graphql")).toBe(false);
    expect(isCompatible("xss", "websocket")).toBe(false);
  });

  it("allows server-side classes on a JSON API", () => {
    expect(isCompatible("idor", "api")).toBe(true);
    expect(isCompatible("sqli", "rest")).toBe(true);
    expect(isCompatible("ssrf", "api")).toBe(true);
  });

  it("allows XSS on HTML surfaces (admin, hosts)", () => {
    expect(isCompatible("xss", "admin")).toBe(true);
    expect(isCompatible("xss", "www.target.com")).toBe(true);
  });
});

describe("relevantEndpointsFor", () => {
  it("collects endpoints tagged with or hosted under the surface", () => {
    const eps = [
      endpoint({ url: "https://api.target.com/api/a", surface_tags: ["api"] }),
      endpoint({ url: "https://admin.target.com/x", surface_tags: ["admin"] }),
    ];
    expect(relevantEndpointsFor("api", eps)).toEqual(["https://api.target.com/api/a"]);
    expect(relevantEndpointsFor("api.target.com", eps)).toEqual([
      "https://api.target.com/api/a",
    ]);
  });
});

describe("buildHuntPlan", () => {
  it("drops incompatible cells", () => {
    const { cells, droppedCells } = buildHuntPlan(
      [cell({ surface: "api", vuln_class: "xss" }), cell({ surface: "api", vuln_class: "idor" })],
      [surface("api")],
      [],
    );
    expect(droppedCells).toBe(1);
    expect(cells.map((c) => c.vuln_class)).toEqual(["idor"]);
  });

  it("guarantees every recon surface has at least one assigned class", () => {
    const { cells } = buildHuntPlan(
      [cell({ surface: "api", vuln_class: "idor" })],
      [surface("api"), surface("admin"), surface("oauth")],
      [],
    );
    const bySurface = new Set(cells.map((c) => c.surface));
    expect(bySurface).toEqual(new Set(["api", "admin", "oauth"]));
    // The synthesized default cell is compatible with its surface.
    for (const c of cells) expect(isCompatible(c.vuln_class, c.surface)).toBe(true);
  });

  it("does not re-cover a surface the planner already covered (even if a cell was dropped)", () => {
    // api is covered by a valid idor cell; the dropped xss cell must not trigger a default.
    const { cells } = buildHuntPlan(
      [cell({ surface: "api", vuln_class: "xss" }), cell({ surface: "api", vuln_class: "idor" })],
      [surface("api")],
      [],
    );
    expect(cells.filter((c) => c.surface === "api")).toHaveLength(1);
  });

  it("fills a default cell's relevant endpoints from recon", () => {
    const { cells } = buildHuntPlan(
      [],
      [surface("api")],
      [endpoint({ url: "https://target.com/api/x", surface_tags: ["api"] })],
    );
    expect(cells[0]!.relevant_endpoints).toEqual(["https://target.com/api/x"]);
  });

  it("produces a plan that validates against the file schema", () => {
    const { cells } = buildHuntPlan([cell({ surface: "admin", vuln_class: "xss" })], [surface("admin")], []);
    expect(() => HuntPlanFileSchema.parse({ cells })).not.toThrow();
  });
});

describe("seedHypotheses", () => {
  const hyp = (over: Partial<PlanHypothesisInput>): PlanHypothesisInput => ({
    class: "idor",
    target_endpoint: "/api/orders/{id}",
    hypothesis: "sequential order ids expose other tenants",
    signal_evidence: "",
    estimated_payout_band: "P2",
    ...over,
  });

  it("stamps source, status, and deterministic ids", () => {
    const { hypotheses } = seedHypotheses([hyp({}), hyp({ class: "auth" })], "P3");
    expect(hypotheses.map((h) => h.id)).toEqual(["h-plan-0001", "h-plan-0002"]);
    expect(hypotheses.every((h) => h.source === "plan_apriori")).toBe(true);
    expect(hypotheses.every((h) => h.status === "queued")).toBe(true);
  });

  it("filters out entries below min_payout_band (acceptance)", () => {
    const { hypotheses, droppedHypotheses } = seedHypotheses(
      [hyp({ estimated_payout_band: "P4" }), hyp({ estimated_payout_band: "P2" })],
      "P3",
    );
    expect(droppedHypotheses).toBe(1);
    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0]!.estimated_payout_band).toBe("P2");
    // Ids are contiguous over the survivors, not the inputs.
    expect(hypotheses[0]!.id).toBe("h-plan-0001");
  });

  it("keeps a null-band a-priori lead for a high-value surface", () => {
    const { hypotheses } = seedHypotheses([hyp({ estimated_payout_band: null })], "P3");
    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0]!.estimated_payout_band).toBeNull();
  });

  it("every seeded band is one of P1|P2|P3|P4|null", () => {
    const { hypotheses } = seedHypotheses(
      [hyp({ estimated_payout_band: "P1" }), hyp({ estimated_payout_band: null })],
      "P4",
    );
    for (const h of hypotheses) {
      expect(h.estimated_payout_band === null || PAYOUT_BANDS.includes(h.estimated_payout_band)).toBe(true);
      expect(() => HypothesisSchema.parse(h)).not.toThrow();
    }
  });
});

describe("runPlan", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-plan-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const writeRecon = async (
    endpoints: MergedEndpoint[],
    surfaces: Surface[],
    tech: Record<string, unknown> = {},
  ): Promise<void> => {
    const rd = reconDir(dir);
    await fs.mkdir(rd, { recursive: true });
    await fs.writeFile(path.join(rd, "endpoints.json"), JSON.stringify({ endpoints }));
    await fs.writeFile(path.join(rd, "surfaces.json"), JSON.stringify({ surfaces }));
    await fs.writeFile(path.join(rd, "tech.json"), JSON.stringify(tech));
  };

  const runnerFor =
    (proposal: PlanProposal) =>
    async (): Promise<PlanProposal> =>
      proposal;

  it("produces a validated hunt-plan.json and advances plan -> sweep", async () => {
    await writeRecon(
      [endpoint({ url: "https://target.com/api/x", surface_tags: ["api"] })],
      [surface("api"), surface("admin")],
    );
    const outcome = await runPlan(dir, {
      scope,
      runner: runnerFor({
        cells: [cell({ surface: "api", vuln_class: "idor" })],
        hypotheses: [],
      }),
    });
    expect(outcome.event).toEqual({ type: "advance" });

    const back = await readHuntPlan(dir);
    // api covered by the proposal, admin covered by a synthesized default.
    expect(new Set(back.map((c) => c.surface))).toEqual(new Set(["api", "admin"]));
    // File on disk validates.
    const onDisk = JSON.parse(await fs.readFile(huntPlanPath(dir), "utf8"));
    expect(() => HuntPlanFileSchema.parse(onDisk)).not.toThrow();
  });

  it("seeds a-priori hypotheses into hypotheses.jsonl, band-filtered", async () => {
    await writeRecon([], [surface("admin"), surface("oauth")]);
    const outcome = await runPlan(dir, {
      scope,
      runner: runnerFor({
        cells: [],
        hypotheses: [
          {
            class: "auth",
            target_endpoint: "/oauth/authorize",
            hypothesis: "open redirect via redirect_uri on the OAuth callback",
            signal_evidence: "redirect_uri not validated against an allowlist",
            estimated_payout_band: "P2",
          },
          {
            class: "info_disclosure",
            target_endpoint: "/admin/config",
            hypothesis: "verbose error leaks stack traces",
            signal_evidence: "",
            estimated_payout_band: "P4", // below default floor P3 -> dropped
          },
        ],
      }),
    });
    expect(outcome.hypotheses.length).toBeGreaterThanOrEqual(1);
    expect(outcome.droppedHypotheses).toBe(1);

    const lines = (await fs.readFile(hypothesesPath(dir), "utf8"))
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l));
    expect(lines).toHaveLength(1);
    expect(() => HypothesisSchema.parse(lines[0])).not.toThrow();
    expect(lines[0].source).toBe("plan_apriori");
    expect(lines[0].class).toBe("auth");
  });

  it("appends (never truncates) hypotheses.jsonl across seeds", async () => {
    await writeRecon([], [surface("admin")]);
    await fs.writeFile(hypothesesPath(dir), JSON.stringify({ id: "pre-existing" }) + "\n");
    await runPlan(dir, {
      scope,
      runner: runnerFor({
        cells: [],
        hypotheses: [
          {
            class: "idor",
            target_endpoint: "/api/x",
            hypothesis: "h",
            signal_evidence: "",
            estimated_payout_band: "P1",
          },
        ],
      }),
    });
    const lines = (await fs.readFile(hypothesesPath(dir), "utf8")).trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!).id).toBe("pre-existing");
  });

  it("still advances and covers surfaces when recon artifacts are missing", async () => {
    // No writeRecon: endpoints/surfaces files absent.
    const outcome = await runPlan(dir, {
      scope,
      runner: runnerFor({ cells: [], hypotheses: [] }),
    });
    expect(outcome.event).toEqual({ type: "advance" });
    expect(await readHuntPlan(dir)).toEqual([]);
  });
});
