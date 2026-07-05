import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  runSweep,
  mapWithConcurrency,
  stampReactiveHypotheses,
  nextReactiveSeq,
  MAX_HYPOTHESES,
} from "../src/hunters/sweep.ts";
import type {
  HunterRunner,
  ProbeTransport,
  ReactiveHypothesisInput,
} from "../src/hunters/framework.ts";
import { readLedger } from "../src/hunters/ledger.ts";
import { coveragePath } from "../src/hunters/coverage.ts";
import {
  hypothesesPath,
  HypothesisSchema,
  HuntPlanCellSchema,
  type HuntPlanCell,
} from "../src/plan.ts";
import { ScopeSchema, type Scope, type CoverageGap } from "../src/scope.ts";

// A committed spec for the parallel Tier 1 sweep: bounded concurrency, the
// coverage invariant (ledger entries OR a logged gap per cell), the reactive
// hypothesis stream, and the derived coverage matrix.

const fixedClock = () => "2026-07-03T12:00:00.000Z";
const scope = (over: Partial<Record<string, unknown>> = {}): Scope =>
  ScopeSchema.parse({ target: "https://juice.test", ...over });

const cell = (
  surface: string,
  vuln_class: string,
  relevant_endpoints: string[],
): HuntPlanCell => HuntPlanCellSchema.parse({ surface, vuln_class, relevant_endpoints });

const okTransport: ProbeTransport = async () => ({ status: "200", trigger_match: false });

/** A runner that fires one probe per endpoint (so the cell is not gapped). */
const firingRunner: HunterRunner = async (ctx) => {
  for (const endpoint of ctx.endpoints) {
    await ctx.fire({
      endpoint,
      method: "GET",
      payload_id: "p1",
      payload: { endpoint },
      session: ctx.session,
    });
  }
  return { findings: [] };
};

describe("mapWithConcurrency", () => {
  it("preserves input order and runs every item", async () => {
    const out = await mapWithConcurrency([1, 2, 3, 4], 2, async (n) => n * 10);
    expect(out).toEqual([10, 20, 30, 40]);
  });

  it("never exceeds the limit in flight", async () => {
    let inFlight = 0;
    let peak = 0;
    await mapWithConcurrency(Array.from({ length: 12 }, (_, i) => i), 3, async (n) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 3));
      inFlight -= 1;
      return n;
    });
    expect(peak).toBeLessThanOrEqual(3);
  });
});

describe("stampReactiveHypotheses / nextReactiveSeq", () => {
  it("stamps tier1_reactive source, queued status, deterministic ids", () => {
    const inputs: ReactiveHypothesisInput[] = [
      { class: "idor", target_endpoint: "/api/Users/2", hypothesis: "seq ids", signal_evidence: "e" },
      { class: "sqli", target_endpoint: "/rest/search", hypothesis: "err leak", signal_evidence: "" },
    ];
    const out = stampReactiveHypotheses(inputs, 1);
    expect(out.map((h) => h.id)).toEqual(["h-react-0001", "h-react-0002"]);
    expect(out.every((h) => h.source === "tier1_reactive")).toBe(true);
    expect(out.every((h) => h.status === "queued")).toBe(true);
    for (const h of out) expect(() => HypothesisSchema.parse(h)).not.toThrow();
  });

  it("continues the sequence past existing h-react rows", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-seq-"));
    await fs.writeFile(
      hypothesesPath(dir),
      JSON.stringify({ id: "h-react-0004" }) + "\n" + JSON.stringify({ id: "h-plan-0001" }) + "\n",
    );
    expect(await nextReactiveSeq(dir)).toBe(5);
    await fs.rm(dir, { recursive: true, force: true });
  });
});

describe("runSweep", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-sweep-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("runs every cell and advances sweep -> author", async () => {
    const out = await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/2"]), cell("api", "idor", ["/api/Users/3"])],
      runnerFor: () => firingRunner,
      transport: okTransport,
      now: fixedClock,
    });
    expect(out.event).toEqual({ type: "advance" });
    expect(out.cellsRun).toBe(2);
    expect(out.probesFired).toBe(2);
    // Both cells left ledger entries.
    expect((await readLedger(dir)).map((e) => e.endpoint).sort()).toEqual([
      "/api/Users/2",
      "/api/Users/3",
    ]);
  });

  it("caps hunters in flight at scope.sweep_concurrency", async () => {
    const cells = Array.from({ length: 10 }, (_, i) => cell(`api${i}`, "idor", [`/api/Users/${i}`]));
    const slowRunner: HunterRunner = async (ctx) => {
      await new Promise((r) => setTimeout(r, 5));
      return firingRunner(ctx);
    };
    const out = await runSweep(dir, {
      scope: scope({ sweep_concurrency: 3 }),
      cells,
      runnerFor: () => slowRunner,
      transport: okTransport,
      now: fixedClock,
    });
    expect(out.maxConcurrency).toBeLessThanOrEqual(3);
    expect(out.maxConcurrency).toBeGreaterThan(1); // proved they actually overlapped
    expect(out.cellsRun).toBe(10);
  });

  it("logs a coverage_gap for a cell with no hunter runner", async () => {
    const gaps: CoverageGap[] = [];
    const out = await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/2"])],
      runnerFor: () => null,
      transport: okTransport,
      onCoverageGap: (g) => gaps.push(g),
      now: fixedClock,
    });
    expect(out.cellsGapped).toBe(1);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]!.reason).toMatch(/no Tier 1 hunter/i);
  });

  it("logs a coverage_gap for a class that has no prompt on disk", async () => {
    const gaps: CoverageGap[] = [];
    const out = await runSweep(dir, {
      scope: scope(),
      // csrf has no hunters/csrf.md prompt -> gap even with a runner supplied.
      cells: [cell("api", "csrf", ["/api/x"])],
      runnerFor: () => firingRunner,
      transport: okTransport,
      onCoverageGap: (g) => gaps.push(g),
      now: fixedClock,
    });
    expect(out.cellsGapped).toBe(1);
    expect(gaps).toHaveLength(1);
  });

  it("logs a coverage_gap when a hunter runs but fires no probes", async () => {
    const gaps: CoverageGap[] = [];
    const emptyRunner: HunterRunner = async () => ({ findings: [] });
    await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/2"])],
      runnerFor: () => emptyRunner,
      transport: okTransport,
      onCoverageGap: (g) => gaps.push(g),
      now: fixedClock,
    });
    expect(gaps).toHaveLength(1);
    expect(gaps[0]!.reason).toMatch(/no probes/i);
  });

  it("appends reactive hypotheses (source tier1_reactive) to hypotheses.jsonl", async () => {
    const signalRunner: HunterRunner = async () => ({
      findings: [],
      hypotheses: [
        // class omitted -> filled from the cell by the framework
        { target_endpoint: "/api/Users/2", hypothesis: "sequential ids", signal_evidence: "200 for id 2" },
      ],
    });
    const out = await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/2"])],
      runnerFor: () => signalRunner,
      transport: okTransport,
      now: fixedClock,
    });
    expect(out.reactiveHypotheses).toHaveLength(1);
    const lines = (await fs.readFile(hypothesesPath(dir), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
    expect(lines).toHaveLength(1);
    expect(lines[0].source).toBe("tier1_reactive");
    expect(lines[0].class).toBe("idor"); // filled from the cell
    expect(lines[0].status).toBe("queued");
    expect(() => HypothesisSchema.parse(lines[0])).not.toThrow();
  });

  it("caps reactive hypotheses at MAX_HYPOTHESES per engagement", async () => {
    const many: ReactiveHypothesisInput[] = Array.from({ length: MAX_HYPOTHESES + 4 }, (_, i) => ({
      class: "idor",
      target_endpoint: `/api/Users/${i}`,
      hypothesis: `signal ${i}`,
      signal_evidence: "",
    }));
    const floodRunner: HunterRunner = async () => ({ findings: [], hypotheses: many });
    const out = await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/0"])],
      runnerFor: () => floodRunner,
      transport: okTransport,
      now: fixedClock,
    });
    expect(out.reactiveHypotheses).toHaveLength(MAX_HYPOTHESES);
    expect(out.droppedHypotheses).toBe(4);
  });

  it("writes coverage.json classifying swept vs GAP", async () => {
    const out = await runSweep(dir, {
      scope: scope(),
      cells: [cell("api", "idor", ["/api/Users/2", "/api/Users/3"])],
      // Fire on the first endpoint only.
      runnerFor: () =>
        async (ctx) => {
          await ctx.fire({
            endpoint: "/api/Users/2",
            method: "GET",
            payload_id: "p1",
            payload: { x: 1 },
            session: ctx.session,
          });
          return { findings: [] };
        },
      transport: okTransport,
      now: fixedClock,
    });
    const cov = JSON.parse(await fs.readFile(coveragePath(dir), "utf8"));
    expect(cov.api["/api/Users/2"].idor.status).toBe("swept");
    expect(cov.api["/api/Users/3"].idor.status).toBe("GAP");
    expect(out.gaps).toBeGreaterThanOrEqual(1);
  });
});
