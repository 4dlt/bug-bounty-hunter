import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeSchema, type Scope } from "../src/scope.ts";
import {
  HypothesisSchema,
  appendHypotheses,
  type Hypothesis,
} from "../src/plan.ts";
import {
  appendLedger,
  LedgerEntrySchema,
  type LedgerEntry,
  type LedgerResult,
} from "../src/hunters/ledger.ts";
import {
  writeFinding,
  HunterFindingSchema,
  type HunterFinding,
  type ProbeTransport,
} from "../src/hunters/framework.ts";
import { writeChecklist } from "../src/checklist/author.ts";
import {
  orderHypotheses,
  planQueue,
  readHypotheses,
  logDeferred,
  deferredPath,
  MAX_TIER2_HYPOTHESES,
} from "../src/tier2/queue.ts";
import { buildRecipe, RECIPE_SECTIONS } from "../src/tier2/recipe.ts";
import {
  runDeepHunter,
  readPriorIterations,
  iterationPath,
  DeepHunterOutputSchema,
  MAX_DEEP_ITERATIONS,
  type DeepHunterRunner,
} from "../src/tier2/deep-hunter.ts";
import { runTier2Stage } from "../src/tier2/stage.ts";
import {
  runVerifyStage,
  readyForHumanPath,
  type SurgicalReDispatch,
  type SurgicalContext,
} from "../src/verify/stage.ts";
import {
  VerdictSchema,
  verdictPath,
  type Verdict,
  type VerifierRunner,
} from "../src/verify/verifier.ts";
import { type PocExecutor } from "../src/verify/refire.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://juice.test" });

let workdir: string;
beforeEach(async () => {
  workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-tier2-"));
});
afterEach(async () => {
  await fs.rm(workdir, { recursive: true, force: true });
});

// --- helpers ---------------------------------------------------------------

const hyp = (over: Partial<Hypothesis> & Pick<Hypothesis, "id" | "source">): Hypothesis =>
  HypothesisSchema.parse({
    class: "idor",
    target_endpoint: "https://juice.test/api/Users/1",
    hypothesis: "cross-tenant read on /api/Users/{id}",
    signal_evidence: "",
    estimated_payout_band: null,
    status: "queued",
    ...over,
  });

const finding = (over: Partial<HunterFinding> & Pick<HunterFinding, "vuln_class">): HunterFinding =>
  HunterFindingSchema.parse({
    title: `${over.vuln_class} deep candidate`,
    severity: "high",
    endpoint: "https://juice.test/api/Users/2",
    method: "GET",
    poc: "echo deep-body",
    response: "captured-body",
    ...over,
  });

const okResult: LedgerResult = { status: "200", trigger_match: false };

const ledgerRow = (over: Partial<LedgerEntry>): LedgerEntry =>
  LedgerEntrySchema.parse({
    ts: "2026-07-03T00:00:00.000Z",
    pass: 0,
    agent: "T2-idor",
    surface: "idor",
    endpoint: "https://juice.test/api/Users/1",
    method: "GET",
    class: "idor",
    payload_id: "seed",
    payload_sig: "sig:seed",
    context: { session: "userA" },
    result: okResult,
    ...over,
  });

const passThroughTransport: ProbeTransport = async () => okResult;

// A deep-hunt runner that returns the same output every iteration.
const alwaysReturn =
  (output: Parameters<typeof DeepHunterOutputSchema.parse>[0]): DeepHunterRunner =>
  async () =>
    DeepHunterOutputSchema.parse(output);

// ---------------------------------------------------------------------------
// Hypothesis queue: priority ordering + 15-cap deferral
// ---------------------------------------------------------------------------

describe("hypothesis queue ordering", () => {
  it("consumes verifier escalations, then plan a-priori, then tier1 reactive", () => {
    const hyps = [
      hyp({ id: "h-react-0001", source: "tier1_reactive" }),
      hyp({ id: "h-plan-0001", source: "plan_apriori" }),
      hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      hyp({ id: "h-plan-0002", source: "plan_apriori" }),
      hyp({ id: "h-react-0002", source: "tier1_reactive" }),
    ];
    const ordered = orderHypotheses(hyps).map((h) => h.id);
    expect(ordered).toEqual([
      "h-esc-0001", // verifier escalation first
      "h-plan-0001", // then a-priori, in file order
      "h-plan-0002",
      "h-react-0001", // then reactive, in file order
      "h-react-0002",
    ]);
  });

  it("15-hypothesis cap processes the top 15 and defers the overflow", async () => {
    // 20 reactive + 1 escalation: the escalation must survive, reactive overflow deferred.
    const hyps: Hypothesis[] = [
      hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      ...Array.from({ length: 20 }, (_, i) =>
        hyp({ id: `h-react-${String(i + 1).padStart(4, "0")}`, source: "tier1_reactive" }),
      ),
    ];
    const { process, deferred } = planQueue(hyps);
    expect(process).toHaveLength(MAX_TIER2_HYPOTHESES);
    expect(deferred).toHaveLength(21 - MAX_TIER2_HYPOTHESES);
    // the escalation is never deferred.
    expect(process[0]!.id).toBe("h-esc-0001");
    expect(deferred.every((h) => h.source === "tier1_reactive")).toBe(true);

    const records = await logDeferred(workdir, deferred);
    expect(records.every((r) => r.status === "deferred")).toBe(true);
    const onDisk = await fs.readFile(deferredPath(workdir), "utf8");
    expect(onDisk.trim().split("\n")).toHaveLength(deferred.length);
    expect(onDisk).toMatch(/hypothesis_cap_exceeded/);
  });

  it("reads hypotheses.jsonl and skips a malformed line", async () => {
    await appendHypotheses(workdir, [hyp({ id: "h-plan-0001", source: "plan_apriori" })]);
    await fs.appendFile(path.join(workdir, "hypotheses.jsonl"), "{ not json\n");
    await appendHypotheses(workdir, [hyp({ id: "h-react-0001", source: "tier1_reactive" })]);
    const read = await readHypotheses(workdir);
    expect(read.map((h) => h.id).sort()).toEqual(["h-plan-0001", "h-react-0001"]);
  });
});

// ---------------------------------------------------------------------------
// Recipe: every section populated
// ---------------------------------------------------------------------------

describe("recipe prompt", () => {
  it("populates every one of the six sections (first iteration)", () => {
    const recipe = buildRecipe({
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      iteration: 1,
      context: "authenticated as userA (tenant A); victim is userB (tenant B)",
      alreadyTried: [],
      mutationHints: [],
      budget: { max_probes: 200, max_minutes: 30 },
    });
    // Every section header present, in order, each followed by non-blank content.
    let cursor = 0;
    for (const section of RECIPE_SECTIONS) {
      const at = recipe.indexOf(section, cursor);
      expect(at, `section ${section} present`).toBeGreaterThanOrEqual(0);
      cursor = at + section.length;
    }
    // No section is left empty: even ALREADY_TRIED / MUTATION_HINTS render text.
    expect(recipe).toMatch(/ALREADY_TRIED:\n- \(none tried yet/);
    expect(recipe).toMatch(/MUTATION_HINTS:\n- \(none/);
    expect(recipe).toContain("max_probes: 200");
    expect(recipe).toContain('"outcome": "finding"');
    expect(recipe).toContain("cross-tenant read");
  });

  it("carries prior mutation hints + already-tried payloads into a later iteration", () => {
    const recipe = buildRecipe({
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      iteration: 3,
      context: "",
      alreadyTried: ["idor-decrement", "idor-increment"],
      mutationHints: ["session_diff_too_small", "try a UB account with private data"],
      budget: { max_probes: 200, max_minutes: 30 },
    });
    expect(recipe).toContain("- idor-decrement");
    expect(recipe).toContain("- session_diff_too_small");
    expect(recipe).toContain("- try a UB account with private data");
  });
});

// ---------------------------------------------------------------------------
// Deep-hunter output schema
// ---------------------------------------------------------------------------

describe("DeepHunterOutputSchema", () => {
  it("requires a finding when the outcome is 'finding'", () => {
    expect(() => DeepHunterOutputSchema.parse({ outcome: "finding" })).toThrow();
    const ok = DeepHunterOutputSchema.parse({
      outcome: "finding",
      finding: finding({ vuln_class: "idor" }),
    });
    expect(ok.outcome).toBe("finding");
  });

  it("accepts rejected + needs_more_budget without a finding", () => {
    expect(DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "no diff" }).outcome).toBe("rejected");
    const nmb = DeepHunterOutputSchema.parse({
      outcome: "needs_more_budget",
      reason: "close",
      mutation_hint: "swap uuid",
    });
    expect(nmb.mutation_hint).toBe("swap uuid");
  });
});

// ---------------------------------------------------------------------------
// Deep hunter: hard-check, fresh agent per iteration, cap escalation
// ---------------------------------------------------------------------------

describe("deep hunter — Tier 2 hard-check against the ledger", () => {
  it("refuses the exact same payload+endpoint+session as a duplicate", async () => {
    const { payloadSig } = await import("../src/hunters/ledger.ts");
    // Seed with the exact sig the firer will compute.
    await appendLedger(
      workdir,
      ledgerRow({
        payload_id: "idor-decrement",
        payload_sig: payloadSig("decrement"),
        context: { session: "userA" },
      }),
    );
    let refused: string | undefined;
    const runner: DeepHunterRunner = async (ctx) => {
      const out = await ctx.fire({
        endpoint: "https://juice.test/api/Users/1",
        payload_id: "idor-decrement",
        payload: "decrement",
        session: "userA",
      });
      if (!out.fired) refused = out.reason;
      return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "r" });
    };
    const out = await runDeepHunter(workdir, {
      runner,
      scope,
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      transport: passThroughTransport,
      maxIterations: 1,
    });
    expect(refused).toBe("duplicate");
    expect(out.duplicatesSkipped).toBe(1);
    expect(out.probesFired).toBe(0);
  });

  it("a novel mutated payload fires (expands the probe space)", async () => {
    const { payloadSig } = await import("../src/hunters/ledger.ts");
    await appendLedger(
      workdir,
      ledgerRow({ payload_id: "seed", payload_sig: payloadSig("decrement"), context: { session: "userA" } }),
    );
    const runner: DeepHunterRunner = async (ctx) => {
      // a DIFFERENT payload -> different sig -> novel.
      const out = await ctx.fire({
        endpoint: "https://juice.test/api/Users/1",
        payload_id: "idor-uuid",
        payload: "uuid-from-userB",
        session: "userA",
      });
      expect(out.fired).toBe(true);
      return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "r" });
    };
    const out = await runDeepHunter(workdir, {
      runner,
      scope,
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      transport: passThroughTransport,
      maxIterations: 1,
    });
    expect(out.probesFired).toBe(1);
  });
});

describe("deep hunter — iteration lifecycle", () => {
  it("fresh agent per iteration inherits prior output + hints from disk", async () => {
    const seenHints: string[][] = [];
    let iterations = 0;
    const runner: DeepHunterRunner = async (ctx) => {
      iterations += 1;
      seenHints.push([...ctx.mutationHints]);
      // Confirm on the 3rd iteration; earlier ones ask for more budget with a hint.
      if (ctx.iteration >= 3) {
        return DeepHunterOutputSchema.parse({
          outcome: "finding",
          finding: finding({ vuln_class: "idor" }),
        });
      }
      return DeepHunterOutputSchema.parse({
        outcome: "needs_more_budget",
        reason: `iter ${ctx.iteration}`,
        mutation_hint: `hint-${ctx.iteration}`,
      });
    };
    const out = await runDeepHunter(workdir, {
      runner,
      scope,
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      transport: passThroughTransport,
    });
    expect(iterations).toBe(3);
    expect(out.result).toBe("finding");
    expect(out.findingIds).toHaveLength(1);
    // iteration 2 saw iter-1's hint; iteration 3 saw iter-1 + iter-2's hints.
    expect(seenHints[0]).toEqual([]);
    expect(seenHints[1]).toEqual(["hint-1"]);
    expect(seenHints[2]).toEqual(["hint-1", "hint-2"]);

    // Each iteration persisted to disk (fresh agent re-reads these).
    const prior = await readPriorIterations(workdir, "h-esc-0001");
    expect(prior).toHaveLength(3);
    expect(await fs.readFile(iterationPath(workdir, "h-esc-0001", 1), "utf8")).toMatch(/hint-1/);

    // The finding was written and is a real finding dir the verify loop can read.
    const fmeta = JSON.parse(
      await fs.readFile(path.join(workdir, "findings", out.findingIds[0]!, "finding.json"), "utf8"),
    );
    expect(fmeta.vuln_class).toBe("idor");
  });

  it("stops immediately on a rejected verdict", async () => {
    let iterations = 0;
    const out = await runDeepHunter(workdir, {
      runner: async (ctx) => {
        iterations += 1;
        void ctx;
        return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "no cross-tenant read" });
      },
      scope,
      hypothesis: hyp({ id: "h-plan-0001", source: "plan_apriori" }),
      transport: passThroughTransport,
    });
    expect(iterations).toBe(1);
    expect(out.result).toBe("rejected");
    expect(out.findingIds).toEqual([]);
  });

  it("10-iteration cap escalates to ready-for-human rather than dropping", async () => {
    const out = await runDeepHunter(workdir, {
      runner: alwaysReturn({ outcome: "needs_more_budget", reason: "stubborn", mutation_hint: "keep trying" }),
      scope,
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      transport: passThroughTransport,
      maxIterations: 4,
    });
    expect(out.result).toBe("escalated");
    expect(out.iterations).toBe(4);
    expect(out.findingIds).toEqual([]);
    const rfh = await fs.readFile(readyForHumanPath(workdir), "utf8");
    expect(rfh).toMatch(/h-esc-0001/);
    expect(rfh).toMatch(/4-iteration cap/);
  });

  it("defaults the iteration cap to MAX_DEEP_ITERATIONS (10)", async () => {
    const out = await runDeepHunter(workdir, {
      runner: alwaysReturn({ outcome: "needs_more_budget", reason: "x", mutation_hint: "y" }),
      scope,
      hypothesis: hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      transport: passThroughTransport,
    });
    expect(out.iterations).toBe(MAX_DEEP_ITERATIONS);
  });
});

// ---------------------------------------------------------------------------
// Tier 2 stage: consume queue in priority order, defer overflow, collect findings
// ---------------------------------------------------------------------------

describe("runTier2Stage", () => {
  it("deep-hunts the queue in priority order and collects findings for verify", async () => {
    const processed: string[] = [];
    const runner: DeepHunterRunner = async (ctx) => {
      processed.push(ctx.hypothesis.id);
      // escalation confirms a finding; the others reject.
      if (ctx.hypothesis.source === "verifier_escalation") {
        return DeepHunterOutputSchema.parse({
          outcome: "finding",
          finding: finding({ vuln_class: ctx.hypothesis.class }),
        });
      }
      return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "no" });
    };
    const out = await runTier2Stage(workdir, {
      scope,
      runner,
      transport: passThroughTransport,
      hypotheses: [
        hyp({ id: "h-react-0001", source: "tier1_reactive" }),
        hyp({ id: "h-plan-0001", source: "plan_apriori" }),
        hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
      ],
      maxIterations: 1,
    });
    // priority order: escalation first.
    expect(processed).toEqual(["h-esc-0001", "h-plan-0001", "h-react-0001"]);
    expect(out.processed).toBe(3);
    expect(out.findingIds).toHaveLength(1);
    expect(out.deferred).toEqual([]);
  });

  it("defers overflow past the cap and logs it", async () => {
    const hyps = Array.from({ length: 5 }, (_, i) =>
      hyp({ id: `h-react-${String(i + 1).padStart(4, "0")}`, source: "tier1_reactive" }),
    );
    const out = await runTier2Stage(workdir, {
      scope,
      runner: alwaysReturn({ outcome: "rejected", reason: "no" }),
      transport: passThroughTransport,
      hypotheses: hyps,
      maxHypotheses: 2,
      maxIterations: 1,
    });
    expect(out.processed).toBe(2);
    expect(out.deferred.map((d) => d.id)).toEqual(["h-react-0003", "h-react-0004", "h-react-0005"]);
    const onDisk = await fs.readFile(deferredPath(workdir), "utf8");
    expect(onDisk.trim().split("\n")).toHaveLength(3);
  });

  it("stops spawning hunters when the engagement budget is exhausted", async () => {
    let spawned = 0;
    const out = await runTier2Stage(workdir, {
      scope,
      runner: async () => {
        spawned += 1;
        return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "no" });
      },
      transport: passThroughTransport,
      hypotheses: [
        hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
        hyp({ id: "h-esc-0002", source: "verifier_escalation" }),
      ],
      budgetExhausted: () => true,
      maxIterations: 1,
    });
    expect(spawned).toBe(0);
    expect(out.budgetExhausted).toBe(true);
    expect(out.processed).toBe(0);
  });

  it("reads hypotheses.jsonl when no override is passed", async () => {
    await appendHypotheses(workdir, [
      hyp({ id: "h-plan-0001", source: "plan_apriori" }),
      hyp({ id: "h-esc-0001", source: "verifier_escalation" }),
    ]);
    const processed: string[] = [];
    await runTier2Stage(workdir, {
      scope,
      runner: async (ctx) => {
        processed.push(ctx.hypothesis.id);
        return DeepHunterOutputSchema.parse({ outcome: "rejected", reason: "no" });
      },
      transport: passThroughTransport,
      maxIterations: 1,
    });
    expect(processed).toEqual(["h-esc-0001", "h-plan-0001"]);
  });
});

// ---------------------------------------------------------------------------
// Verify-loop integration: promote_to_tier2 spawns Tier 2, findings re-verify
// ---------------------------------------------------------------------------

describe("verify loop — promote_to_tier2 routing", () => {
  const executorReturning = (stdout: string): PocExecutor => async () => ({
    exit_code: 0,
    stdout,
    stderr: "",
  });

  it("routes a promote_to_tier2 verdict to the Tier 2 seam and re-verifies its finding", async () => {
    await writeChecklist(workdir, "idor", "# idor\n- private-data gate\n");
    await writeFinding(workdir, "f-0001", finding({ vuln_class: "idor", title: "weak idor" }));

    // First verify of f-0001 -> weak_evidence + promote_to_tier2.
    // The Tier 2 seam produces f-0002, which then verifies confirmed.
    const promoteToTier2: SurgicalReDispatch = async (ctx: SurgicalContext) => {
      expect(ctx.finding.id).toBe("f-0001");
      expect(ctx.mutation_hint).toMatch(/deeper flow/);
      await writeFinding(workdir, "f-0002", finding({ vuln_class: "idor", title: "deep idor" }));
      return ["f-0002"];
    };

    const runner: VerifierRunner = async (input) => {
      if (input.finding_id === "f-0001") {
        return VerdictSchema.parse({
          finding_id: "f-0001",
          verdict: "weak_evidence",
          reason: "session_diff_too_small",
          mutation_hint: "needs a deeper flow with multi-account setup",
          next_step: "promote_to_tier2",
        });
      }
      return { finding_id: input.finding_id, verdict: "confirmed", reason: "cross-tenant read confirmed" };
    };

    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: runner,
      execute: executorReturning("fresh"),
      reDispatch: async () => [],
      promoteToTier2,
    });

    expect(out.tier2Spawned).toBe(1);
    expect(out.deferredTier2).toEqual(["f-0001"]);
    // the Tier 2 finding flowed back through the SAME loop and confirmed.
    expect(out.confirmed).toEqual(["f-0002"]);
    // its verdict was persisted.
    const v2 = JSON.parse(await fs.readFile(verdictPath(workdir, "f-0002"), "utf8")) as Verdict;
    expect(v2.verdict).toBe("confirmed");
  });

  it("without a promoteToTier2 seam, a promote verdict is only recorded (deferred)", async () => {
    await writeChecklist(workdir, "idor", "# idor\n");
    await writeFinding(workdir, "f-0001", finding({ vuln_class: "idor" }));
    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: async (input) => ({
        finding_id: input.finding_id,
        verdict: "repro_failed",
        reason: "needs depth",
        next_step: "promote_to_tier2",
      }),
      execute: executorReturning("x"),
      reDispatch: async () => [],
    });
    expect(out.deferredTier2).toEqual(["f-0001"]);
    expect(out.tier2Spawned).toBe(0);
    expect(out.confirmed).toEqual([]);
  });

  it("promote is one-shot per verdict: a fruitless deep hunt records without looping", async () => {
    // The deep hunter owns its OWN 10-iteration cap (runDeepHunter escalates
    // internally); the verify loop spawns it once per promote verdict rather
    // than re-queuing the original finding, so a fruitless spawn (returns [])
    // ends the loop cleanly instead of dropping or spinning.
    await writeChecklist(workdir, "idor", "# idor\n");
    await writeFinding(workdir, "f-0001", finding({ vuln_class: "idor" }));
    let spawns = 0;
    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: async (input) => ({
        finding_id: input.finding_id,
        verdict: "weak_evidence",
        reason: "still shallow",
        next_step: "promote_to_tier2",
      }),
      execute: executorReturning("x"),
      reDispatch: async () => [],
      promoteToTier2: async () => {
        spawns += 1;
        return []; // deep hunt produced no new candidate
      },
    });
    expect(spawns).toBe(1);
    expect(out.tier2Spawned).toBe(1);
    expect(out.deferredTier2).toEqual(["f-0001"]);
    expect(out.dropped).toEqual([]);
    expect(out.escalated).toEqual([]);
  });
});
