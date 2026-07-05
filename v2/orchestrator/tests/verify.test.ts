import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ScopeSchema, type Scope } from "../src/scope.ts";
import {
  writeFinding,
  HunterFindingSchema,
  type HunterFinding,
} from "../src/hunters/framework.ts";
import { writeChecklist } from "../src/checklist/author.ts";
import {
  VerdictSchema,
  VERDICTS,
  verifyFinding,
  readVerdict,
  passVerdictPath,
  type Verdict,
  type VerifierRunner,
} from "../src/verify/verifier.ts";
import { routeVerdict, isRequeueVerdict } from "../src/verify/routing.ts";
import { refirePoc, type PocExecutor } from "../src/verify/refire.ts";
import {
  runVerifyStage,
  readyForHumanPath,
  type SurgicalReDispatch,
  type SurgicalContext,
} from "../src/verify/stage.ts";
import { transition, initialState, type State } from "../src/state.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://juice.test" });
const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(here, "fixtures", "verify");

let workdir: string;
beforeEach(async () => {
  workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-verify-"));
});
afterEach(async () => {
  await fs.rm(workdir, { recursive: true, force: true });
});

// --- helpers ---------------------------------------------------------------

const finding = (over: Partial<HunterFinding> & Pick<HunterFinding, "vuln_class">): HunterFinding =>
  HunterFindingSchema.parse({
    title: `${over.vuln_class} candidate`,
    severity: "high",
    endpoint: "https://juice.test/api/Users/1",
    method: "GET",
    poc: "echo fresh-body",
    response: "captured-body",
    ...over,
  });

async function seedFinding(id: string, f: HunterFinding): Promise<void> {
  await writeFinding(workdir, id, f);
}

/** A PoC executor that returns a fixed body (stands in for the live target). */
const executorReturning = (stdout: string, exit = 0): PocExecutor =>
  async () => ({ exit_code: exit, stdout, stderr: "" });

/** A Verifier stub that returns a fixed verdict for the finding under test. */
const verifierReturning =
  (verdict: Omit<Verdict, "finding_id">): VerifierRunner =>
  async (input) => VerdictSchema.parse({ ...verdict, finding_id: input.finding_id });

const noReDispatch: SurgicalReDispatch = async () => [];

interface FixtureCase {
  id: string;
  title: string;
  severity: string;
  verdict: Verdict["verdict"];
  reason: string;
  mutation_hint?: string;
  next_step?: Verdict["next_step"];
  expect_action: string;
}
async function loadFixture(): Promise<{ checklist_class: string; cases: FixtureCase[] }> {
  return JSON.parse(await fs.readFile(path.join(fixtureDir, "cases.json"), "utf8"));
}

// --- verdict schema --------------------------------------------------------

describe("VerdictSchema", () => {
  it("validates all eight verdict kinds", () => {
    for (const kind of VERDICTS) {
      const v = VerdictSchema.parse({ finding_id: "f-0001", verdict: kind, reason: "r" });
      expect(v.verdict).toBe(kind);
    }
  });

  it("rejects an unknown verdict and a missing reason", () => {
    expect(() => VerdictSchema.parse({ finding_id: "f-1", verdict: "bogus", reason: "r" })).toThrow();
    expect(() => VerdictSchema.parse({ finding_id: "f-1", verdict: "confirmed" })).toThrow();
  });

  it("carries next_step + mutation_hint only when supplied", () => {
    const v = VerdictSchema.parse({
      finding_id: "f-1",
      verdict: "repro_failed",
      reason: "r",
      mutation_hint: "try adjacent ids",
      next_step: "surgical",
    });
    expect(v.next_step).toBe("surgical");
    expect(v.mutation_hint).toBe("try adjacent ids");
  });
});

// --- routing (pure) --------------------------------------------------------

describe("routeVerdict", () => {
  const v = (verdict: Verdict["verdict"], extra: Partial<Verdict> = {}): Verdict =>
    VerdictSchema.parse({ finding_id: "f-1", verdict, reason: "r", ...extra });

  it("maps each verdict to its action", () => {
    expect(routeVerdict(v("confirmed"))).toEqual({ action: "promote" });
    expect(routeVerdict(v("out_of_scope"))).toEqual({ action: "drop" });
    expect(routeVerdict(v("duplicate"))).toEqual({ action: "merge" });
    expect(routeVerdict(v("severity_mismatch"))).toEqual({ action: "downgrade" });
    expect(routeVerdict(v("non_deterministic"))).toEqual({ action: "escalate" });
    expect(routeVerdict(v("rate_limited"))).toEqual({ action: "backoff" });
  });

  it("routes both re-queue verdicts, defaulting a missing next_step to surgical", () => {
    expect(routeVerdict(v("repro_failed", { next_step: "surgical" }))).toEqual({
      action: "requeue",
      next_step: "surgical",
    });
    expect(routeVerdict(v("weak_evidence", { next_step: "promote_to_tier2" }))).toEqual({
      action: "requeue",
      next_step: "promote_to_tier2",
    });
    // no next_step -> surgical (the conservative default)
    expect(routeVerdict(v("repro_failed"))).toEqual({ action: "requeue", next_step: "surgical" });
  });

  it("isRequeueVerdict is true only for repro_failed / weak_evidence", () => {
    expect(isRequeueVerdict(v("repro_failed"))).toBe(true);
    expect(isRequeueVerdict(v("weak_evidence"))).toBe(true);
    expect(isRequeueVerdict(v("confirmed"))).toBe(false);
  });
});

// --- re-fire path ----------------------------------------------------------

describe("refirePoc", () => {
  it("runs poc.sh in the finding dir and captures fresh vs captured response", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor", response: "captured-body" }));
    let ranPath = "";
    let ranCwd = "";
    const execute: PocExecutor = async (p, cwd) => {
      ranPath = p;
      ranCwd = cwd;
      return { exit_code: 0, stdout: "fresh-body", stderr: "" };
    };
    const out = await refirePoc(workdir, "f-0001", { execute });
    expect(ranPath.endsWith(path.join("f-0001", "poc.sh"))).toBe(true);
    expect(ranCwd.endsWith("f-0001")).toBe(true);
    expect(out.fresh_response).toBe("fresh-body");
    expect(out.captured_response.trim()).toBe("captured-body");
    expect(out.differs).toBe(true);
  });

  it("differs is false when the re-fire matches the captured response", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor", response: "same" }));
    const out = await refirePoc(workdir, "f-0001", { execute: executorReturning("same") });
    expect(out.differs).toBe(false);
  });
});

// --- verifyFinding ---------------------------------------------------------

describe("verifyFinding", () => {
  it("reads the frozen checklist + evidence + refire and returns a validated verdict", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor", evidence: { "diff.txt": "victim ssn leaked" } }));
    await writeChecklist(workdir, "idor", "# idor checklist\n- private-data gate");

    let sawChecklist = "";
    let sawEvidence: Record<string, string> = {};
    let sawRefire = false;
    const runner: VerifierRunner = async (input) => {
      sawChecklist = input.checklist;
      sawEvidence = input.evidence;
      sawRefire = input.refire.fresh_response === "fresh-body";
      return { finding_id: input.finding_id, verdict: "confirmed", reason: "ok" };
    };
    const { verdict } = await verifyFinding(workdir, "f-0001", {
      runner,
      execute: executorReturning("fresh-body"),
    });
    expect(verdict.verdict).toBe("confirmed");
    expect(sawChecklist).toContain("private-data gate");
    expect(sawEvidence["diff.txt"]).toBe("victim ssn leaked");
    expect(sawRefire).toBe(true);
  });

  it("throws when the Verifier answers about the wrong finding", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    const runner: VerifierRunner = async () => ({ finding_id: "f-9999", verdict: "confirmed", reason: "r" });
    await expect(
      verifyFinding(workdir, "f-0001", { runner, execute: executorReturning("x") }),
    ).rejects.toThrow(/finding under test/);
  });

  it("never edits the frozen checklist", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    const frozen = "# idor checklist\n- FROZEN AT 3.6\n";
    await writeChecklist(workdir, "idor", frozen);
    await verifyFinding(workdir, "f-0001", {
      runner: verifierReturning({ verdict: "confirmed", reason: "r" }),
      execute: executorReturning("x"),
    });
    // the checklist on disk is byte-for-byte the frozen content.
    const after = await fs.readFile(path.join(workdir, "checklists", "idor.md"), "utf8");
    expect(after).toBe(frozen);
  });
});

// --- structural rule -------------------------------------------------------

describe("structural rule — the Verifier cannot edit the checklist", () => {
  it("verifier.ts references no checklist/finding writer", async () => {
    const source = await fs.readFile(path.resolve(here, "..", "src", "verify", "verifier.ts"), "utf8");
    expect(source).not.toMatch(/writeChecklist|authorChecklist|runAuthor/);
    expect(source).not.toMatch(/writeFinding\b/);
  });
});

// --- seam tests over the fixtures ------------------------------------------

describe("verify-loop seam fixtures (all 8 verdicts + both re-queue paths)", () => {
  it("routeVerdict maps every fixture case to its expected action", async () => {
    const fixture = await loadFixture();
    const actionFor: Record<string, string> = {
      promote: "promote",
      drop: "drop",
      merge: "merge",
      downgrade: "downgrade",
      escalate: "escalate",
      requeue: "requeue",
      backoff: "backoff",
    };
    const seen = new Set<string>();
    for (const c of fixture.cases) {
      const verdict = VerdictSchema.parse({
        finding_id: c.id,
        verdict: c.verdict,
        reason: c.reason,
        ...(c.mutation_hint ? { mutation_hint: c.mutation_hint } : {}),
        ...(c.next_step ? { next_step: c.next_step } : {}),
      });
      const action = routeVerdict(verdict);
      expect(action.action).toBe(actionFor[c.expect_action]);
      seen.add(c.verdict);
    }
    // every verdict kind is exercised by a fixture.
    expect([...seen].sort()).toEqual([...VERDICTS].sort());
    // both re-queue paths are present.
    const steps = fixture.cases.filter((c) => c.next_step).map((c) => c.next_step);
    expect(steps).toContain("surgical");
    expect(steps).toContain("promote_to_tier2");
  });

  it("runs the loop over all fixtures and routes each to the right bucket", async () => {
    const fixture = await loadFixture();
    await writeChecklist(
      workdir,
      fixture.checklist_class,
      await fs.readFile(path.join(fixtureDir, "checklist.md"), "utf8"),
    );
    for (const c of fixture.cases) {
      await seedFinding(c.id, finding({ vuln_class: fixture.checklist_class, title: c.title, severity: c.severity }));
    }

    // First visit: emit the fixture verdict. Any re-visit (surgical / backoff
    // re-verify): confirm, so the loop terminates cleanly.
    const visited = new Set<string>();
    const runner: VerifierRunner = async (input) => {
      const c = fixture.cases.find((x) => x.id === input.finding_id)!;
      if (visited.has(input.finding_id)) {
        return { finding_id: input.finding_id, verdict: "confirmed", reason: "resolved-on-reverify" };
      }
      visited.add(input.finding_id);
      return VerdictSchema.parse({
        finding_id: input.finding_id,
        verdict: c.verdict,
        reason: c.reason,
        ...(c.mutation_hint ? { mutation_hint: c.mutation_hint } : {}),
        ...(c.next_step ? { next_step: c.next_step } : {}),
      });
    };

    const surgicalCalls: SurgicalContext[] = [];
    const reDispatch: SurgicalReDispatch = async (ctx) => {
      surgicalCalls.push(ctx);
      return [];
    };
    let backoffs = 0;

    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: runner,
      execute: executorReturning("fresh-body"),
      reDispatch,
      backoff: async () => {
        backoffs += 1;
      },
    });

    expect(out.event).toEqual({ type: "advance" });
    // confirmed = the confirmed fixture + the two that resolved on re-verify.
    expect(out.confirmed.sort()).toEqual(["f-0001", "f-0002", "f-0008"]);
    expect(out.dropped).toEqual(["f-0004"]);
    expect(out.merged).toEqual(["f-0005"]);
    expect(out.downgraded).toEqual(["f-0006"]);
    expect(out.escalated).toEqual(["f-0007"]);
    expect(out.deferredTier2).toEqual(["f-0003"]);

    // surgical re-dispatch fired for f-0002 with the reason + mutation_hint.
    expect(out.reDispatched).toBe(1);
    expect(surgicalCalls).toHaveLength(1);
    expect(surgicalCalls[0]!.finding.id).toBe("f-0002");
    expect(surgicalCalls[0]!.reason).toBe("refire_returned_403");
    expect(surgicalCalls[0]!.mutation_hint).toMatch(/victim UUID/);

    // rate_limited backed off before its re-verify.
    expect(backoffs).toBe(1);

    // the downgrade lowered f-0006 high -> medium on disk.
    const f6 = JSON.parse(await fs.readFile(path.join(workdir, "findings", "f-0006", "finding.json"), "utf8"));
    expect(f6.severity).toBe("medium");

    // non_deterministic escalated to ready-for-human, evidence preserved.
    const rfh = await fs.readFile(readyForHumanPath(workdir), "utf8");
    expect(rfh).toMatch(/f-0007/);

    // confirmed findings landed in verdicts/pass-0.json.
    const passFile = JSON.parse(await fs.readFile(passVerdictPath(workdir, 0), "utf8"));
    expect(passFile.verdicts.map((v: Verdict) => v.finding_id).sort()).toEqual(["f-0001", "f-0002", "f-0008"]);
  });
});

// --- iteration cap ---------------------------------------------------------

describe("iteration cap", () => {
  it("escalates rather than drops a finding that keeps re-queuing to the cap", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await writeChecklist(workdir, "idor", "# idor\n");
    let reDispatches = 0;
    const out = await runVerifyStage(workdir, {
      scope,
      // always surgical -> would loop forever without the cap.
      verifierRunner: verifierReturning({ verdict: "repro_failed", reason: "stuck", next_step: "surgical" }),
      execute: executorReturning("x"),
      reDispatch: async () => {
        reDispatches += 1;
        return [];
      },
      maxIterations: 3,
    });
    // 3 iterations: iter1 + iter2 re-dispatch, iter3 hits the cap -> escalate.
    expect(reDispatches).toBe(2);
    expect(out.escalated).toEqual(["f-0001"]);
    expect(out.dropped).toEqual([]);
    expect(out.iterations["f-0001"]).toBe(3);
  });
});

// --- loop / budget control -------------------------------------------------

describe("loop control", () => {
  it("exits cleanly when there are no re-queue verdicts", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await seedFinding("f-0002", finding({ vuln_class: "idor" }));
    await writeChecklist(workdir, "idor", "# idor\n");
    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: verifierReturning({ verdict: "confirmed", reason: "ok" }),
      execute: executorReturning("x"),
      reDispatch: noReDispatch,
    });
    expect(out.confirmed.sort()).toEqual(["f-0001", "f-0002"]);
    expect(out.budgetExhausted).toBe(false);
    expect(out.event).toEqual({ type: "advance" });
  });

  it("stops when the engagement budget is exhausted", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await writeChecklist(workdir, "idor", "# idor\n");
    let verifierCalls = 0;
    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: async (input) => {
        verifierCalls += 1;
        return { finding_id: input.finding_id, verdict: "confirmed", reason: "ok" };
      },
      execute: executorReturning("x"),
      reDispatch: noReDispatch,
      budgetExhausted: () => true,
    });
    expect(verifierCalls).toBe(0);
    expect(out.budgetExhausted).toBe(true);
    expect(out.confirmed).toEqual([]);
    expect(out.event).toEqual({ type: "advance" });
  });

  it("returns advance with no findings on disk", async () => {
    const out = await runVerifyStage(workdir, {
      scope,
      verifierRunner: verifierReturning({ verdict: "confirmed", reason: "ok" }),
      execute: executorReturning("x"),
      reDispatch: noReDispatch,
    });
    expect(out.confirmed).toEqual([]);
    expect(out.event).toEqual({ type: "advance" });
  });
});

// --- state transition ------------------------------------------------------

describe("state transition verify -> report", () => {
  const at = (stage: State["current_stage"]): State => ({
    ...initialState("e", "https://juice.test"),
    current_stage: stage,
  });

  it("advance walks verify -> report", () => {
    const report = transition(at("verify"), { type: "advance" });
    expect(report.current_stage).toBe("report");
  });
});
