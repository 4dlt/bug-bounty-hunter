// Slice 7 — the stage-gate seam tests (the third and final testing seam).
//
// Covers, per the issue's acceptance criteria:
//   - report.md contains only confirmed findings + a separate ready-for-human
//     section, and NO bounty estimation anywhere (a source-grep proves it);
//   - `bbh resume <id>` validates artifacts and resumes from each of the 8
//     stages (pure `validateResume` over fixture snapshots + a live disk read);
//   - re-running an in-flight stage does not double-fire probes (the ledger
//     dedupe holds across a fresh firer that re-reads the persisted ledger);
//   - budget exhaustion halts cleanly, marks status `budget_exhausted`, writes
//     a partial report;
//   - `bbh status <id>` reports real engagement state.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ScopeSchema, type Scope, type Budget } from "../src/scope.ts";
import {
  initialState,
  writeState,
  readState,
  type State,
  STAGES,
} from "../src/state.ts";
import { writeFinding, createProbeFirer, type ProbeRequest } from "../src/hunters/framework.ts";
import { readLedger } from "../src/hunters/ledger.ts";
import { writePassVerdicts, VerdictSchema } from "../src/verify/verifier.ts";
import { escalateToHuman } from "../src/verify/stage.ts";
import {
  buildReport,
  readConfirmedFindings,
  readEscalations,
  writeReport,
  reportPath,
  severityToPriority,
  suggestedFix,
} from "../src/report/report.ts";
import {
  exceededBudgets,
  isBudgetExhausted,
  countProbes,
  BudgetTracker,
  haltForBudget,
} from "../src/budget.ts";
import {
  validateResume,
  collectArtifacts,
  collectStatus,
  formatStatus,
  type ArtifactSnapshot,
} from "../src/resume.ts";
import {
  writeRejectionReport,
  rejectionReportPath,
} from "../src/checklist/stage.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://juice.test" });
const budget: Budget = scope.budget;
const here = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(here, "fixtures", "state-gate");

let workdir: string;
beforeEach(async () => {
  workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-state-gate-"));
});
afterEach(async () => {
  await fs.rm(workdir, { recursive: true, force: true });
});

// --- helpers ---------------------------------------------------------------

const state = (over: Partial<State> = {}): State => ({
  ...initialState("eng-1", "https://juice.test"),
  ...over,
});

async function seedFinding(
  id: string,
  over: { title?: string; severity?: string; vuln_class?: string; endpoint?: string } = {},
): Promise<void> {
  await writeFinding(workdir, id, {
    title: over.title ?? `${over.vuln_class ?? "idor"} candidate`,
    severity: over.severity ?? "high",
    vuln_class: over.vuln_class ?? "idor",
    endpoint: over.endpoint ?? "https://juice.test/api/Users/1",
    method: "GET",
    poc: "echo body",
    response: "captured",
    evidence: {},
  });
}

const confirmed = (findingId: string) =>
  VerdictSchema.parse({ finding_id: findingId, verdict: "confirmed", reason: "checklist passed" });

// ===========================================================================
// Report generation (acceptance: only confirmed + ready-for-human, no bounty)
// ===========================================================================

describe("report — confirmed findings only, no bounty estimation", () => {
  it("renders one numbered section per confirmed finding with the required fields", () => {
    // buildReport renders in the order given (readConfirmedFindings does the
    // impact sort); the report driver hands it P1-first.
    const md = buildReport(
      state(),
      [
        {
          meta: {
            id: "f-0001",
            title: "Critical SQLi",
            severity: "critical",
            vuln_class: "sqli",
            endpoint: "/api/login",
            method: "POST",
          },
          verdict: confirmed("f-0001"),
        },
        {
          meta: {
            id: "f-0002",
            title: "Medium IDOR",
            severity: "medium",
            vuln_class: "idor",
            endpoint: "/api/Users/2",
            method: "GET",
          },
          verdict: confirmed("f-0002"),
        },
      ],
      [],
    );
    expect(md).toContain("### 1. Critical SQLi  [P1]");
    expect(md).toContain("### 2. Medium IDOR  [P3]");
    expect(md).toContain("**Confirmed findings:** 2");
    // Every confirmed finding carries the five required fields.
    expect(md).toContain("**Affected endpoint:** `POST /api/login`");
    expect(md).toContain("`findings/f-0001/poc.sh`");
    expect(md).toContain("**Suggested fix:**");
    // No ready-for-human section when there are no escalations.
    expect(md).not.toContain("Ready for Human Review");
  });

  it("adds a separate ready-for-human section when escalations exist", () => {
    const md = buildReport(state(), [], [
      { finding_id: "f-0009", reason: "non_deterministic", evidence_dir: "findings/f-0009/evidence" },
    ]);
    expect(md).toContain("## Ready for Human Review");
    expect(md).toContain("f-0009");
    expect(md).toContain("non_deterministic");
    // With zero confirmed the Confirmed section states so explicitly.
    expect(md).toContain("_No findings were confirmed in this engagement._");
  });

  it("carries no bounty_estimate field and no monetary figures (report + source)", async () => {
    const md = buildReport(
      state(),
      [
        {
          meta: {
            id: "f-0001",
            title: "X",
            severity: "high",
            vuln_class: "idor",
            endpoint: "/a",
            method: "GET",
          },
          verdict: confirmed("f-0001"),
        },
      ],
      [{ finding_id: "f-0002", reason: "weak" }],
    );
    // No bounty_estimate field, no dollar figures — severity is impact only.
    expect(md.toLowerCase()).not.toContain("bounty_estimate");
    expect(md).not.toContain("$");
    expect(md).not.toMatch(/\bestimated?\b/i);
    // Structural guard: the report module never emits a bounty_estimate field.
    const src = await fs.readFile(
      path.resolve(here, "..", "src", "report", "report.ts"),
      "utf8",
    );
    expect(src).not.toContain("bounty_estimate");
  });

  it("maps severity bands to P1–P4 impact, flooring unknown to P4", () => {
    expect(severityToPriority("critical")).toBe("P1");
    expect(severityToPriority("High")).toBe("P2");
    expect(severityToPriority("medium")).toBe("P3");
    expect(severityToPriority("low")).toBe("P4");
    expect(severityToPriority("unknown")).toBe("P4");
    expect(severityToPriority("nonsense")).toBe("P4");
  });

  it("suggests a class-specific fix, with a generic fallback", () => {
    expect(suggestedFix("idor")).toMatch(/object-level authorization/i);
    expect(suggestedFix("totally_new_class")).toMatch(/regression test/i);
  });
});

describe("report — reading confirmed findings from disk", () => {
  it("collects only confirmed verdicts, highest pass wins, skips missing findings", async () => {
    await seedFinding("f-0001", { severity: "high", vuln_class: "idor" });
    await seedFinding("f-0002", { severity: "low", vuln_class: "xss_reflected" });
    // f-0003 has a confirmed verdict but NO finding.json on disk → skipped.
    await writePassVerdicts(workdir, 1, [
      confirmed("f-0001"),
      VerdictSchema.parse({ finding_id: "f-0002", verdict: "weak_evidence", reason: "thin", mutation_hint: "vary" }),
      confirmed("f-0003"),
    ]);
    // A later pass re-confirms f-0002 — the highest pass wins.
    await writePassVerdicts(workdir, 2, [confirmed("f-0002")]);

    const found = await readConfirmedFindings(workdir);
    const ids = found.map((c) => c.meta.id);
    expect(ids).toContain("f-0001");
    expect(ids).toContain("f-0002");
    expect(ids).not.toContain("f-0003"); // no finding.json
    expect(found).toHaveLength(2);
    // Impact sort: high (P2) f-0001 before low (P4) f-0002.
    expect(ids).toEqual(["f-0001", "f-0002"]);
  });

  it("readEscalations reads ready-for-human.jsonl, none when absent", async () => {
    expect(await readEscalations(workdir)).toEqual([]);
    await escalateToHuman(workdir, "f-0007", "non_deterministic");
    const escs = await readEscalations(workdir);
    expect(escs).toHaveLength(1);
    expect(escs[0]!.finding_id).toBe("f-0007");
  });

  it("writeReport writes report.md to disk with only confirmed findings", async () => {
    await seedFinding("f-0001", { severity: "critical", vuln_class: "sqli" });
    await writePassVerdicts(workdir, 1, [confirmed("f-0001")]);
    const md = await writeReport(workdir, state());
    const onDisk = await fs.readFile(reportPath(workdir), "utf8");
    expect(onDisk).toBe(md);
    expect(onDisk).toContain("[P1]");
    expect(onDisk.toLowerCase()).not.toContain("bounty_estimate");
  });
});

// ===========================================================================
// Budget halt (acceptance: clean halt, status budget_exhausted, partial report)
// ===========================================================================

describe("budget — the pure exhaustion decision", () => {
  it("flags each threshold at or above the ceiling", () => {
    const b: Budget = { max_probes: 10, max_llm_calls: 5, max_minutes: 2 };
    expect(exceededBudgets({ probes: 9, llm_calls: 4, minutes: 1 }, b)).toEqual([]);
    expect(exceededBudgets({ probes: 10, llm_calls: 0, minutes: 0 }, b)).toEqual(["max_probes"]);
    expect(exceededBudgets({ probes: 0, llm_calls: 5, minutes: 0 }, b)).toEqual(["max_llm_calls"]);
    expect(exceededBudgets({ probes: 0, llm_calls: 0, minutes: 2 }, b)).toEqual(["max_minutes"]);
    expect(exceededBudgets({ probes: 11, llm_calls: 6, minutes: 3 }, b)).toEqual([
      "max_probes",
      "max_llm_calls",
      "max_minutes",
    ]);
    expect(isBudgetExhausted({ probes: 10, llm_calls: 0, minutes: 0 }, b)).toBe(true);
    expect(isBudgetExhausted({ probes: 0, llm_calls: 0, minutes: 0 }, b)).toBe(false);
  });

  it("generous defaults do not fire on a normal usage", () => {
    expect(isBudgetExhausted({ probes: 100, llm_calls: 50, minutes: 30 }, budget)).toBe(false);
  });
});

describe("budget — the live tracker", () => {
  it("counts probes from the ledger and LLM calls in-process", async () => {
    expect(await countProbes(workdir)).toBe(0);
    await fs.writeFile(
      path.join(workdir, "ledger.jsonl"),
      '{"a":1}\n{"a":2}\n\n{"a":3}\n',
      "utf8",
    );
    expect(await countProbes(workdir)).toBe(3);

    let clock = 0;
    const tracker = new BudgetTracker({
      workdir,
      budget: { max_probes: 5, max_llm_calls: 2, max_minutes: 10 },
      now: () => clock,
      startedAt: 0,
    });
    tracker.recordLlmCall();
    expect(tracker.llmCallCount).toBe(1);
    const snap = await tracker.snapshot();
    expect(snap.probes).toBe(3);
    expect(snap.llm_calls).toBe(1);
    // Predicate reflects the cached probe count + live llm/clock.
    expect(tracker.predicate()()).toBe(false);
    tracker.recordLlmCall();
    expect(tracker.predicate()()).toBe(true); // llm_calls hit 2
  });

  it("predicate fires on wall-clock exhaustion", async () => {
    let clock = 0;
    const tracker = new BudgetTracker({
      workdir,
      budget: { max_probes: 1000, max_llm_calls: 1000, max_minutes: 5 },
      now: () => clock,
      startedAt: 0,
    });
    await tracker.refresh();
    expect(tracker.predicate()()).toBe(false);
    clock = 5 * 60000; // 5 minutes
    expect(tracker.predicate()()).toBe(true);
  });
});

describe("budget — clean halt writes a partial report + marks state", () => {
  it("halts: partial report from confirmed to date, status budget_exhausted, stage preserved", async () => {
    await seedFinding("f-0001", { severity: "high", vuln_class: "idor" });
    await writePassVerdicts(workdir, 1, [confirmed("f-0001")]);
    const s = state({ current_stage: "verify", status: "in_progress" });
    await writeState(workdir, s);

    const halt = await haltForBudget(workdir, s, ["max_probes"]);
    expect(halt.state.status).toBe("budget_exhausted");
    expect(halt.state.current_stage).toBe("verify"); // stage preserved
    expect(halt.exceeded).toEqual(["max_probes"]);
    // The partial report exists and carries the one confirmed finding.
    expect(halt.report).toContain("f-0001");
    expect(await fs.readFile(reportPath(workdir), "utf8")).toContain("f-0001");
    // state.json on disk reflects the halt.
    const reread = await readState(workdir);
    expect(reread.status).toBe("budget_exhausted");
  });
});

// ===========================================================================
// Resume — the stage gate (acceptance: resume from each of the 8 stages)
// ===========================================================================

describe("resume — validate against fixture artifact snapshots", () => {
  let cases: { full: ArtifactSnapshot; missing_recon: ArtifactSnapshot; no_candidates: ArtifactSnapshot };
  beforeEach(async () => {
    cases = JSON.parse(await fs.readFile(path.join(fixtureDir, "resume-cases.json"), "utf8"));
  });

  const PIPELINE = STAGES.filter((s) => s !== "halted");

  it("resumes cleanly into every one of the 8 pipeline stages when prior artifacts are present", () => {
    for (const stage of PIPELINE) {
      const plan = validateResume(state({ current_stage: stage }), cases.full);
      expect(plan.resumeStage).toBe(stage);
      if (stage === "done") {
        expect(plan.terminal).toBe(true);
      } else {
        expect(plan.ok, `resume into ${stage} should be clean`).toBe(true);
        expect(plan.missing).toEqual([]);
      }
    }
  });

  it("flags an inconsistent state when a prior stage's artifact is missing", () => {
    // Resume into verify with recon artifacts gone → recon gate fails.
    const plan = validateResume(state({ current_stage: "verify" }), cases.missing_recon);
    expect(plan.ok).toBe(false);
    expect(plan.missing.map((m) => m.stage)).toContain("recon");
    // Resume into recon itself does NOT check recon (it's the in-flight stage).
    const atRecon = validateResume(state({ current_stage: "recon" }), cases.missing_recon);
    expect(atRecon.ok).toBe(true);
  });

  it("satisfies the author/review gates when the sweep produced zero candidates", () => {
    // No findings ⇒ no checklist authored ⇒ author/review gates are vacuously met.
    const plan = validateResume(state({ current_stage: "verify" }), cases.no_candidates);
    expect(plan.ok).toBe(true);
    expect(plan.missing).toEqual([]);
  });

  it("a terminal state resumes to itself with nothing to run", () => {
    for (const stage of ["done", "halted"] as const) {
      const plan = validateResume(state({ current_stage: stage }), cases.full);
      expect(plan.terminal).toBe(true);
      expect(plan.ok).toBe(true);
    }
  });
});

describe("resume — a checklist-reviewer rejection halts with an operator artifact", () => {
  it("writes halted/checklist-rejection.md and the stage gate treats halted as terminal", async () => {
    const noAns = {
      excludes_documented_exclusions: false,
      distinguishes_public_by_design: true,
      has_impact_gate: true,
      notes: "does not exclude the program's documented public API",
    };
    const file = await writeRejectionReport(workdir, {
      vuln_class: "idor",
      attempt1Checklist: "# idor checklist v1",
      attempt2Checklist: "# idor checklist v2",
      review1: noAns,
      review2: noAns,
    });
    expect(file).toBe(rejectionReportPath(workdir));

    // The operator artifact carries both attempts + both verdicts and the halt.
    const md = await fs.readFile(file, "utf8");
    expect(md).toContain("Checklist rejected — engagement halted");
    expect(md).toContain("Attempt 1 — Author");
    expect(md).toContain("Attempt 2 — Author (rewrite with Reviewer feedback)");
    expect(md).toContain("NO");

    // The engagement halts at `author` with status `halted`; the stage gate does
    // not try to resume a terminal state.
    const halted = state({ current_stage: "halted", status: "halted" });
    await writeState(workdir, halted);
    const snap = await collectArtifacts(workdir);
    const plan = validateResume(halted, snap);
    expect(plan.terminal).toBe(true);
    expect(plan.ok).toBe(true);
  });
});

describe("resume — collectArtifacts reads the real workdir", () => {
  it("reflects findings + verdicts written to disk", async () => {
    const empty = await collectArtifacts(workdir);
    expect(empty.findingsCount).toBe(0);
    expect(empty.verdictPasses).toBe(0);
    expect(empty.hasReport).toBe(false);

    await seedFinding("f-0001");
    await seedFinding("f-0002");
    await writePassVerdicts(workdir, 1, [confirmed("f-0001")]);
    await writeReport(workdir, state());

    const snap = await collectArtifacts(workdir);
    expect(snap.findingsCount).toBe(2);
    expect(snap.verdictPasses).toBe(1);
    expect(snap.hasReport).toBe(true);
  });
});

// ===========================================================================
// In-flight re-run does not double-fire probes (dedupe holds across resume)
// ===========================================================================

describe("resume — re-running an in-flight stage does not double-fire", () => {
  it("a fresh firer that re-reads the persisted ledger refuses the repeat probe", async () => {
    const probe: ProbeRequest = {
      endpoint: "https://juice.test/api/Users/1",
      method: "GET",
      payload_id: "p1",
      payload: { id: 1 },
      session: "userA",
    };
    const transport = async () => ({ status: "200", trigger_match: false });

    // First run (pre-crash): fire the probe, it lands in ledger.jsonl.
    const ledger1 = await readLedger(workdir);
    const fire1 = createProbeFirer({
      workdir,
      pass: 0,
      agent: "idor",
      surface: "api",
      vuln_class: "idor",
      ledger: ledger1,
      takeToken: async () => true,
      transport,
    });
    expect((await fire1(probe)).fired).toBe(true);
    expect(await countProbes(workdir)).toBe(1);

    // Resume: a BRAND NEW firer re-reads the persisted ledger from disk. The
    // same 3-tuple is refused as a duplicate — the target is not hit twice.
    const ledger2 = await readLedger(workdir);
    expect(ledger2).toHaveLength(1);
    const fire2 = createProbeFirer({
      workdir,
      pass: 1,
      agent: "idor",
      surface: "api",
      vuln_class: "idor",
      ledger: ledger2,
      takeToken: async () => true,
      transport,
    });
    const second = await fire2(probe);
    expect(second.fired).toBe(false);
    expect(second.fired === false && second.reason).toBe("duplicate");
    expect(await countProbes(workdir)).toBe(1); // still one line — no double fire
  });
});

// ===========================================================================
// Status (acceptance: shows real engagement state)
// ===========================================================================

describe("status — real engagement state", () => {
  it("reports stage, pass, findings, hypotheses, and probe budget usage", async () => {
    const s = state({ current_stage: "verify", current_pass: 2 });
    await writeState(workdir, s);
    await seedFinding("f-0001");
    await fs.writeFile(path.join(workdir, "ledger.jsonl"), '{"a":1}\n{"a":2}\n', "utf8");

    const status = await collectStatus(workdir, s, budget);
    expect(status.stage).toBe("verify");
    expect(status.pass).toBe(2);
    expect(status.findings_count).toBe(1);
    expect(status.budget.probes).toBe(2);
    expect(status.budget.max_probes).toBe(budget.max_probes);

    const rendered = formatStatus(status);
    expect(rendered).toContain("stage:       verify  (pass 2)");
    expect(rendered).toContain("2/" + budget.max_probes + " probes");
  });
});
