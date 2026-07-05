import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ScopeSchema, type Scope } from "../src/scope.ts";
import { writeFinding, findingsDir, HunterFindingSchema, type HunterFinding } from "../src/hunters/framework.ts";
import {
  runAuthor,
  readFindings,
  groupFindingsByClass,
  checklistPath,
  readChecklist,
  AUTHOR_SAMPLE,
  type AuthorRunner,
  type FindingMeta,
} from "../src/checklist/author.ts";
import {
  reviewChecklist,
  writeApproval,
  readApproval,
  approvalPath,
  allYes,
  feedbackFrom,
  ReviewAnswersSchema,
  REVIEWER_SAMPLE,
  type ReviewerRunner,
  type ReviewAnswers,
} from "../src/checklist/reviewer.ts";
import {
  runChecklistStage,
  rejectionReportPath,
  type RunChecklistStageOptions,
} from "../src/checklist/stage.ts";
import { transition, initialState, type State } from "../src/state.ts";

const scope: Scope = ScopeSchema.parse({ target: "https://juice.test" });

let workdir: string;
beforeEach(async () => {
  workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-checklist-"));
});
afterEach(async () => {
  await fs.rm(workdir, { recursive: true, force: true });
});

// --- helpers ---------------------------------------------------------------

const finding = (over: Partial<HunterFinding> & Pick<HunterFinding, "vuln_class">): HunterFinding =>
  HunterFindingSchema.parse({
    title: `${over.vuln_class} candidate`,
    severity: "medium",
    endpoint: "https://juice.test/api/Users/1",
    method: "GET",
    poc: "curl https://juice.test/api/Users/1",
    ...over,
  });

/** Seed a finding on disk under findings/<id>/. */
async function seedFinding(id: string, f: HunterFinding): Promise<void> {
  await writeFinding(workdir, id, f);
}

const yes: ReviewAnswers = {
  excludes_documented_exclusions: true,
  distinguishes_public_by_design: true,
  has_impact_gate: true,
  notes: "",
};
const noExclusions: ReviewAnswers = { ...yes, excludes_documented_exclusions: false };

/** Author stub: returns a fixed checklist, echoing feedback when present. */
const authorStub: AuthorRunner = async (input) =>
  [
    `# ${input.vuln_class} checklist`,
    input.feedback && input.feedback.length ? `Addressed: ${input.feedback.join("; ")}` : "initial",
  ].join("\n");

/** Reviewer stub that returns a fixed answer set. */
const reviewerReturning = (...answers: ReviewAnswers[]): ReviewerRunner => {
  let i = 0;
  return async () => answers[Math.min(i++, answers.length - 1)]!;
};

// --- readFindings / grouping ----------------------------------------------

describe("readFindings + groupFindingsByClass", () => {
  it("reads finding.json metadata and groups by vuln class", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await seedFinding("f-0002", finding({ vuln_class: "idor" }));
    await seedFinding("f-0003", finding({ vuln_class: "sqli" }));

    const found = await readFindings(workdir);
    expect(found.map((f) => f.id)).toEqual(["f-0001", "f-0002", "f-0003"]);

    const byClass = groupFindingsByClass(found);
    expect(byClass.get("idor")!.length).toBe(2);
    expect(byClass.get("sqli")!.length).toBe(1);
  });

  it("returns [] when there are no findings", async () => {
    expect(await readFindings(workdir)).toEqual([]);
  });

  it("skips a half-written finding.json instead of crashing", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    // A truncated finding.json (crashed mid-write) must be skipped, not thrown.
    const halfWritten = path.join(findingsDir(workdir), "f-0002", "finding.json");
    await fs.mkdir(path.dirname(halfWritten), { recursive: true });
    await fs.writeFile(halfWritten, '{"id": "f-0002", "title": "trunc', "utf8");

    const found = await readFindings(workdir);
    expect(found.map((f) => f.id)).toEqual(["f-0001"]);
  });
});

// --- Author: only classes with candidates ---------------------------------

describe("runAuthor (Stage 3.5)", () => {
  it("writes checklists/<class>.md only for classes with a Tier 1 candidate", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await seedFinding("f-0002", finding({ vuln_class: "sqli" }));

    const out = await runAuthor(workdir, { runner: authorStub, scope });
    expect(out.authored).toEqual(["idor", "sqli"]);

    expect(await readChecklist(workdir, "idor")).toContain("# idor checklist");
    expect(await readChecklist(workdir, "sqli")).toContain("# sqli checklist");
    // xss had no candidate -> no checklist.
    await expect(fs.access(checklistPath(workdir, "xss"))).rejects.toThrow();
  });

  it("caps the sample handed to the Author at AUTHOR_SAMPLE", async () => {
    for (let i = 1; i <= AUTHOR_SAMPLE + 3; i += 1) {
      await seedFinding(`f-${String(i).padStart(4, "0")}`, finding({ vuln_class: "idor" }));
    }
    let seen = -1;
    const spy: AuthorRunner = async (input) => {
      seen = input.findings.length;
      return "# idor";
    };
    await runAuthor(workdir, { runner: spy, scope });
    expect(seen).toBe(AUTHOR_SAMPLE);
  });

  it("NEVER writes an approval.json (structural rule: Author owns only checklists)", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await runAuthor(workdir, { runner: authorStub, scope });
    await expect(fs.access(approvalPath(workdir, "idor"))).rejects.toThrow();
  });
});

// --- Reviewer answers + approval writer -----------------------------------

describe("reviewChecklist + approval", () => {
  it("approves only when all three answers are YES", async () => {
    const approved = await reviewChecklist("idor", {
      runner: reviewerReturning(yes),
      scope,
      checklist: "# idor",
      findings: [],
    });
    expect(approved.approved).toBe(true);

    const rejected = await reviewChecklist("idor", {
      runner: reviewerReturning(noExclusions),
      scope,
      checklist: "# idor",
      findings: [],
    });
    expect(rejected.approved).toBe(false);
    expect(allYes(rejected.answers)).toBe(false);
  });

  it("caps the sample shown to the Reviewer at REVIEWER_SAMPLE", async () => {
    const many: FindingMeta[] = Array.from({ length: 5 }, (_v, i) => ({
      id: `f-${i}`,
      title: "t",
      severity: "low",
      vuln_class: "idor",
      endpoint: "https://juice.test/x",
      method: "GET",
    }));
    let seen = -1;
    const spy: ReviewerRunner = async (input) => {
      seen = input.findings.length;
      return yes;
    };
    await reviewChecklist("idor", { runner: spy, scope, checklist: "#", findings: many });
    expect(seen).toBe(REVIEWER_SAMPLE);
  });

  it("writeApproval round-trips and is the reviewer's only artifact", async () => {
    await writeApproval(workdir, { class: "idor", approved: true, attempt: 1, answers: yes });
    const back = await readApproval(workdir, "idor");
    expect(back).toEqual({ class: "idor", approved: true, attempt: 1, answers: yes });
    // no checklist was created by the reviewer writer.
    await expect(fs.access(checklistPath(workdir, "idor"))).rejects.toThrow();
  });

  it("feedbackFrom names each failed criterion", () => {
    const fb = feedbackFrom({ ...yes, excludes_documented_exclusions: false, has_impact_gate: false, notes: "be specific" });
    expect(fb.some((l) => /Q1 NO/.test(l))).toBe(true);
    expect(fb.some((l) => /Q3 NO/.test(l))).toBe(true);
    expect(fb.some((l) => /be specific/.test(l))).toBe(true);
    expect(fb.some((l) => /Q2 NO/.test(l))).toBe(false);
  });
});

// --- Full stage routing ----------------------------------------------------

describe("runChecklistStage (Stages 3.5 + 3.6 routing)", () => {
  it("all-YES: freezes the checklist, writes approved:true, advances", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    const out = await runChecklistStage(workdir, {
      authorRunner: authorStub,
      reviewerRunner: reviewerReturning(yes),
      scope,
    });

    expect(out.halted).toBe(false);
    expect(out.event).toEqual({ type: "advance" });
    expect(out.reviews).toEqual([
      { class: "idor", approved: true, attempts: 1, answers: yes },
    ]);
    const approval = await readApproval(workdir, "idor");
    expect(approval.approved).toBe(true);
    // frozen: the checklist is the attempt-1 content (no rewrite happened).
    expect(await readChecklist(workdir, "idor")).toContain("initial");
  });

  it("first-rejection then YES: exactly one Author rewrite with the NO answers as feedback", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    let authorCalls = 0;
    const countingAuthor: AuthorRunner = async (input) => {
      authorCalls += 1;
      return input.feedback?.length ? `# idor\nrewrote: ${input.feedback.join("|")}` : "# idor\ninitial";
    };
    const out = await runChecklistStage(workdir, {
      authorRunner: countingAuthor,
      reviewerRunner: reviewerReturning(noExclusions, yes),
      scope,
    });

    expect(out.halted).toBe(false);
    expect(out.event).toEqual({ type: "advance" });
    expect(authorCalls).toBe(2); // initial + exactly one rewrite
    expect(out.reviews[0]!.attempts).toBe(2);
    // the rewrite saw the Q1 feedback
    const checklist = await readChecklist(workdir, "idor");
    expect(checklist).toMatch(/rewrote: .*Q1 NO/);
    expect((await readApproval(workdir, "idor")).approved).toBe(true);
  });

  it("second-attempt rejection: halts cleanly with approved:false + operator report", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    const out = await runChecklistStage(workdir, {
      authorRunner: authorStub,
      // Reviewer keeps saying NO (missing exclusions) even after the rewrite.
      reviewerRunner: reviewerReturning(noExclusions),
      scope,
    });

    expect(out.halted).toBe(true);
    expect(out.event.type).toBe("halt");
    const approval = await readApproval(workdir, "idor");
    expect(approval.approved).toBe(false);
    expect(approval.attempt).toBe(2);

    // operator-facing artifact contains BOTH author attempts + reviewer notes.
    const reportPath = rejectionReportPath(workdir);
    expect(out.rejectionReport).toBe(reportPath);
    const report = await fs.readFile(reportPath, "utf8");
    expect(report).toContain("Attempt 1 — Author");
    expect(report).toContain("Attempt 2 — Author");
    expect(report).toContain("halted");
  });

  it("halts on the FIRST failing class and does not review later classes", async () => {
    await seedFinding("f-0001", finding({ vuln_class: "idor" }));
    await seedFinding("f-0002", finding({ vuln_class: "sqli" }));
    // idor (sorted first) fails twice -> halt before sqli is reviewed.
    const out = await runChecklistStage(workdir, {
      authorRunner: authorStub,
      reviewerRunner: reviewerReturning(noExclusions),
      scope,
    });
    expect(out.halted).toBe(true);
    expect(out.reviews.map((r) => r.class)).toEqual(["idor"]);
    // sqli never got an approval verdict.
    await expect(fs.access(approvalPath(workdir, "sqli"))).rejects.toThrow();
  });

  it("no candidates: authors nothing and advances (event advance)", async () => {
    const out = await runChecklistStage(workdir, {
      authorRunner: authorStub,
      reviewerRunner: reviewerReturning(yes),
      scope,
    });
    expect(out.authored).toEqual([]);
    expect(out.halted).toBe(false);
    expect(out.event).toEqual({ type: "advance" });
  });
});

// --- State transitions -----------------------------------------------------

describe("state transitions author -> review -> verify / halted", () => {
  const at = (stage: State["current_stage"]): State => ({
    ...initialState("e", "https://juice.test"),
    current_stage: stage,
  });

  it("full approval walks author -> review -> verify", () => {
    const review = transition(at("author"), { type: "advance" });
    expect(review.current_stage).toBe("review");
    const verify = transition(review, { type: "advance" });
    expect(verify.current_stage).toBe("verify");
  });

  it("second-attempt rejection halts from review", () => {
    const halted = transition(at("review"), { type: "halt", reason: "checklist rejected" });
    expect(halted.current_stage).toBe("halted");
    expect(halted.status).toBe("halted");
  });
});

// --- Structural rule: separate modules, no cross-imports -------------------

describe("structural rule — role modules cannot edit each other's output", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const src = (f: string) => path.resolve(here, "..", "src", "checklist", f);

  it("author.ts does not import reviewer.ts nor call an approval writer", async () => {
    const source = await fs.readFile(src("author.ts"), "utf8");
    expect(source).not.toMatch(/from ["'].*reviewer/);
    // never references the Reviewer's writer/path helpers (comments aside, the
    // symbols simply do not appear in this module).
    expect(source).not.toMatch(/writeApproval|approvalPath|readApproval/);
  });

  it("reviewer.ts does not import the Author's checklist writer", async () => {
    const source = await fs.readFile(src("reviewer.ts"), "utf8");
    // It never references the Author's writers.
    expect(source).not.toMatch(/writeChecklist|authorChecklist|runAuthor/);
    // Any import it does take from ./author is TYPE-ONLY (erased at runtime), so
    // no runtime coupling to the other role exists.
    for (const line of source.split("\n")) {
      if (/from ["']\.\/author/.test(line)) {
        expect(line).toMatch(/import type/);
      }
    }
  });

  it("the answer schema pins exactly the three yes/no questions", () => {
    const keys = Object.keys(ReviewAnswersSchema.shape).sort();
    expect(keys).toEqual([
      "distinguishes_public_by_design",
      "excludes_documented_exclusions",
      "has_impact_gate",
      "notes",
    ]);
  });
});
