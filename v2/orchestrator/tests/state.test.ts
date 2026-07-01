import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  transition,
  initialState,
  readState,
  writeState,
  StateSchema,
  ScopeSchema,
  STAGES,
  type State,
} from "../src/state.ts";

const base = (over: Partial<State> = {}): State => ({
  ...initialState("eng-1", "juice-shop.local"),
  ...over,
});

describe("transition — advance", () => {
  it("walks the full pipeline auth -> done", () => {
    const order = [
      "auth",
      "recon",
      "plan",
      "sweep",
      "author",
      "review",
      "verify",
      "report",
      "done",
    ];
    let s = base();
    for (let i = 1; i < order.length; i++) {
      s = transition(s, { type: "advance" });
      expect(s.current_stage).toBe(order[i]);
    }
    expect(s.status).toBe("done");
  });

  it("does not mutate the input state", () => {
    const s = base();
    const next = transition(s, { type: "advance" });
    expect(s.current_stage).toBe("auth");
    expect(next.current_stage).toBe("recon");
  });

  it("refuses to advance past a terminal stage", () => {
    const s = base({ current_stage: "done", status: "done" });
    expect(() => transition(s, { type: "advance" })).toThrow();
  });
});

describe("transition — loop", () => {
  it("re-queues verify back to sweep and bumps the pass counter", () => {
    const s = base({ current_stage: "verify", current_pass: 0 });
    const next = transition(s, { type: "loop" });
    expect(next.current_stage).toBe("sweep");
    expect(next.current_pass).toBe(1);
  });

  it("rejects loop from any stage other than verify", () => {
    const s = base({ current_stage: "plan" });
    expect(() => transition(s, { type: "loop" })).toThrow(/verify/);
  });
});

describe("transition — halt", () => {
  it("moves to the halted stage from mid-pipeline", () => {
    const s = base({ current_stage: "sweep" });
    const next = transition(s, { type: "halt", reason: "budget" });
    expect(next.current_stage).toBe("halted");
    expect(next.status).toBe("halted");
  });

  it("is idempotent once halted", () => {
    const s = base({ current_stage: "halted", status: "halted" });
    expect(transition(s, { type: "halt", reason: "again" })).toEqual(s);
  });
});

describe("StateSchema", () => {
  it("covers every stage in the enum", () => {
    for (const stage of STAGES) {
      expect(() =>
        StateSchema.parse(base({ current_stage: stage })),
      ).not.toThrow();
    }
  });

  it("rejects an unknown stage", () => {
    const bad = { ...base(), current_stage: "bogus" };
    expect(() => StateSchema.parse(bad)).toThrow();
  });
});

describe("ScopeSchema", () => {
  it("applies generous default budgets", () => {
    const scope = ScopeSchema.parse({ target: "juice-shop.local" });
    expect(scope.budget.max_probes).toBe(10000);
    expect(scope.budget.max_llm_calls).toBe(2000);
    expect(scope.budget.max_minutes).toBe(480);
    expect(scope.min_payout_band).toBe("P3");
  });
});

describe("persistence round-trip", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-state-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("writes and re-reads state.json through the Zod schema", async () => {
    const s = base({ current_stage: "verify", current_pass: 2 });
    await writeState(dir, s);
    const back = await readState(dir);
    expect(back).toEqual(s);
  });

  it("creates the workdir if missing", async () => {
    const nested = path.join(dir, "a", "b");
    const s = base();
    await writeState(nested, s);
    expect(await readState(nested)).toEqual(s);
  });
});
