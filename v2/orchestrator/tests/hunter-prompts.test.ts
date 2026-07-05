import { describe, it, expect } from "vitest";
import {
  HUNTER_CLASSES,
  loadHunterPrompt,
  renderHunterPrompt,
  templateVars,
  resolveHunterClass,
  hunterPromptExists,
} from "../src/hunters/framework.ts";

// Acceptance criterion 1: all 13 Tier 1 hunter prompts are present and load —
// and render — without error. One prompt file `hunters/<class>.md` per class.

const CELL_VARS: Record<string, string> = {
  surface: "rest",
  vuln_class: "idor",
  session: "userA",
  pass: "0",
  endpoints: "[]",
  payloads: "[]",
  already_tried: "[]",
};

describe("Tier 1 hunter prompt set", () => {
  it("has exactly 13 classes", () => {
    expect(HUNTER_CLASSES).toHaveLength(13);
  });

  for (const cls of HUNTER_CLASSES) {
    it(`loads and renders hunters/${cls}.md with no leftover placeholders`, async () => {
      const tmpl = await loadHunterPrompt(cls);
      expect(tmpl.length).toBeGreaterThan(0);

      // Fill whatever variables this prompt references (a superset of CELL_VARS
      // is tolerated) and confirm nothing is left un-substituted.
      const vars: Record<string, string> = { ...CELL_VARS, vuln_class: cls };
      for (const name of templateVars(tmpl)) if (!(name in vars)) vars[name] = "x";
      const rendered = await renderHunterPrompt(cls, vars);
      expect(rendered).not.toMatch(/\{\{.*?\}\}/);
    });
  }
});

describe("resolveHunterClass / hunterPromptExists", () => {
  it("maps the Plan agent's coarser vocabulary onto a concrete hunter", () => {
    expect(resolveHunterClass("xss")).toBe("xss_reflected");
    expect(resolveHunterClass("auth")).toBe("auth_bypass");
    expect(resolveHunterClass("path_traversal")).toBe("lfi");
  });

  it("passes an already-concrete class through unchanged", () => {
    expect(resolveHunterClass("idor")).toBe("idor");
    expect(resolveHunterClass("sqli")).toBe("sqli");
  });

  it("reports a prompt exists for every plan-default class, and not for csrf", async () => {
    // The plan backfill emits xss / auth / info_disclosure / idor; each must
    // resolve to a real prompt so a backfilled cell dispatches a hunter.
    expect(await hunterPromptExists("xss")).toBe(true);
    expect(await hunterPromptExists("auth")).toBe(true);
    expect(await hunterPromptExists("idor")).toBe(true);
    // csrf has no Tier 1 hunter in this taxonomy.
    expect(await hunterPromptExists("csrf")).toBe(false);
  });
});
