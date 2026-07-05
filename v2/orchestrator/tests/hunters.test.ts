import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  renderTemplate,
  templateVars,
  loadHunterPrompt,
  renderHunterPrompt,
  createProbeFirer,
  writeFinding,
  findingDir,
  nextFindingSeq,
  runHunter,
  HunterFindingSchema,
  HUNTER_CLASSES,
  HUNTER_CLASS_ALIASES,
  resolveHunterClass,
  hunterPromptExists,
  type ProbeRequest,
  type ProbeTransport,
  type HunterContext,
  type HunterRunner,
  type HunterFinding,
  type Payload,
} from "../src/hunters/framework.ts";
import { readLedger, type LedgerEntry } from "../src/hunters/ledger.ts";
import { ScopeSchema, type Scope } from "../src/scope.ts";

// A second, agent-owned framework spec that mirrors the harness reference so the
// Tier 1 framework has stable coverage under our control (see the slice notes on
// the externally-managed `framework.test.ts`).

const scope: Scope = ScopeSchema.parse({
  target: "https://juice.test",
  auth: { username: "userA@test", password: "x" },
});
const fixedClock = () => "2026-07-03T12:00:00.000Z";
const payloads: Payload[] = [
  { id: "idor-decrement", value: { op: "decrement-id" } },
  { id: "idor-seq", value: { op: "sequential-scan" } },
];

describe("renderTemplate / templateVars", () => {
  it("substitutes {{var}} (inner whitespace tolerated)", () => {
    expect(renderTemplate("hunt {{class}} on {{ surface }}", { class: "idor", surface: "rest" })).toBe(
      "hunt idor on rest",
    );
  });

  it("throws naming every missing variable (no silent blanks)", () => {
    let msg = "";
    try {
      renderTemplate("{{a}} {{b}} {{c}}", { b: "2" });
    } catch (err) {
      msg = (err as Error).message;
    }
    expect(msg).toMatch(/missing variable/i);
    expect(msg).toContain("a");
    expect(msg).toContain("c");
  });

  it("lists the unique variables a template needs", () => {
    expect(templateVars("{{a}} {{b}} {{a}}")).toEqual(["a", "b"]);
  });
});

describe("loadHunterPrompt / renderHunterPrompt", () => {
  it("loads the shipped idor prompt", async () => {
    expect((await loadHunterPrompt("idor")).toLowerCase()).toContain("idor");
  });

  it("errors clearly for an unknown class", async () => {
    await expect(loadHunterPrompt("no-such-class")).rejects.toThrow(/no-such-class/);
  });

  it("renders the idor prompt with every placeholder filled", async () => {
    const tmpl = await loadHunterPrompt("idor");
    const vars: Record<string, string> = {
      surface: "rest",
      vuln_class: "idor",
      session: "userA",
      pass: "0",
      endpoints: "/rest/basket/1",
      payloads: "idor-seq",
      already_tried: "(none)",
    };
    for (const name of templateVars(tmpl)) if (!(name in vars)) vars[name] = "x";
    const rendered = await renderHunterPrompt("idor", vars);
    expect(rendered).toContain("rest");
    expect(rendered).not.toMatch(/\{\{.*?\}\}/);
  });
});

describe("hunter class registry", () => {
  it("ships all 13 Tier 1 hunter prompts and they load without error", async () => {
    expect(HUNTER_CLASSES).toHaveLength(13);
    for (const cls of HUNTER_CLASSES) {
      const prompt = await loadHunterPrompt(cls);
      // Every prompt renders with the standard cell vars and has no dangling {{var}}.
      const vars: Record<string, string> = {};
      for (const name of templateVars(prompt)) vars[name] = "x";
      expect(renderTemplate(prompt, vars)).not.toMatch(/\{\{\s*[\w.]+\s*\}\}/);
    }
  });

  it("resolves the Plan agent's coarser class names onto a concrete hunter", () => {
    expect(resolveHunterClass("xss")).toBe("xss_reflected");
    expect(resolveHunterClass("auth")).toBe("auth_bypass");
    expect(resolveHunterClass("path_traversal")).toBe("lfi");
    // An unaliased class resolves to itself.
    expect(resolveHunterClass("idor")).toBe("idor");
    // Every alias target is a real hunter class.
    for (const target of Object.values(HUNTER_CLASS_ALIASES)) {
      expect(HUNTER_CLASSES).toContain(target);
    }
  });

  it("hunterPromptExists follows resolution and is false for an unbuilt class", async () => {
    expect(await hunterPromptExists("idor")).toBe(true);
    expect(await hunterPromptExists("xss")).toBe(true); // -> xss_reflected.md
    expect(await hunterPromptExists("csrf")).toBe(false); // no hunter built
  });
});

describe("createProbeFirer", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-fire-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const cfg = (over: Partial<Parameters<typeof createProbeFirer>[0]> = {}) => ({
    workdir: dir,
    pass: 0,
    agent: "H-idor",
    surface: "rest",
    vuln_class: "idor",
    ledger: [] as LedgerEntry[],
    takeToken: async () => true,
    transport: (async () => ({ status: "200", trigger_match: false })) as ProbeTransport,
    now: fixedClock,
    ...over,
  });
  const probe = (over: Partial<ProbeRequest> = {}): ProbeRequest => ({
    endpoint: "/rest/basket/2",
    method: "GET",
    payload_id: "idor-seq",
    payload: { basketId: 2 },
    session: "userA",
    ...over,
  });

  it("fires a novel probe and appends it to the ledger", async () => {
    let fired = 0;
    const fire = createProbeFirer(cfg({ transport: async () => (fired++, { status: "200", trigger_match: false }) }));
    const out = await fire(probe());
    expect(out.fired).toBe(true);
    expect(fired).toBe(1);
    const ledger = await readLedger(dir);
    expect(ledger).toHaveLength(1);
    expect(ledger[0]!.context.session).toBe("userA");
  });

  it("refuses a duplicate WITHOUT touching the transport", async () => {
    let fired = 0;
    const fire = createProbeFirer(cfg({ transport: async () => (fired++, { status: "200", trigger_match: false }) }));
    await fire(probe());
    const out = await fire(probe());
    expect(out).toEqual({ fired: false, reason: "duplicate" });
    expect(fired).toBe(1);
    expect(await readLedger(dir)).toHaveLength(1);
  });

  it("a mutated payload is novel and fires", async () => {
    let fired = 0;
    const fire = createProbeFirer(cfg({ transport: async () => (fired++, { status: "200", trigger_match: false }) }));
    await fire(probe({ payload: { basketId: 2 } }));
    await fire(probe({ payload: { basketId: 3 } }));
    expect(fired).toBe(2);
  });

  it("refuses when the token is denied and appends nothing", async () => {
    let fired = 0;
    const fire = createProbeFirer(
      cfg({ takeToken: async () => false, transport: async () => (fired++, { status: "200", trigger_match: false }) }),
    );
    const out = await fire(probe());
    expect(out).toEqual({ fired: false, reason: "rate_limited" });
    expect(fired).toBe(0);
    expect(await readLedger(dir)).toHaveLength(0);
  });
});

describe("writeFinding", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-find-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const finding: HunterFinding = HunterFindingSchema.parse({
    title: "Cross-tenant read on /api/Users/{id}",
    severity: "high",
    endpoint: "/api/Users/2",
    method: "GET",
    vuln_class: "idor",
    poc: 'curl -s "$TARGET/api/Users/2"',
    response: { data: { email: "victim@test" } },
    evidence: { "note.txt": "email leaked", "../escape.txt": "basename-only please" },
  });

  it("writes an executable poc.sh with a shebang", async () => {
    await writeFinding(dir, "f-0001", finding);
    const pocPath = path.join(findingDir(dir, "f-0001"), "poc.sh");
    const body = await fs.readFile(pocPath, "utf8");
    expect(body.startsWith("#!")).toBe(true);
    expect(body).toContain("curl");
    expect((await fs.stat(pocPath)).mode & 0o100).toBeTruthy();
  });

  it("preserves a caller shebang instead of double-wrapping", async () => {
    const withShebang = HunterFindingSchema.parse({ ...finding, poc: "#!/usr/bin/env bash\necho hi\n" });
    await writeFinding(dir, "f-0009", withShebang);
    const body = await fs.readFile(path.join(findingDir(dir, "f-0009"), "poc.sh"), "utf8");
    expect((body.match(/#!/g) ?? []).length).toBe(1);
  });

  it("writes response.json + finding.json metadata", async () => {
    await writeFinding(dir, "f-0001", finding);
    const fdir = findingDir(dir, "f-0001");
    expect(await fs.readFile(path.join(fdir, "response.json"), "utf8")).toContain("victim@test");
    const meta = JSON.parse(await fs.readFile(path.join(fdir, "finding.json"), "utf8"));
    expect(meta).toMatchObject({ id: "f-0001", vuln_class: "idor", endpoint: "/api/Users/2", poc: "poc.sh" });
  });

  it("writes evidence basename-only (no path traversal)", async () => {
    await writeFinding(dir, "f-0001", finding);
    const names = await fs.readdir(path.join(findingDir(dir, "f-0001"), "evidence"));
    expect(names).toContain("note.txt");
    expect(names).toContain("escape.txt");
    await expect(fs.stat(path.join(dir, "escape.txt"))).rejects.toThrow();
  });

  it("rejects a finding with no poc", () => {
    expect(() => HunterFindingSchema.parse({ ...finding, poc: "" })).toThrow();
  });
});

describe("nextFindingSeq", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-seq-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("is 1 on empty and continues past existing findings", async () => {
    expect(await nextFindingSeq(dir)).toBe(1);
    await fs.mkdir(path.join(dir, "findings", "f-0003"), { recursive: true });
    await fs.mkdir(path.join(dir, "findings", "f-0007"), { recursive: true });
    expect(await nextFindingSeq(dir)).toBe(8);
  });
});

describe("runHunter", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-hunt-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const runner: HunterRunner = async (ctx) => {
    const findings: HunterFinding[] = [];
    for (const endpoint of ctx.endpoints) {
      const out = await ctx.fire({
        endpoint,
        method: "GET",
        payload_id: "idor-decrement",
        payload: { endpoint },
        session: ctx.session,
      });
      if (out.fired && out.result.trigger_match) {
        findings.push(
          HunterFindingSchema.parse({
            title: `IDOR on ${endpoint}`,
            severity: "high",
            endpoint,
            vuln_class: "idor",
            poc: `curl -s "$TARGET${endpoint}"`,
            response: { leaked: true },
          }),
        );
      }
    }
    return { findings };
  };

  const opts = (over: Partial<Parameters<typeof runHunter>[1]> = {}) => ({
    runner,
    scope,
    surface: "api",
    vuln_class: "idor",
    endpoints: ["/api/Users/2", "/api/Users/3"],
    payloads,
    transport: (async (p: ProbeRequest) => ({
      status: "200",
      trigger_match: p.endpoint.endsWith("/2"),
      evidence: "cross-tenant email",
    })) as ProbeTransport,
    now: fixedClock,
    ...over,
  });

  it("fires probes, appends ledger, writes findings/<id>/, defaults session from scope", async () => {
    const out = await runHunter(dir, opts());
    expect(out.probesFired).toBe(2);
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]!.id).toBe("f-0001");
    expect(await fs.readFile(path.join(out.findings[0]!.dir, "poc.sh"), "utf8")).toContain("curl");
    const ledger = await readLedger(dir);
    expect(ledger.map((e) => e.endpoint).sort()).toEqual(["/api/Users/2", "/api/Users/3"]);
    expect(ledger.every((e) => e.context.session === "userA@test")).toBe(true);
  });

  it("re-running re-fires NOTHING (dedupe end-to-end)", async () => {
    let calls = 0;
    const counting: ProbeTransport = async (p) => (calls++, {
      status: "200",
      trigger_match: p.endpoint.endsWith("/2"),
      evidence: "x",
    });
    await runHunter(dir, opts({ transport: counting }));
    const second = await runHunter(dir, opts({ transport: counting }));
    expect(calls).toBe(2);
    expect(second.probesFired).toBe(0);
    expect(second.duplicatesSkipped).toBe(2);
    expect(await readLedger(dir)).toHaveLength(2);
  });

  it("exposes the (surface, class)-scoped ALREADY_TRIED slice", async () => {
    await runHunter(dir, opts());
    let seen: HunterContext["alreadyTried"] = [];
    await runHunter(dir, opts({ runner: async (ctx) => ((seen = ctx.alreadyTried), { findings: [] }) }));
    expect(seen.map((k) => k.endpoint).sort()).toEqual(["/api/Users/2", "/api/Users/3"]);
  });

  it("hands the token source to the hunter context", async () => {
    let took = 0;
    await runHunter(
      dir,
      opts({ runner: async (ctx) => (await ctx.takeToken(), { findings: [] }), takeToken: async () => (took++, true) }),
    );
    expect(took).toBe(1);
  });

  it("surfaces reactive hypotheses, filling an omitted class from the cell", async () => {
    const out = await runHunter(
      dir,
      opts({
        runner: async () => ({
          findings: [],
          hypotheses: [
            { target_endpoint: "/api/Users/2", hypothesis: "sequential ids", signal_evidence: "200 for id 2" },
            { class: "sqli", target_endpoint: "/rest/search", hypothesis: "error leak", signal_evidence: "" },
          ],
        }),
      }),
    );
    // Not stamped/persisted here — that is the sweep's job — but class-filled.
    expect(out.reactiveHypotheses.map((h) => h.class)).toEqual(["idor", "sqli"]);
  });
});
