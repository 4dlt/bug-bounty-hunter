import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ScopeSchema,
  loadScope,
  matchesGlob,
  checkScope,
  scopedFetch,
  coverageGapLogger,
  ScopeError,
  type Scope,
  type CoverageGap,
} from "../src/scope.ts";

const scopeOf = (over: Partial<Scope> = {}): Scope =>
  ScopeSchema.parse({ target: "juice-shop.local", ...over });

describe("ScopeSchema", () => {
  it("parses the minimal target-only scope with generous defaults", () => {
    const s = ScopeSchema.parse({ target: "juice-shop.local" });
    expect(s.scope).toEqual([]);
    expect(s.out_of_scope).toEqual([]);
    expect(s.min_payout_band).toBe("P3");
    expect(s.budget.max_probes).toBe(10000);
    expect(s.auth.method).toBe("form");
  });

  it("parses a full scope with glob lists and an auth block", () => {
    const s = ScopeSchema.parse({
      target: "http://localhost:3000",
      scope: ["*.target.com", "api.target.com"],
      out_of_scope: ["blog.target.com"],
      auth: {
        method: "form",
        login_url: "http://localhost:3000/#/login",
        username: "test@example.com",
        password: "hunter2",
      },
      min_payout_band: "P2",
    });
    expect(s.scope).toContain("api.target.com");
    expect(s.out_of_scope).toContain("blog.target.com");
    expect(s.auth.username).toBe("test@example.com");
    expect(s.min_payout_band).toBe("P2");
  });

  it("rejects a scope with no target, with a helpful message", () => {
    const res = ScopeSchema.safeParse({ scope: ["*.target.com"] });
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(JSON.stringify(res.error.issues)).toMatch(/target/);
    }
  });
});

describe("loadScope", () => {
  it("parses YAML text into a validated Scope", () => {
    const yaml = `
target: http://localhost:3000
scope:
  - "*.target.com"
out_of_scope:
  - blog.target.com
auth:
  method: form
  login_url: http://localhost:3000/#/login
  username: test@example.com
  password: hunter2
min_payout_band: P3
budget:
  max_probes: 500
`;
    const s = loadScope(yaml);
    expect(s.target).toBe("http://localhost:3000");
    expect(s.scope).toEqual(["*.target.com"]);
    expect(s.budget.max_probes).toBe(500);
    expect(s.budget.max_minutes).toBe(480); // default preserved
  });

  it("throws a helpful error for malformed YAML", () => {
    expect(() => loadScope("target: [unclosed")).toThrow(/scope\.yaml/i);
  });

  it("throws a helpful error when the schema is violated", () => {
    expect(() => loadScope("scope:\n  - a.com\n")).toThrow(/target/i);
  });
});

describe("matchesGlob", () => {
  it("matches an exact host", () => {
    expect(matchesGlob("api.target.com", "api.target.com")).toBe(true);
    expect(matchesGlob("api.target.com", "www.target.com")).toBe(false);
  });

  it("matches a wildcard subdomain glob", () => {
    expect(matchesGlob("api.target.com", "*.target.com")).toBe(true);
    expect(matchesGlob("a.b.target.com", "*.target.com")).toBe(true);
    expect(matchesGlob("target.com", "*.target.com")).toBe(false);
  });

  it("is case-insensitive and does not treat dots as wildcards", () => {
    expect(matchesGlob("API.Target.COM", "api.target.com")).toBe(true);
    expect(matchesGlob("apiXtarget.com", "api.target.com")).toBe(false);
  });
});

describe("checkScope", () => {
  it("allows a host that matches an in-scope glob", () => {
    const s = scopeOf({ scope: ["*.target.com"] });
    expect(checkScope(s, "https://api.target.com/x")).toEqual({ allowed: true });
  });

  it("falls back to the target host when no scope globs are given", () => {
    const s = scopeOf({ target: "http://localhost:3000" });
    expect(checkScope(s, "http://localhost:3000/rest/products").allowed).toBe(
      true,
    );
    expect(checkScope(s, "http://evil.com/x").allowed).toBe(false);
  });

  it("hard-blocks an out-of-scope host even if it also matches in-scope", () => {
    const s = scopeOf({
      scope: ["*.target.com"],
      out_of_scope: ["blog.target.com"],
    });
    const d = checkScope(s, "https://blog.target.com/x");
    expect(d.allowed).toBe(false);
    if (!d.allowed) expect(d.reason).toBe("out_of_scope");
  });

  it("blocks a host that matches nothing", () => {
    const s = scopeOf({ scope: ["*.target.com"] });
    const d = checkScope(s, "https://other.example/x");
    expect(d.allowed).toBe(false);
    if (!d.allowed) expect(d.reason).toBe("not_in_scope");
  });

  it("blocks an unparseable URL rather than allowing it", () => {
    const s = scopeOf({ scope: ["*.target.com"] });
    const d = checkScope(s, "not a url");
    expect(d.allowed).toBe(false);
  });
});

describe("scopedFetch", () => {
  it("delegates to the underlying fetch for an in-scope URL", async () => {
    const s = scopeOf({ scope: ["*.target.com"] });
    const calls: string[] = [];
    const fakeFetch = async (u: string | URL) => {
      calls.push(String(u));
      return new Response("ok");
    };
    const res = await scopedFetch(s, "https://api.target.com/x", undefined, {
      fetch: fakeFetch as typeof fetch,
    });
    expect(await res.text()).toBe("ok");
    expect(calls).toEqual(["https://api.target.com/x"]);
  });

  it("blocks an out-of-scope URL, logs a coverage_gap, and never fetches", async () => {
    const s = scopeOf({ scope: ["*.target.com"] });
    let fetched = false;
    const gaps: CoverageGap[] = [];
    await expect(
      scopedFetch(s, "https://evil.com/x", undefined, {
        fetch: (async () => {
          fetched = true;
          return new Response("");
        }) as typeof fetch,
        onCoverageGap: (g) => gaps.push(g),
      }),
    ).rejects.toBeInstanceOf(ScopeError);
    expect(fetched).toBe(false);
    expect(gaps).toHaveLength(1);
    expect(gaps[0]!.kind).toBe("coverage_gap");
    expect(gaps[0]!.url).toBe("https://evil.com/x");
    expect(gaps[0]!.reason).toBe("not_in_scope");
  });
});

describe("coverageGapLogger", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-gap-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("appends each blocked request as one jsonl line", async () => {
    const log = coverageGapLogger(dir);
    await log({ kind: "coverage_gap", url: "https://a.com", host: "a.com", reason: "not_in_scope" });
    await log({ kind: "coverage_gap", url: "https://b.com", host: "b.com", reason: "out_of_scope" });
    const lines = (await fs.readFile(path.join(dir, "coverage-gaps.jsonl"), "utf8"))
      .trim()
      .split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[1]!).reason).toBe("out_of_scope");
  });
});
