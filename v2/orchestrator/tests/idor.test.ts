import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeSchema, ScopeError, type Scope } from "../src/scope.ts";
import { runIdorOracle, type IdorObservation } from "../src/idor/oracle.ts";
import {
  captureSessions,
  createHttpTransport,
  httpProbe,
  loginIdentity,
  resolveUrl,
  extractToken,
  sessionHeaders,
  isAuthenticatedSession,
  decodeProbeEvidence,
  UNAUTH_SESSION,
  type IdentitySession,
} from "../src/idor/transport.ts";
import {
  createIdorHunterRunner,
  buildPocScript,
  IdorProbeSpecSchema,
  type IdorProbeSpec,
} from "../src/idor/probe.ts";
import { createOracleVerifierRunner, ORACLE_EVIDENCE_FILE } from "../src/idor/oracle-verifier.ts";
import { buildTracerSpecs } from "../src/idor/tracer.ts";
import { runHunter } from "../src/hunters/framework.ts";
import { runVerifyStage } from "../src/verify/stage.ts";
import type { PocExecutor } from "../src/verify/refire.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const scopeOf = (over: Partial<Scope> = {}): Scope =>
  ScopeSchema.parse({
    target: "http://localhost:3000",
    scope: ["localhost"],
    identities: [
      { name: "alice", username: "alice@shop.test", password: "pw-a" },
      { name: "bob", username: "bob@shop.test", password: "pw-b" },
    ],
    ...over,
  });

const obs = (over: Partial<IdorObservation> = {}): IdorObservation => ({
  private_field: "email",
  victim_marker: "bob@shop.test",
  attacker_marker: "alice@shop.test",
  attacker: { status: 200, body: '{"email":"bob@shop.test"}' },
  unauth: { status: 401, body: "Unauthorized" },
  ...over,
});

// ---------------------------------------------------------------------------
// 1. The pure oracle — the differential decision table
// ---------------------------------------------------------------------------

describe("runIdorOracle (pure differential table)", () => {
  it("CONFIRMS a true cross-tenant read with a hard unauth deny (high confidence)", () => {
    const v = runIdorOracle(obs());
    expect(v.confirmed).toBe(true);
    expect(v.confidence).toBe("high");
    expect(v.signals.victim_data_leaked).toBe(true);
    expect(v.signals.unauth_denied).toBe(true);
  });

  it("CONFIRMS with medium confidence on a soft unauth deny (2xx but marker absent)", () => {
    const v = runIdorOracle(obs({ unauth: { status: 200, body: "[]" } }));
    expect(v.confirmed).toBe(true);
    expect(v.confidence).toBe("medium");
  });

  it("does NOT confirm public-by-design (unauth also returns the marker)", () => {
    const v = runIdorOracle(obs({ unauth: { status: 200, body: '{"email":"bob@shop.test"}' } }));
    expect(v.confirmed).toBe(false);
    expect(v.signals.public_by_design).toBe(true);
    expect(v.reason).toMatch(/public-by-design/);
  });

  it("does NOT confirm own-data (attacker's own value returned, not the victim's)", () => {
    const v = runIdorOracle(
      obs({ attacker: { status: 200, body: '{"email":"alice@shop.test"}' } }),
    );
    expect(v.confirmed).toBe(false);
    expect(v.signals.own_data).toBe(true);
    expect(v.reason).toMatch(/own-data/);
  });

  it("does NOT confirm when the attacker read was denied (access control held)", () => {
    const v = runIdorOracle(obs({ attacker: { status: 403, body: "Forbidden" } }));
    expect(v.confirmed).toBe(false);
    expect(v.signals.attacker_read_ok).toBe(false);
  });

  it("does NOT confirm when the victim marker never leaked", () => {
    const v = runIdorOracle(obs({ attacker: { status: 200, body: "{}" } }));
    expect(v.confirmed).toBe(false);
    expect(v.signals.victim_data_leaked).toBe(false);
  });

  it("never throws / always returns a labelled verdict (never drops)", () => {
    const v = runIdorOracle(obs({ attacker: { status: 500, body: "" }, unauth: { status: 500, body: "" } }));
    expect(v.confirmed).toBe(false);
    expect(typeof v.reason).toBe("string");
    expect(v.reason.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// 2. The HTTP probe transport (injected fetch)
// ---------------------------------------------------------------------------

describe("resolveUrl", () => {
  it("resolves a path against the target base and passes an absolute URL through", () => {
    expect(resolveUrl("http://localhost:3000", "/rest/basket/2")).toBe("http://localhost:3000/rest/basket/2");
    expect(resolveUrl("http://localhost:3000", "http://localhost:3000/x")).toBe("http://localhost:3000/x");
  });
});

describe("sessionHeaders / isAuthenticatedSession", () => {
  it("emits no headers for the implicit unauthenticated identity", () => {
    const s: IdentitySession = { name: UNAUTH_SESSION };
    expect(sessionHeaders(s)).toEqual({});
    expect(isAuthenticatedSession(s)).toBe(false);
  });
  it("emits an Authorization header for a bearer session", () => {
    const s: IdentitySession = { name: "alice", authorization: "Bearer t" };
    expect(sessionHeaders(s)).toEqual({ Authorization: "Bearer t" });
    expect(isAuthenticatedSession(s)).toBe(true);
  });
});

describe("httpProbe (injected fetch)", () => {
  it("resolves the endpoint, injects the identity, and returns status/body/timing", async () => {
    const seen: { url: string; headers: Record<string, string> }[] = [];
    let clock = 1000;
    const fakeFetch = (async (url: string, init?: RequestInit) => {
      seen.push({ url: String(url), headers: (init?.headers as Record<string, string>) ?? {} });
      return new Response('{"email":"bob@shop.test"}', { status: 200 });
    }) as unknown as typeof fetch;

    const sessions = new Map<string, IdentitySession>([
      ["alice", { name: "alice", authorization: "Bearer tok-a" }],
      [UNAUTH_SESSION, { name: UNAUTH_SESSION }],
    ]);
    const cfg = { scope: scopeOf(), sessions, fetch: fakeFetch, now: () => (clock += 5) };

    const out = await httpProbe(cfg, {
      endpoint: "/rest/basket/2",
      payload_id: "p",
      payload: "x",
      session: "alice",
    });
    expect(out.status).toBe(200);
    expect(out.body).toContain("bob@shop.test");
    expect(out.ms).toBe(5);
    expect(seen[0]!.url).toBe("http://localhost:3000/rest/basket/2");
    expect(seen[0]!.headers).toMatchObject({ Authorization: "Bearer tok-a" });
  });

  it("blocks an out-of-scope target before any byte leaves the process", async () => {
    let called = false;
    const fakeFetch = (async () => {
      called = true;
      return new Response("", { status: 200 });
    }) as unknown as typeof fetch;
    const cfg = {
      scope: scopeOf({ target: "http://evil.example.com", scope: ["localhost"] }),
      sessions: new Map<string, IdentitySession>([[UNAUTH_SESSION, { name: UNAUTH_SESSION }]]),
      fetch: fakeFetch,
    };
    await expect(
      httpProbe(cfg, { endpoint: "/x", payload_id: "p", payload: "x", session: UNAUTH_SESSION }),
    ).rejects.toBeInstanceOf(ScopeError);
    expect(called).toBe(false);
  });
});

describe("createHttpTransport", () => {
  it("returns a LedgerResult whose evidence round-trips through decodeProbeEvidence", async () => {
    const fakeFetch = (async () => new Response("body-text", { status: 200 })) as unknown as typeof fetch;
    const transport = createHttpTransport({
      scope: scopeOf(),
      sessions: new Map([[UNAUTH_SESSION, { name: UNAUTH_SESSION }]]),
      fetch: fakeFetch,
      now: () => 0,
    });
    const res = await transport({ endpoint: "/x", payload_id: "p", payload: "x", session: UNAUTH_SESSION });
    expect(res.status).toBe("200");
    expect(decodeProbeEvidence(res.evidence)).toEqual({ status: 200, body: "body-text" });
  });
});

// ---------------------------------------------------------------------------
// 3. Multi-identity auth (injected fetch)
// ---------------------------------------------------------------------------

describe("extractToken", () => {
  it("pulls a token from the Juice-Shop authentication shape and the flat shapes", () => {
    expect(extractToken({ authentication: { token: "j" } })).toBe("j");
    expect(extractToken({ token: "flat" })).toBe("flat");
    expect(extractToken({ access_token: "oauth" })).toBe("oauth");
    expect(extractToken({ nope: 1 })).toBeUndefined();
  });
});

describe("captureSessions (injected fetch)", () => {
  it("registers + logs in each identity, keying a bearer session by name, plus unauth", async () => {
    const calls: string[] = [];
    const fakeFetch = (async (url: string, init?: RequestInit) => {
      const u = String(url);
      calls.push(`${init?.method ?? "GET"} ${u}`);
      if (u.endsWith("/api/Users")) return new Response("{}", { status: 201 });
      // login: echo a token derived from the posted email
      const body = JSON.parse(String(init?.body ?? "{}")) as { email: string };
      return new Response(JSON.stringify({ authentication: { token: `tok-${body.email}` } }), { status: 200 });
    }) as unknown as typeof fetch;

    const sessions = await captureSessions(scopeOf(), { fetch: fakeFetch });
    expect(sessions.get(UNAUTH_SESSION)).toEqual({ name: UNAUTH_SESSION });
    expect(sessions.get("alice")!.authorization).toBe("Bearer tok-alice@shop.test");
    expect(sessions.get("bob")!.authorization).toBe("Bearer tok-bob@shop.test");
    // Register was attempted before login for each identity.
    expect(calls.filter((c) => c.includes("/api/Users"))).toHaveLength(2);
  });

  it("yields a name-only (credential-less) session when a login fails, without aborting the others", async () => {
    const fakeFetch = (async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith("/api/Users")) return new Response("{}", { status: 201 });
      const body = JSON.parse(String(init?.body ?? "{}")) as { email: string };
      if (body.email.startsWith("alice")) return new Response("Invalid", { status: 401 });
      return new Response(JSON.stringify({ authentication: { token: "tok-bob" } }), { status: 200 });
    }) as unknown as typeof fetch;

    const sessions = await captureSessions(scopeOf(), { fetch: fakeFetch });
    expect(isAuthenticatedSession(sessions.get("alice"))).toBe(false);
    expect(isAuthenticatedSession(sessions.get("bob"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 4. The hardcoded IDOR probe (hunter runner)
// ---------------------------------------------------------------------------

const SPEC: IdorProbeSpec = IdorProbeSpecSchema.parse({
  endpoint: "/rest/basket/2",
  attacker: "alice",
  private_field: "email",
  victim_marker: "bob@shop.test",
  attacker_marker: "alice@shop.test",
});

describe("buildPocScript", () => {
  it("bakes the marker + attacker credential and is self-checking (greps + exits)", () => {
    const poc = buildPocScript(SPEC, "Bearer tok-a", "http://localhost:3000");
    expect(poc).toMatch(/Authorization: Bearer tok-a/);
    expect(poc).toContain("bob@shop.test");
    expect(poc).toMatch(/exit 1/);
    expect(poc).toMatch(/exit 0/);
    expect(poc.startsWith("#!/usr/bin/env bash")).toBe(true);
  });
});

describe("createIdorHunterRunner + runHunter (real transport, injected fetch)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-idor-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("fires attacker+unauth through the ledger path and writes a finding with a runnable poc.sh + oracle.json", async () => {
    // Attacker (bearer) sees bob's email; unauth is denied.
    const fakeFetch = (async (_url: string, init?: RequestInit) => {
      const auth = (init?.headers as Record<string, string> | undefined)?.["Authorization"];
      if (auth) return new Response('{"email":"bob@shop.test"}', { status: 200 });
      return new Response("Unauthorized", { status: 401 });
    }) as unknown as typeof fetch;

    const scope = scopeOf();
    const sessions = new Map<string, IdentitySession>([
      ["alice", { name: "alice", authorization: "Bearer tok-a" }],
      [UNAUTH_SESSION, { name: UNAUTH_SESSION }],
    ]);
    const transport = createHttpTransport({ scope, sessions, fetch: fakeFetch, now: () => 0 });
    const runner = createIdorHunterRunner([SPEC], sessions, scope.target);

    const outcome = await runHunter(dir, {
      runner,
      scope,
      surface: "api",
      vuln_class: "idor",
      endpoints: ["/rest/basket/2"],
      payloads: [],
      transport,
      session: "alice",
      now: () => "2026-07-05T00:00:00.000Z",
    });

    // Two probes fired (attacker + unauth), one candidate written.
    expect(outcome.probesFired).toBe(2);
    expect(outcome.findings).toHaveLength(1);

    const fdir = outcome.findings[0]!.dir;
    const poc = await fs.readFile(path.join(fdir, "poc.sh"), "utf8");
    expect(poc).toContain("bob@shop.test");
    const stat = await fs.stat(path.join(fdir, "poc.sh"));
    expect(stat.mode & 0o111).toBeTruthy(); // executable
    const oracle = JSON.parse(await fs.readFile(path.join(fdir, "evidence", ORACLE_EVIDENCE_FILE), "utf8"));
    expect(oracle.attacker.status).toBe(200);
    expect(oracle.unauth.status).toBe(401);
  });

  it("raises no candidate when the attacker read is itself denied (access control held)", async () => {
    const fakeFetch = (async () => new Response("Forbidden", { status: 403 })) as unknown as typeof fetch;
    const scope = scopeOf();
    const sessions = new Map<string, IdentitySession>([
      ["alice", { name: "alice", authorization: "Bearer tok-a" }],
      [UNAUTH_SESSION, { name: UNAUTH_SESSION }],
    ]);
    const transport = createHttpTransport({ scope, sessions, fetch: fakeFetch });
    const runner = createIdorHunterRunner([SPEC], sessions, scope.target);
    const outcome = await runHunter(dir, {
      runner, scope, surface: "api", vuln_class: "idor",
      endpoints: ["/rest/basket/2"], payloads: [], transport, session: "alice",
    });
    expect(outcome.findings).toHaveLength(0);
  });
});

describe("buildTracerSpecs (trivial hardcoded plan)", () => {
  it("yields a cross-tenant spec per (attacker, victim) × endpoint template, marker = victim username", () => {
    const specs = buildTracerSpecs(scopeOf());
    expect(specs.length).toBeGreaterThanOrEqual(2);
    expect(specs.every((s) => s.attacker === "alice")).toBe(true);
    expect(specs.every((s) => s.victim_marker === "bob@shop.test")).toBe(true);
  });

  it("yields nothing when fewer than two identities are declared (no victim to reach)", () => {
    expect(buildTracerSpecs(scopeOf({ identities: [{ name: "solo", username: "s@t", password: "p" }] }))).toHaveLength(0);
    expect(buildTracerSpecs(scopeOf({ identities: [] }))).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 5. The Verifier wired to the oracle
// ---------------------------------------------------------------------------

describe("createOracleVerifierRunner", () => {
  const input = (evidence: Record<string, string>) => ({
    finding_id: "f-0001",
    vuln_class: "idor",
    checklist: "",
    refire: { finding_id: "f-0001", exit_code: 0, stdout: "", stderr: "", captured_response: "", fresh_response: "", differs: false },
    evidence,
  });

  it("emits `confirmed` when the oracle passes", async () => {
    const v = await createOracleVerifierRunner()(input({ [ORACLE_EVIDENCE_FILE]: JSON.stringify(obs()) }));
    expect(v.verdict).toBe("confirmed");
  });

  it("emits `weak_evidence` (surfaced, not dropped) when the oracle cannot confirm", async () => {
    const notCross = obs({ unauth: { status: 200, body: '{"email":"bob@shop.test"}' } });
    const v = await createOracleVerifierRunner()(input({ [ORACLE_EVIDENCE_FILE]: JSON.stringify(notCross) }));
    expect(v.verdict).toBe("weak_evidence");
  });

  it("emits `weak_evidence` (never confirmed) when the differential is missing", async () => {
    const v = await createOracleVerifierRunner()(input({}));
    expect(v.verdict).toBe("weak_evidence");
  });
});

// ---------------------------------------------------------------------------
// 6. End-to-end verify loop: oracle-verified finding → confirmed; unconfirmable → escalated, not dropped
// ---------------------------------------------------------------------------

describe("verify loop wired to the oracle", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-idor-e2e-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const writeCandidate = async (id: string, observation: IdorObservation) => {
    const fdir = path.join(dir, "findings", id);
    await fs.mkdir(path.join(fdir, "evidence"), { recursive: true });
    await fs.writeFile(path.join(fdir, "poc.sh"), "#!/usr/bin/env bash\necho ok\n", "utf8");
    await fs.writeFile(path.join(fdir, "response.json"), "ok\n", "utf8");
    await fs.writeFile(path.join(fdir, "evidence", ORACLE_EVIDENCE_FILE), JSON.stringify(observation), "utf8");
    await fs.writeFile(
      path.join(fdir, "finding.json"),
      JSON.stringify({ id, title: "IDOR", severity: "high", vuln_class: "idor", endpoint: "/rest/basket/2", method: "GET", poc: "poc.sh" }, null, 2),
      "utf8",
    );
  };

  const noopExec: PocExecutor = async () => ({ exit_code: 0, stdout: "ok", stderr: "" });
  const noopReDispatch = async () => [];

  it("confirms a true cross-tenant IDOR (lands in verdicts/pass-N.json)", async () => {
    await writeCandidate("f-0001", obs());
    const outcome = await runVerifyStage(dir, {
      scope: scopeOf(),
      verifierRunner: createOracleVerifierRunner(),
      execute: noopExec,
      reDispatch: noopReDispatch,
    });
    expect(outcome.confirmed).toEqual(["f-0001"]);
    expect(outcome.dropped).toHaveLength(0);
  });

  it("escalates (surfaces, never drops) a candidate the oracle cannot confirm", async () => {
    await writeCandidate("f-0002", obs({ unauth: { status: 200, body: '{"email":"bob@shop.test"}' } }));
    const outcome = await runVerifyStage(dir, {
      scope: scopeOf(),
      verifierRunner: createOracleVerifierRunner(),
      execute: noopExec,
      reDispatch: noopReDispatch,
      maxIterations: 1, // one pass, then the re-queue caps to escalation
    });
    expect(outcome.escalated).toContain("f-0002");
    expect(outcome.dropped).toHaveLength(0);
    expect(outcome.confirmed).toHaveLength(0);
    const rfh = await fs.readFile(path.join(dir, "ready-for-human.jsonl"), "utf8");
    expect(rfh).toContain("f-0002");
  });
});
