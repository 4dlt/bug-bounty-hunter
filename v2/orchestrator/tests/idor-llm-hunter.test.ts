import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ScopeSchema, type Scope } from "../src/scope.ts";
import { runHunter } from "../src/hunters/framework.ts";
import {
  createHttpTransport,
  UNAUTH_SESSION,
  type IdentitySession,
} from "../src/idor/transport.ts";
import {
  createLlmIdorHunterRunner,
  buildHunterSystemPrompt,
  candidateToFinding,
  httpRequestTool,
  bashTool,
  HTTP_REQUEST_TOOL,
  BASH_TOOL,
  SUBMIT_FINDINGS_TOOL,
  type LlmIdorCandidate,
} from "../src/idor/llm-hunter.ts";
import { runIdorOracle } from "../src/idor/oracle.ts";
import { createOracleVerifierRunner, ORACLE_EVIDENCE_FILE } from "../src/idor/oracle-verifier.ts";
import type { AgentMessage, MessagesClient } from "../src/agent/tool-loop.ts";
import type { HunterContext } from "../src/hunters/framework.ts";

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

const sessionsOf = () =>
  new Map<string, IdentitySession>([
    ["alice", { name: "alice", authorization: "Bearer tok-a" }],
    ["bob", { name: "bob", authorization: "Bearer tok-b" }],
    [UNAUTH_SESSION, { name: UNAUTH_SESSION }],
  ]);

// A fake client that plays a scripted tool-use dialogue. The hunter discovers
// bob's email as alice, confirms it is denied unauthenticated, and submits.
function scriptedClient(script: AgentMessage[]): MessagesClient {
  let i = 0;
  return {
    messages: {
      create: async () => {
        const msg = script[i];
        i += 1;
        if (!msg) throw new Error("scripted client exhausted");
        return msg;
      },
    },
  };
}

const CANDIDATE: LlmIdorCandidate = {
  endpoint: "/api/Users/2",
  method: "GET",
  attacker_identity: "alice",
  private_field: "email",
  victim_marker: "bob@shop.test",
  attacker_marker: "alice@shop.test",
  severity: "high",
  attacker_response: { status: 200, body: '{"id":2,"email":"bob@shop.test"}' },
  unauth_response: { status: 401, body: "Unauthorized" },
};

const HUNT_DIALOGUE: AgentMessage[] = [
  // Turn 1: baseline read as alice via http_request.
  { content: [{ type: "tool_use", id: "u1", name: HTTP_REQUEST_TOOL, input: { endpoint: "/api/Users/2", identity: "alice" } }] },
  // Turn 2: same object unauthenticated.
  { content: [{ type: "tool_use", id: "u2", name: HTTP_REQUEST_TOOL, input: { endpoint: "/api/Users/2", identity: UNAUTH_SESSION } }] },
  // Turn 3: use bash to jq the leaked field (proves the full toolset is wired).
  { content: [{ type: "tool_use", id: "u3", name: BASH_TOOL, input: { command: "echo '{\"email\":\"bob@shop.test\"}' | jq .email" } }] },
  // Turn 4: submit the candidate + a weaker hypothesis.
  {
    content: [
      {
        type: "tool_use",
        id: "u4",
        name: SUBMIT_FINDINGS_TOOL,
        input: {
          findings: [CANDIDATE],
          hypotheses: [
            { target_endpoint: "/api/Orders/{id}", hypothesis: "order ids look sequential", signal_evidence: "own id 1042" },
          ],
        },
      },
    ],
  },
];

describe("createLlmIdorHunterRunner (fake LLM client, real transport)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-llm-idor-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("drives baseline+mutate+unauth through http_request, uses bash, and emits an oracle-confirmable finding", async () => {
    // alice (bearer) sees bob's email; unauth is denied.
    const fakeFetch = (async (_url: string, init?: RequestInit) => {
      const auth = (init?.headers as Record<string, string> | undefined)?.["Authorization"];
      if (auth) return new Response('{"id":2,"email":"bob@shop.test"}', { status: 200 });
      return new Response("Unauthorized", { status: 401 });
    }) as unknown as typeof fetch;

    const scope = scopeOf();
    const sessions = sessionsOf();
    const bash = vi.fn(async () => ({ stdout: "bob@shop.test\n", stderr: "", exit_code: 0 }));
    const onLlmCall = vi.fn();
    const transport = createHttpTransport({ scope, sessions, fetch: fakeFetch, now: () => 0 });
    const runner = createLlmIdorHunterRunner({
      client: scriptedClient(HUNT_DIALOGUE),
      sessions,
      base: scope.target,
      playbook: "# IDOR playbook\nHunt cross-tenant reads.",
      bash,
      onLlmCall,
    });

    const outcome = await runHunter(dir, {
      runner,
      scope,
      surface: "api",
      vuln_class: "idor",
      endpoints: ["/api/Users/2"],
      payloads: [],
      transport,
      session: "alice",
      now: () => "2026-07-05T00:00:00.000Z",
    });

    // Two http_request probes went through the ledger firer; bash ran once;
    // 4 model turns were each counted against the budget.
    expect(outcome.probesFired).toBe(2);
    expect(bash).toHaveBeenCalledOnce();
    expect(onLlmCall).toHaveBeenCalledTimes(4);

    // One candidate finding with a self-checking poc.sh + oracle.json.
    expect(outcome.findings).toHaveLength(1);
    const fdir = outcome.findings[0]!.dir;
    const poc = await fs.readFile(path.join(fdir, "poc.sh"), "utf8");
    expect(poc).toContain("bob@shop.test");
    expect(poc).toMatch(/exit 0/);
    const oracleJson = JSON.parse(
      await fs.readFile(path.join(fdir, "evidence", ORACLE_EVIDENCE_FILE), "utf8"),
    );
    expect(runIdorOracle(oracleJson).confirmed).toBe(true);

    // The unconfirmed signal rode along as a hypothesis.
    expect(outcome.reactiveHypotheses).toHaveLength(1);
    expect(outcome.reactiveHypotheses[0]!.target_endpoint).toBe("/api/Orders/{id}");

    // The Slice-1 oracle verifier confirms this finding from its oracle.json.
    const verdict = await createOracleVerifierRunner()({
      finding_id: outcome.findings[0]!.id,
      vuln_class: "idor",
      checklist: "",
      refire: { finding_id: outcome.findings[0]!.id, exit_code: 0, stdout: "", stderr: "", captured_response: "", fresh_response: "", differs: false },
      evidence: { [ORACLE_EVIDENCE_FILE]: JSON.stringify(oracleJson) },
    });
    expect(verdict.verdict).toBe("confirmed");
  });

  it("yields nothing (no crash) when the model hits the turn cap without submitting", async () => {
    const loop: AgentMessage = {
      content: [{ type: "tool_use", id: "u", name: HTTP_REQUEST_TOOL, input: { endpoint: "/api/Users/2", identity: "alice" } }],
    };
    const fakeFetch = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    const scope = scopeOf();
    const sessions = sessionsOf();
    const runner = createLlmIdorHunterRunner({
      client: scriptedClient([loop, loop, loop]),
      sessions,
      base: scope.target,
      playbook: "pb",
      bash: async () => ({ stdout: "", stderr: "", exit_code: 0 }),
      maxTurns: 2,
    });
    const outcome = await runHunter(dir, {
      runner, scope, surface: "api", vuln_class: "idor",
      endpoints: ["/api/Users/2"], payloads: [], transport: createHttpTransport({ scope, sessions, fetch: fakeFetch }), session: "alice",
    });
    expect(outcome.findings).toHaveLength(0);
  });
});

describe("the hunter's tools + prompt (unit)", () => {
  const fakeCtx = (over: Partial<HunterContext> = {}): HunterContext => ({
    agent: "H-idor",
    surface: "api",
    vuln_class: "idor",
    endpoints: ["/api/Users/2"],
    payloads: [],
    session: "alice",
    pass: 0,
    alreadyTried: [{ endpoint: "/api/Users/1", payload_sig: "sig", session: "alice" }],
    fire: (async () => ({ fired: true, result: { status: "200", resp_sig: "s", trigger_match: false, evidence: JSON.stringify({ status: 200, body: "hi" }) } })) as HunterContext["fire"],
    takeToken: async () => true,
    ...over,
  });

  it("http_request fires through ctx.fire and returns the decoded {status, body}", async () => {
    const fire = vi.fn(async () => ({ fired: true as const, result: { status: "200", resp_sig: "s", trigger_match: false, evidence: JSON.stringify({ status: 200, body: "leaked" }) } }));
    const tool = httpRequestTool(fakeCtx({ fire }));
    const out = (await tool.handler({ endpoint: "/api/Users/2", identity: "alice" })) as Record<string, unknown>;
    expect(out).toEqual({ fired: true, status: 200, body: "leaked" });
    expect(fire).toHaveBeenCalledWith(expect.objectContaining({ endpoint: "/api/Users/2", session: "alice" }));
  });

  it("http_request reports a duplicate/rate-limited refusal back to the model", async () => {
    const fire = vi.fn(async () => ({ fired: false as const, reason: "duplicate" as const }));
    const tool = httpRequestTool(fakeCtx({ fire }));
    const out = await tool.handler({ endpoint: "/x", identity: "alice" });
    expect(out).toEqual({ fired: false, reason: "duplicate" });
  });

  it("bash tool passes the command through the injected executor", async () => {
    const exec = vi.fn(async () => ({ stdout: "out", stderr: "", exit_code: 0 }));
    const out = await bashTool(exec).handler({ command: "echo hi" });
    expect(out).toEqual({ stdout: "out", stderr: "", exit_code: 0 });
    expect(exec).toHaveBeenCalledWith("echo hi");
  });

  it("system prompt carries the playbook, the identities, and the already-tried keys", () => {
    const sys = buildHunterSystemPrompt("PLAYBOOK-BODY", fakeCtx(), ["alice", "bob", UNAUTH_SESSION]);
    expect(sys).toContain("PLAYBOOK-BODY");
    expect(sys).toContain("alice");
    expect(sys).toContain(UNAUTH_SESSION);
    expect(sys).toContain("/api/Users/1");
    expect(sys).toContain(SUBMIT_FINDINGS_TOOL);
  });

  it("candidateToFinding reuses the Slice-1 finding shape (oracle.json + self-checking poc)", () => {
    const finding = candidateToFinding(CANDIDATE, sessionsOf(), "http://localhost:3000");
    expect(finding.vuln_class).toBe("idor");
    expect(finding.evidence[ORACLE_EVIDENCE_FILE]).toBeDefined();
    expect(finding.poc).toContain("bob@shop.test");
    const obs = JSON.parse(finding.evidence[ORACLE_EVIDENCE_FILE]!);
    expect(runIdorOracle(obs).confirmed).toBe(true);
  });
});
