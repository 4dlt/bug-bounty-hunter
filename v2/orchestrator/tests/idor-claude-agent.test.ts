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
  createClaudeIdorHunterRunner,
  buildAgentBrief,
  extractSubmitJson,
  parseClaudeCliResult,
  claudeAgentArgs,
  type ClaudeAgentRunner,
} from "../src/idor/claude-agent.ts";
import { runIdorOracle } from "../src/idor/oracle.ts";
import { createOracleVerifierRunner, ORACLE_EVIDENCE_FILE } from "../src/idor/oracle-verifier.ts";
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

// The agent's final result: it explains what it did, then emits the contract JSON.
const AGENT_RESULT = `I read /api/Users/2 as alice and it leaked bob's email; the same
request unauthenticated is denied. Here is the finding:

\`\`\`json
{
  "findings": [
    {
      "endpoint": "/api/Users/2",
      "method": "GET",
      "attacker_identity": "alice",
      "private_field": "email",
      "victim_marker": "bob@shop.test",
      "attacker_marker": "alice@shop.test",
      "severity": "high",
      "attacker_response": { "status": 200, "body": "{\\"id\\":2,\\"email\\":\\"bob@shop.test\\"}" },
      "unauth_response": { "status": 401, "body": "Unauthorized" }
    }
  ],
  "hypotheses": [
    { "target_endpoint": "/api/Orders/{id}", "hypothesis": "order ids look sequential", "signal_evidence": "own id 1042" }
  ]
}
\`\`\``;

const fakeCtx = (over: Partial<HunterContext> = {}): HunterContext => ({
  agent: "H-idor",
  surface: "api",
  vuln_class: "idor",
  endpoints: ["/api/Users/2"],
  payloads: [],
  session: "alice",
  pass: 0,
  alreadyTried: [{ endpoint: "/api/Users/1", payload_sig: "sig", session: "alice" }],
  fire: (async () => ({ fired: true, result: { status: "200", resp_sig: "s", trigger_match: false, evidence: "" } })) as HunterContext["fire"],
  takeToken: async () => true,
  ...over,
});

describe("createClaudeIdorHunterRunner (fake claude agent, offline)", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-claude-idor-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("spawns one claude agent, extracts its candidate JSON, and emits an oracle-confirmable finding", async () => {
    const agent: ClaudeAgentRunner = vi.fn(async () => ({ text: AGENT_RESULT }));
    const onLlmCall = vi.fn();
    const scope = scopeOf();
    const sessions = sessionsOf();
    const runner = createClaudeIdorHunterRunner({
      agent,
      sessions,
      base: scope.target,
      playbook: "# IDOR playbook\nHunt cross-tenant reads.",
      onLlmCall,
      level: "smart",
    });

    const outcome = await runHunter(dir, {
      runner,
      scope,
      surface: "api",
      vuln_class: "idor",
      endpoints: ["/api/Users/2"],
      payloads: [],
      // The agent fires its own curl; the transport is unused during the hunt.
      transport: createHttpTransport({ scope, sessions, fetch: (async () => new Response("{}")) as unknown as typeof fetch }),
      session: "alice",
      now: () => "2026-07-05T00:00:00.000Z",
    });

    // Exactly one agent spawn, counted once against the budget; premium model.
    expect(agent).toHaveBeenCalledOnce();
    const call = (agent as unknown as { mock: { calls: [{ prompt: string; model: string }][] } }).mock.calls[0]![0];
    expect(call.model).toBe("claude-opus-4-8");
    expect(call.prompt).toContain("Bearer tok-a");
    expect(call.prompt).toContain("/api/Users/2");
    expect(onLlmCall).toHaveBeenCalledOnce();
    // No probes go through the ledger firer — the agent fires its own bash/curl.
    expect(outcome.probesFired).toBe(0);

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

  it("yields nothing (no crash) on malformed agent output", async () => {
    const scope = scopeOf();
    const sessions = sessionsOf();
    const runner = createClaudeIdorHunterRunner({
      agent: async () => ({ text: "I could not find anything conclusive. Sorry!" }),
      sessions,
      base: scope.target,
      playbook: "pb",
    });
    const y = await runner(fakeCtx());
    expect(y.findings).toHaveLength(0);
    expect(y.hypotheses).toHaveLength(0);
  });

  it("yields nothing (no crash) when the agent spawn throws", async () => {
    const scope = scopeOf();
    const runner = createClaudeIdorHunterRunner({
      agent: async () => {
        throw new Error("claude not found on PATH");
      },
      sessions: sessionsOf(),
      base: scope.target,
      playbook: "pb",
    });
    const y = await runner(fakeCtx());
    expect(y.findings).toHaveLength(0);
  });

  it("emits only hypotheses when the agent reports an empty findings array", async () => {
    const runner = createClaudeIdorHunterRunner({
      agent: async () => ({
        text: '{ "findings": [], "hypotheses": [ { "target_endpoint": "/api/x", "hypothesis": "h", "signal_evidence": "e" } ] }',
      }),
      sessions: sessionsOf(),
      base: "http://localhost:3000",
      playbook: "pb",
    });
    const y = await runner(fakeCtx());
    expect(y.findings).toHaveLength(0);
    expect(y.hypotheses).toHaveLength(1);
  });
});

describe("claude-agent seam + brief + extraction (unit)", () => {
  it("claudeAgentArgs runs print mode, the chosen model, JSON, skip-permissions, stdin", () => {
    expect(claudeAgentArgs("claude-sonnet-4-6")).toEqual([
      "--print", "--model", "claude-sonnet-4-6",
      "--output-format", "json", "--dangerously-skip-permissions", "-p", "-",
    ]);
  });

  it("parseClaudeCliResult pulls `result` from the CLI JSON envelope, else falls back to raw", () => {
    expect(parseClaudeCliResult(JSON.stringify({ type: "result", result: "the answer" }))).toBe("the answer");
    expect(parseClaudeCliResult("not json — raw text")).toBe("not json — raw text");
  });

  it("buildAgentBrief carries the playbook, target, tokens, endpoints, unauth, and contract", () => {
    const brief = buildAgentBrief("PLAYBOOK-BODY", fakeCtx(), sessionsOf(), "http://localhost:3000");
    expect(brief).toContain("PLAYBOOK-BODY");
    expect(brief).toContain("http://localhost:3000");
    expect(brief).toContain("Bearer tok-a");
    expect(brief).toContain("Bearer tok-b");
    expect(brief).toContain("/api/Users/2");
    expect(brief).toContain(UNAUTH_SESSION);
    expect(brief).toContain("no Authorization header");
    expect(brief).toContain('"findings"');
    expect(brief).toContain('"unauth_response"');
  });

  it("extractSubmitJson takes the last findings-bearing object even amid prose + multiple blocks", () => {
    const text = 'prelude {"scratch": 1} then\n```json\n{"findings":[],"hypotheses":[]}\n```';
    const obj = extractSubmitJson(text) as Record<string, unknown>;
    expect(obj).not.toBeNull();
    expect(obj).toHaveProperty("findings");
  });

  it("extractSubmitJson respects braces inside string values", () => {
    const obj = extractSubmitJson('{"findings":[],"note":"a } brace in a string"}') as Record<string, unknown>;
    expect(obj.note).toBe("a } brace in a string");
  });

  it("extractSubmitJson returns null when there is no JSON object", () => {
    expect(extractSubmitJson("just prose, no json here")).toBeNull();
  });
});
