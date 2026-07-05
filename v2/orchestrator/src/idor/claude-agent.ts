// The first-party `claude`-agent IDOR hunter (Phase 1 · Slice 3).
//
// SUPERSEDES Slice 2's direct-`@anthropic-ai/sdk` tool-loop hunter execution.
// The workflow MUST run on the Claude *subscription* tier (a hard requirement —
// no pay-as-you-go API key), but Anthropic anti-abuse-gates Sonnet/Opus with a
// 429 when a subscription OAuth token hits `/v1/messages` directly. The same
// token reaches premium models fine through the FIRST-PARTY `claude` CLI, which
// carries the first-party identity. So instead of driving a bounded tool-loop
// over the SDK client, this hunter spawns one `claude` agent per IDOR cell:
//
//   claude --print --model <model> --output-format json \
//          --dangerously-skip-permissions -p -
//
// with its whole brief piped over stdin. The agent is the "capable agent" model
// — it probes with its OWN `bash`/`curl` (not limited to one wired tool), using
// the captured identity session tokens we hand it. It ends by emitting a single
// JSON object matching the EXISTING candidate contract (`SubmitFindingsSchema`),
// which we extract from its final result and feed through the UNCHANGED
// `candidateToFinding` -> `buildIdorFinding` -> oracle -> verify -> report path.
// The model discovers; the code proves.
//
// The `claude` invocation is behind an injectable `ClaudeAgentRunner` seam
// (mirroring the `BashExecutor` / `PocExecutor` / `MessagesClient` seams), so the
// hunter is unit-testable offline with a fake that returns canned agent output —
// no live `claude`, no network.
//
// Trade-off (accepted by the operator): probes fired by the agent's `bash`
// bypass the in-process ledger/scope firer; scope is still the operator's
// authorized target. The direct-SDK premium path is removed for the hunter.

import { spawn } from "node:child_process";
import { z } from "zod";
import type { HunterContext, HunterRunner, HunterYield } from "../hunters/framework.ts";
import type { Level } from "../llm.ts";
import { modelForLevel } from "../llm.ts";
import { submitFindingsToYield, SubmitFindingsSchema } from "./llm-hunter.ts";
import { UNAUTH_SESSION, type IdentitySession } from "./transport.ts";

// ---------------------------------------------------------------------------
// The claude-agent seam
// ---------------------------------------------------------------------------

/** One spawn of the first-party `claude` agent. `prompt` is piped over stdin. */
export interface ClaudeAgentRequest {
  prompt: string;
  /** Resolved model id (haiku/sonnet/opus) from the engagement level. */
  model: string;
}

/** The agent's final result text — the model's last message, JSON contract and
 *  all. The runner extracts the candidate JSON from it. */
export interface ClaudeAgentResult {
  text: string;
}

/** Spawns a first-party `claude` agent and returns its final result text.
 *  Injected so the hunter is unit-testable without a live CLI; the default
 *  (`spawnClaudeAgent`) shells out to `claude --print … -p -`. */
export type ClaudeAgentRunner = (req: ClaudeAgentRequest) => Promise<ClaudeAgentResult>;

/** CLI args for a first-party `claude` agent run: print mode, chosen model, JSON
 *  envelope, permissions skipped (headless), prompt read from stdin (`-p -`). */
export function claudeAgentArgs(model: string): string[] {
  return [
    "--print",
    "--model",
    model,
    "--output-format",
    "json",
    "--dangerously-skip-permissions",
    "-p",
    "-",
  ];
}

/** The `--output-format json` envelope the CLI prints (permissive — we only need
 *  the final `result` text). */
const CliEnvelopeSchema = z.object({ result: z.string() });

/** Extract the agent's final result text from the CLI's `--output-format json`
 *  envelope. Falls back to the raw stdout when it is not the expected envelope. */
export function parseClaudeCliResult(stdout: string): string {
  try {
    const env = CliEnvelopeSchema.safeParse(JSON.parse(stdout));
    if (env.success) return env.data.result;
  } catch {
    // Not the JSON envelope — treat the whole stdout as the result.
  }
  return stdout;
}

/**
 * Default runner: spawn `claude` in `cwd`, pipe the brief over stdin, and parse
 * the final result out of the `--output-format json` envelope. Auth is the
 * ambient `CLAUDE_CODE_OAUTH_TOKEN` — the CLI carries the first-party identity,
 * so premium models are served on the subscription without a 429.
 */
export function spawnClaudeAgent(cwd: string): ClaudeAgentRunner {
  return ({ prompt, model }) =>
    new Promise<ClaudeAgentResult>((resolve, reject) => {
      const child = spawn("claude", claudeAgentArgs(model), { cwd });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d.toString()));
      child.stderr.on("data", (d) => (stderr += d.toString()));
      child.on("error", reject);
      child.on("close", (code) => {
        if (code !== 0 && stdout.trim() === "") {
          reject(new Error(`claude agent exited ${code}: ${stderr.trim()}`));
          return;
        }
        resolve({ text: parseClaudeCliResult(stdout) });
      });
      child.stdin.write(prompt);
      child.stdin.end();
    });
}

// ---------------------------------------------------------------------------
// The agent brief
// ---------------------------------------------------------------------------

/** One line per identity: how the agent authenticates its own curl/bash probes. */
function formatIdentities(sessions: Map<string, IdentitySession>): string[] {
  const lines: string[] = [];
  for (const [name, s] of sessions) {
    if (name === UNAUTH_SESSION) {
      lines.push(`- ${name}: no credentials — send the request with no Authorization header`);
      continue;
    }
    const parts: string[] = [];
    if (s.authorization) parts.push(`Authorization: ${s.authorization}`);
    if (s.cookie) parts.push(`Cookie: ${s.cookie}`);
    lines.push(`- ${name}: ${parts.length ? parts.join("  ") : "(login yielded no credential)"}`);
  }
  return lines;
}

/** The JSON contract the agent must end on — kept verbatim in the brief so the
 *  model emits exactly what `SubmitFindingsSchema` / `candidateToFinding` expect. */
export const OUTPUT_CONTRACT = [
  "{",
  '  "findings": [',
  "    {",
  '      "endpoint": "/api/Users/2",',
  '      "method": "GET",',
  '      "attacker_identity": "<one of the identity names above>",',
  '      "private_field": "email",',
  '      "victim_marker": "<a value unique to the VICTIM\'s object that leaked>",',
  '      "attacker_marker": "<the attacker\'s own equivalent value (optional)>",',
  '      "severity": "high",',
  '      "attacker_response": { "status": 200, "body": "<body you saw AS the attacker>" },',
  '      "unauth_response":   { "status": 401, "body": "<body you saw UNAUTHENTICATED>" }',
  "    }",
  "  ],",
  '  "hypotheses": [',
  '    { "target_endpoint": "/api/Orders/{id}", "hypothesis": "…", "signal_evidence": "…" }',
  "  ]",
  "}",
].join("\n");

/**
 * Build the agent's stdin brief: the injected IDOR playbook (methodology), then
 * the concrete engagement context — the target base URL, the captured identity
 * session tokens (so the agent can `curl -H "Authorization: Bearer …"`), the
 * id-bearing endpoints, and the unauthenticated option — then the required JSON
 * output contract. The agent probes with its OWN bash/curl.
 */
export function buildAgentBrief(
  playbook: string,
  ctx: HunterContext,
  sessions: Map<string, IdentitySession>,
  base: string,
): string {
  const alreadyTried = ctx.alreadyTried.map((k) => `${k.endpoint} [${k.session}]`);
  return [
    playbook.trim(),
    "",
    "## This engagement",
    "",
    `- Target base URL: ${base}`,
    `- Surface: ${ctx.surface}`,
    `- Id-bearing endpoints handed to you: ${JSON.stringify(ctx.endpoints)}`,
    `- Already-fired probes (context; you fire your own now): ${JSON.stringify(alreadyTried)}`,
    "",
    "## Identities — use these to authenticate your own `curl`/`bash` probes",
    "",
    ...formatIdentities(sessions),
    "",
    "## How to work",
    "",
    "You have `bash` and `curl`. Fire your own requests against the target.",
    "",
    "1. Baseline: read an id-bearing object as one identity.",
    "2. Mutate: swap the object id and/or switch identity to reach ANOTHER",
    "   principal's private data. Fire the SAME object unauthenticated too.",
    "3. Prove cross-tenant: a candidate is real only when the victim's private",
    "   marker leaks to the attacking identity AND is denied/absent unauthenticated",
    "   (not public-by-design, not the attacker's own data).",
    "",
    "## Required output",
    "",
    "When done, emit a SINGLE JSON object — and nothing after it — with this exact",
    "shape. Report BOTH responses faithfully; a code oracle (not you) confirms it.",
    "Report weaker leads as `hypotheses`. If you find nothing solid, emit",
    '`{ "findings": [], "hypotheses": [...] }`.',
    "",
    "```json",
    OUTPUT_CONTRACT,
    "```",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Candidate-JSON extraction (robust to prose around the object)
// ---------------------------------------------------------------------------

/** Scan `text` for every balanced, top-level `{…}` region that parses as JSON,
 *  in order. String literals (and their escapes) are respected so a `}` inside a
 *  string does not close the object early. */
function scanJsonObjects(text: string): unknown[] {
  const objs: unknown[] = [];
  let depth = 0;
  let start = -1;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
    } else if (c === "{") {
      if (depth === 0) start = i;
      depth += 1;
    } else if (c === "}") {
      if (depth > 0) {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          try {
            objs.push(JSON.parse(text.slice(start, i + 1)));
          } catch {
            // Not valid JSON — skip this region.
          }
          start = -1;
        }
      }
    }
  }
  return objs;
}

/**
 * Pull the candidate contract object out of the agent's final result text. The
 * agent may wrap the JSON in prose or a fenced block; we take the LAST balanced
 * object that carries a `findings` key (the contract), falling back to the last
 * parseable object. Returns null when there is no JSON object at all.
 */
export function extractSubmitJson(text: string): unknown | null {
  const objs = scanJsonObjects(text);
  for (let i = objs.length - 1; i >= 0; i -= 1) {
    const o = objs[i];
    if (o && typeof o === "object" && "findings" in (o as Record<string, unknown>)) {
      return o;
    }
  }
  return objs.length ? objs[objs.length - 1]! : null;
}

// ---------------------------------------------------------------------------
// The hunter runner
// ---------------------------------------------------------------------------

export interface ClaudeIdorHunterDeps {
  /** The injectable `claude`-agent seam (default `spawnClaudeAgent`). */
  agent: ClaudeAgentRunner;
  /** Captured sessions keyed by identity name (+ the implicit unauth identity). */
  sessions: Map<string, IdentitySession>;
  /** Engagement target base URL (for the PoC's default `$TARGET` + the brief). */
  base: string;
  /** The injected IDOR playbook (methodology) — heads the agent brief. */
  playbook: string;
  /** Records one LLM call (one agent spawn) against `max_llm_calls`. */
  onLlmCall?: () => void;
  /** Capability tier -> model (fast=haiku, standard=sonnet, smart=opus). */
  level?: Level;
}

/**
 * Build the first-party `claude`-agent IDOR hunter as a `HunterRunner`. It drops
 * into the SAME pipeline seam Slices 1 & 2 used (real transport + oracle verifier
 * downstream), but discovers the bug by spawning a `claude` agent whose final
 * JSON is fed through the unchanged `candidateToFinding` path. Malformed/empty
 * agent output yields no findings — a labelled empty yield, never a crash.
 */
export function createClaudeIdorHunterRunner(deps: ClaudeIdorHunterDeps): HunterRunner {
  return async (ctx: HunterContext): Promise<HunterYield> => {
    const model = modelForLevel(deps.level ?? "standard");
    const prompt = buildAgentBrief(deps.playbook, ctx, deps.sessions, deps.base);

    deps.onLlmCall?.();
    let text: string;
    try {
      const res = await deps.agent({ prompt, model });
      text = res.text;
    } catch {
      // A failed spawn / dead agent is a labelled empty yield, not an abort.
      return { findings: [], hypotheses: [] };
    }

    const raw = extractSubmitJson(text);
    if (raw == null) return { findings: [], hypotheses: [] };
    const parsed = SubmitFindingsSchema.safeParse(raw);
    if (!parsed.success) return { findings: [], hypotheses: [] };

    return submitFindingsToYield(parsed.data, deps.sessions, deps.base);
  };
}
