// The capable LLM IDOR hunter (Phase 1 · Slice 2).
//
// Replaces Slice 1's hardcoded probe: instead of firing a handed list of specs,
// a real model DISCOVERS the bug itself. It runs on the agent tool-loop with a
// full toolset — deliberately NOT restricted to one tool:
//
//   - `http_request` — the integrated, identity/unauth-aware probe path. Every
//     call routes through `ctx.fire` (the SAME dedupe + rate-limit-token + ledger
//     firer the whole orchestrator uses), so scope / rate-limit / no-repeat hold
//     by construction, and the structured {status, body} is fed back to the model
//     so it can reason over the response. This is the preferred path for probes
//     that become findings.
//   - `bash` — general shell for everything else a real hunter does (decode a
//     JWT, `jq` a body, run a discovery tool, scratch a script). Injected so it is
//     testable offline; probes fired via raw bash bypass the ledger (acceptable
//     for one hunter this phase — see the issue note).
//   - the injected IDOR playbook as the system prompt (methodology, not guessing).
//
// The terminal `submit_findings` tool carries the model's structured differential
// for each candidate — the endpoint, the leaked victim marker, and the response
// it saw as the attacker AND unauthenticated. From that the hunter DETERMINISTICALLY
// builds the Slice-1 finding shape (`buildIdorFinding`): a self-checking `poc.sh`
// plus `evidence/oracle.json`. The unchanged Slice-1 oracle is still the sole
// confirmation gate — the model discovers, the code proves. Interesting-but-
// unconfirmed signals ride along as `hypotheses`.

import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { defaultPromptsDir } from "../hunters/framework.ts";
import type {
  HunterContext,
  HunterFinding,
  HunterRunner,
  HunterYield,
  ReactiveHypothesisInput,
} from "../hunters/framework.ts";
import type { Level } from "../llm.ts";
import { runToolLoop, type AgentTool, type MessagesClient } from "../agent/tool-loop.ts";
import { IdorProbeSpecSchema, buildIdorFinding } from "./probe.ts";
import { decodeProbeEvidence, type IdentitySession } from "./transport.ts";
import type { DifferentialResponse } from "./oracle.ts";

// ---------------------------------------------------------------------------
// The bash tool seam
// ---------------------------------------------------------------------------

/** Result of running a shell command for the `bash` tool. */
export interface BashResult {
  stdout: string;
  stderr: string;
  exit_code: number;
}

/** Runs a shell command. Injected so the hunter is unit-testable without a real
 *  shell; the default (`spawnBashExecutor`) spawns `bash -c` in `cwd`. */
export type BashExecutor = (command: string) => Promise<BashResult>;

/** Default executor: run `bash -c <command>` in `cwd`, capturing streams. */
export function spawnBashExecutor(cwd: string): BashExecutor {
  return (command) =>
    new Promise<BashResult>((resolve, reject) => {
      const child = spawn("bash", ["-c", command], { cwd });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d.toString()));
      child.stderr.on("data", (d) => (stderr += d.toString()));
      child.on("error", reject);
      child.on("close", (code) => resolve({ exit_code: code ?? 0, stdout, stderr }));
    });
}

// ---------------------------------------------------------------------------
// Tool input schemas
// ---------------------------------------------------------------------------

/** `http_request` — fire a probe as a chosen identity (or unauthenticated). */
export const HttpRequestInputSchema = z.object({
  endpoint: z.string().min(1),
  method: z.string().default("GET"),
  /** Identity name to fire as; use the unauth identity name for no credential. */
  identity: z.string().min(1),
});

/** `bash` — run an arbitrary shell command. */
export const BashInputSchema = z.object({ command: z.string().min(1) });

/** One side of a candidate's differential, as the model reports it. */
const ResponseInputSchema = z.object({ status: z.number(), body: z.string() });

/** One candidate the model submits. It supplies the discovered differential; the
 *  hunter builds the self-checking PoC + oracle.json deterministically from it. */
export const LlmIdorCandidateSchema = z.object({
  endpoint: z.string().min(1),
  method: z.string().default("GET"),
  /** Identity that leaked the victim's data (a captured session name). */
  attacker_identity: z.string().min(1),
  private_field: z.string().min(1),
  /** A value unique to the VICTIM's object; its leak is the cross-tenant signal. */
  victim_marker: z.string().min(1),
  /** The attacker's own equivalent value (own-data guard), optional. */
  attacker_marker: z.string().optional(),
  severity: z.string().default("high"),
  /** The victim object read AS the attacker (2xx + leaked marker => cross-tenant). */
  attacker_response: ResponseInputSchema,
  /** The SAME object read UNAUTHENTICATED (denied/absent => not public-by-design). */
  unauth_response: ResponseInputSchema,
});
export type LlmIdorCandidate = z.infer<typeof LlmIdorCandidateSchema>;

/** The terminal `submit_findings` payload. */
export const SubmitFindingsSchema = z.object({
  findings: z.array(LlmIdorCandidateSchema).default([]),
  hypotheses: z
    .array(
      z.object({
        target_endpoint: z.string().min(1),
        hypothesis: z.string().min(1),
        signal_evidence: z.string().default(""),
      }),
    )
    .default([]),
});

export const HTTP_REQUEST_TOOL = "http_request";
export const BASH_TOOL = "bash";
export const SUBMIT_FINDINGS_TOOL = "submit_findings";

/** The hand-written IDOR playbook shipped as the hunter's methodology context. */
export const IDOR_PLAYBOOK_FILE = "idor-playbook.md";

/** Load the injected IDOR playbook (methodology) from `v2/prompts/`. */
export async function loadIdorPlaybook(dir = defaultPromptsDir()): Promise<string> {
  return fs.readFile(path.join(dir, IDOR_PLAYBOOK_FILE), "utf8");
}

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

/**
 * Build the hunter's system prompt: the injected IDOR playbook, then the cell
 * context (endpoints, the identities it can fire as, the already-tried probe
 * keys). The playbook is the methodology; the context is the concrete brief.
 */
export function buildHunterSystemPrompt(
  playbook: string,
  ctx: HunterContext,
  identities: string[],
): string {
  const alreadyTried = ctx.alreadyTried.map((k) => `${k.endpoint} [${k.session}]`);
  return [
    playbook.trim(),
    "",
    "## This engagement",
    "",
    `- Surface: ${ctx.surface}`,
    `- Endpoints handed to you: ${JSON.stringify(ctx.endpoints)}`,
    `- Identities you can fire as (the \`identity\` arg to http_request): ${JSON.stringify(identities)}`,
    `- Already-fired probes (do NOT re-fire; the ledger will refuse duplicates): ${JSON.stringify(alreadyTried)}`,
    "",
    "## How to work",
    "",
    "1. Baseline: read an id-bearing object as one identity via `http_request`.",
    "2. Mutate: swap the object id and/or switch `identity` to another user to reach",
    "   another principal's private data. Fire the SAME object unauthenticated too.",
    "3. Use `bash` for anything else (decode a token, `jq` a body, scratch a script).",
    "4. When you have a cross-tenant read that is denied/absent unauthenticated, call",
    `   \`${SUBMIT_FINDINGS_TOOL}\` with each candidate's endpoint, the leaked`,
    "   `victim_marker`, the attacking `identity`, and BOTH responses you saw",
    "   (attacker + unauth). A code oracle — not you — confirms it, so report the",
    "   responses faithfully. Record weaker leads as `hypotheses`.",
  ].join("\n");
}

// ---------------------------------------------------------------------------
// Tool wiring
// ---------------------------------------------------------------------------

/** The `http_request` tool, backed by the orchestrator's `ctx.fire`. A duplicate
 *  or rate-limited probe is reported back to the model rather than firing. */
export function httpRequestTool(ctx: HunterContext): AgentTool {
  return {
    name: HTTP_REQUEST_TOOL,
    description:
      "Fire an HTTP request against the target as a chosen identity (or the " +
      "unauthenticated identity). Routes through the scoped, rate-limited, " +
      "deduped ledger path. Returns { status, body } — or a refusal if the probe " +
      "is a duplicate or rate-limited.",
    input_schema: {
      type: "object",
      properties: {
        endpoint: { type: "string", description: "Path or absolute URL to request." },
        method: { type: "string", description: "HTTP method (default GET)." },
        identity: {
          type: "string",
          description: "Identity name to fire as (the unauth identity for no credential).",
        },
      },
      required: ["endpoint", "identity"],
    },
    handler: async (raw) => {
      const input = HttpRequestInputSchema.parse(raw);
      const fire = await ctx.fire({
        endpoint: input.endpoint,
        method: input.method,
        payload_id: "llm-http",
        payload: `${input.method}:${input.endpoint}`,
        session: input.identity,
      });
      if (!fire.fired) return { fired: false, reason: fire.reason };
      const { status, body } = decodeProbeEvidence(fire.result.evidence);
      return { fired: true, status, body };
    },
  };
}

/** The general-purpose `bash` tool. */
export function bashTool(bash: BashExecutor): AgentTool {
  return {
    name: BASH_TOOL,
    description:
      "Run a shell command (decode a JWT, jq a response, run a discovery tool, " +
      "write a scratch script). Returns { stdout, stderr, exit_code }. NOTE: raw " +
      "requests fired here bypass the ledger — prefer http_request for probes.",
    input_schema: {
      type: "object",
      properties: { command: { type: "string", description: "The shell command to run." } },
      required: ["command"],
    },
    handler: async (raw) => {
      const { command } = BashInputSchema.parse(raw);
      return bash(command);
    },
  };
}

/** The terminal `submit_findings` tool (handler never runs — the loop intercepts). */
export function submitFindingsTool(): AgentTool {
  return {
    name: SUBMIT_FINDINGS_TOOL,
    description:
      "Submit your candidate IDOR findings and any weaker hypotheses, ending the " +
      "hunt. Each finding must carry the endpoint, the leaked victim_marker, the " +
      "attacking identity, and BOTH the attacker and unauthenticated responses.",
    input_schema: {
      type: "object",
      properties: {
        findings: { type: "array", items: { type: "object" } },
        hypotheses: { type: "array", items: { type: "object" } },
      },
    },
    handler: () => {
      throw new Error("submit_findings is the terminal tool — its handler is never invoked");
    },
  };
}

// ---------------------------------------------------------------------------
// Candidate -> finding
// ---------------------------------------------------------------------------

/** Build the Slice-1 finding (self-checking poc.sh + oracle.json) from one
 *  model-submitted candidate. Reuses `buildIdorFinding` so the confirmed-format
 *  and the oracle input are identical to Slice 1. */
export function candidateToFinding(
  candidate: LlmIdorCandidate,
  sessions: Map<string, IdentitySession>,
  base: string,
): HunterFinding {
  const spec = IdorProbeSpecSchema.parse({
    endpoint: candidate.endpoint,
    method: candidate.method,
    attacker: candidate.attacker_identity,
    private_field: candidate.private_field,
    victim_marker: candidate.victim_marker,
    attacker_marker: candidate.attacker_marker,
    severity: candidate.severity,
  });
  const attacker: DifferentialResponse = candidate.attacker_response;
  const unauth: DifferentialResponse = candidate.unauth_response;
  return buildIdorFinding(spec, base, sessions.get(candidate.attacker_identity), attacker, unauth);
}

// ---------------------------------------------------------------------------
// The hunter runner
// ---------------------------------------------------------------------------

export interface LlmIdorHunterDeps {
  client: MessagesClient;
  /** Captured sessions keyed by identity name (+ the implicit unauth identity). */
  sessions: Map<string, IdentitySession>;
  /** Engagement target base URL (for the PoC's default `$TARGET`). */
  base: string;
  /** The injected IDOR playbook (methodology) — becomes the system prompt head. */
  playbook: string;
  /** The shell executor for the `bash` tool. */
  bash: BashExecutor;
  /** Records one LLM call against the engagement's `max_llm_calls` budget. */
  onLlmCall?: () => void;
  /** Model turn cap (default 20). */
  maxTurns?: number;
  /** Capability tier for the hunter model (default `standard`). */
  level?: Level;
}

/**
 * Build the capable LLM IDOR hunter as a `HunterRunner`. It drops into the SAME
 * pipeline seam Slice 1's hardcoded runner used (real transport + oracle
 * verifier downstream), but discovers the bug via the tool-loop rather than
 * firing handed specs.
 */
export function createLlmIdorHunterRunner(deps: LlmIdorHunterDeps): HunterRunner {
  return async (ctx: HunterContext): Promise<HunterYield> => {
    const identities = [...deps.sessions.keys()];
    const tools: AgentTool[] = [
      httpRequestTool(ctx),
      bashTool(deps.bash),
      submitFindingsTool(),
    ];
    const system = buildHunterSystemPrompt(deps.playbook, ctx, identities);

    const result = await runToolLoop({
      client: deps.client,
      system,
      prompt:
        "Hunt this cell for cross-tenant IDOR. Establish a baseline, mutate ids / " +
        "switch identity, and submit any confirmed cross-tenant read via " +
        `${SUBMIT_FINDINGS_TOOL}. If you find nothing solid, submit your hypotheses.`,
      tools,
      terminalTool: SUBMIT_FINDINGS_TOOL,
      maxTurns: deps.maxTurns ?? 20,
      level: deps.level,
      onLlmCall: deps.onLlmCall,
    });

    // No terminal call (turn cap / end_turn without submitting) => nothing to
    // emit. The probes it did fire are already in the ledger; a non-submitting
    // run is a labelled empty yield, not a crash.
    if (result.stop !== "terminal" || result.terminal == null) {
      return { findings: [], hypotheses: [] };
    }

    const payload = SubmitFindingsSchema.parse(result.terminal);
    const findings: HunterFinding[] = payload.findings.map((c) =>
      candidateToFinding(c, deps.sessions, deps.base),
    );
    const hypotheses: ReactiveHypothesisInput[] = payload.hypotheses.map((h) => ({
      target_endpoint: h.target_endpoint,
      hypothesis: h.hypothesis,
      signal_evidence: h.signal_evidence,
    }));
    return { findings, hypotheses };
  };
}
