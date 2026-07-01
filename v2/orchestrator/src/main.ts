#!/usr/bin/env bun
// BugBountyHunter v2 orchestrator CLI.
//
// Slice 0 ships one command: `hello` — an end-to-end smoke that proves the
// runtime, the LLM client, the state layer, the rate-limit governor, and the
// Juice Shop test target all work together before any pentest logic exists.

import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { complete } from "./llm.ts";
import {
  initialState,
  readState,
  transition,
  writeState,
} from "./state.ts";
import { acquireToken, startTokenServer, TokenBucket } from "./ratelimit.ts";
import {
  loadScope,
  coverageGapLogger,
  ScopeSchema,
  type Scope,
} from "./scope.ts";
import { acquireAuth, type LoginOutcome } from "./auth.ts";
import {
  runRecon,
  type ReconAgentContext,
  type ReconResult,
} from "./recon.ts";
import {
  JUICE_SHOP_URL,
  composeDown,
  composeUp,
  waitForJuiceShop,
} from "./test-target.ts";

async function hello(): Promise<void> {
  const workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-hello-"));
  console.log(`[hello] workdir: ${workdir}`);

  // 1. Rate-limit governor.
  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[hello] token endpoint: ${tokens.url}/token`);

  try {
    // 2. Test target up + reachable.
    console.log("[hello] bringing up Juice Shop via docker compose...");
    await composeUp();
    await waitForJuiceShop();
    console.log(`[hello] Juice Shop reachable at ${JUICE_SHOP_URL}`);

    // 3. One LLM call through the vendored client.
    const reply = await complete({
      level: "fast",
      prompt: 'Reply with exactly the word "pong" and nothing else.',
      maxTokens: 16,
    });
    console.log(`[hello] LLM replied: ${reply.trim()}`);

    // 4. Zod-validated state.json, written then re-read.
    const state = initialState("hello-smoke", JUICE_SHOP_URL);
    await writeState(workdir, state);
    const back = await readState(workdir);
    if (back.engagement_id !== state.engagement_id) {
      throw new Error("state.json round-trip mismatch");
    }
    console.log("[hello] state.json written and re-validated OK");

    console.log("[hello] SUCCESS");
  } finally {
    // 5. Teardown — always, even on failure.
    await tokens.close().catch(() => {});
    console.log("[hello] tearing down Juice Shop...");
    await composeDown().catch((err) =>
      console.error(`[hello] teardown warning: ${String(err)}`),
    );
  }
}

/** Load scope.yaml from cwd, or synthesize a minimal target-only scope. */
async function resolveScope(target: string): Promise<Scope> {
  const scopePath = path.resolve(process.cwd(), "scope.yaml");
  try {
    const text = await fs.readFile(scopePath, "utf8");
    console.log(`[pentest] loaded scope from ${scopePath}`);
    return loadScope(text);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    console.log(
      `[pentest] no scope.yaml found; synthesizing a target-only scope for ${target}`,
    );
    return ScopeSchema.parse({ target });
  }
}

/**
 * Drive the dev-browser login. Delegated to the auth-acquire agent
 * (v2/prompts/auth-acquire.md) which needs a headed dev-browser — not wired in
 * this slice. Fails gracefully at that boundary, exactly as `hello` does at the
 * docker boundary, so the pipeline wiring can still be exercised end-to-end.
 */
async function browserLogin(_scope: Scope): Promise<LoginOutcome> {
  return {
    status: "failed",
    reason:
      "dev-browser login not wired in Slice 1 — see v2/prompts/auth-acquire.md",
  };
}

/**
 * Run one recon agent (R1-R4). Delegated to the spawned agent driven by
 * `v2/prompts/recon-r{1..4}-*.md`, which crawls / scans / analyses through the
 * scope-enforced fetch and the governor's token endpoint — not wired in this
 * slice. Returns an empty result (with a note) so the pipeline advances
 * `recon → plan` gracefully, exactly as `browserLogin` stubs Stage 0.
 */
async function reconAgentStub(ctx: ReconAgentContext): Promise<ReconResult> {
  return {
    agent: ctx.agent,
    endpoints: [],
    tech: {},
    notes: [
      `recon agent ${ctx.agent} not wired in Slice 2 — see v2/prompts/recon-*.md`,
    ],
  };
}

/**
 * Stage 0 + Stage 1 driver. Reads scope, initializes state, runs the auth stage
 * through the scope-enforced login, and — on a successful session — runs Stage 1
 * recon (R1-R4 in parallel), merging into `recon/endpoints.json` +
 * `recon/surfaces.json` before advancing `recon → plan`.
 */
async function pentest(target?: string): Promise<void> {
  if (!target) {
    console.error("Usage: bbh pentest <target-url>");
    throw new Error("missing target");
  }
  const scope = await resolveScope(target);

  const workdir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-pentest-"));
  console.log(`[pentest] workdir: ${workdir}`);

  let state = initialState(`pentest-${path.basename(workdir)}`, target);
  await writeState(workdir, state);
  console.log(`[pentest] stage: ${state.current_stage}`);

  const logGap = coverageGapLogger(workdir);
  const plan = await acquireAuth(workdir, () => browserLogin(scope), {
    onCoverageGap: (gap) => {
      void logGap(gap);
      console.error(`[pentest] coverage_gap: ${gap.reason}`);
    },
  });

  state = transition(state, plan.event);
  await writeState(workdir, state);

  if (plan.event.type !== "advance") {
    console.error(
      `[pentest] auth halted: ${plan.event.type === "halt" ? plan.event.reason : ""}`,
    );
    console.error(`[pentest] state: ${state.status}`);
    return;
  }
  console.log(`[pentest] auth OK -> advanced to ${state.current_stage}`);

  // Stage 1 — parallel recon. Consumes rate-limit tokens from the governor and
  // is scope-enforced per agent. Best-effort: a failed agent logs a
  // coverage_gap and the survivors still merge before advancing recon -> plan.
  const tokens = await startTokenServer(new TokenBucket(5));
  console.log(`[pentest] token endpoint: ${tokens.url}/token`);
  try {
    const recon = await runRecon(workdir, {
      scope,
      runner: reconAgentStub,
      takeToken: () => acquireToken(tokens.url),
      onCoverageGap: (gap) => {
        void logGap(gap);
        console.error(`[pentest] coverage_gap: ${gap.reason}`);
      },
    });
    state = transition(state, recon.event);
    await writeState(workdir, state);
    console.log(
      `[pentest] recon done: ${recon.endpoints.length} endpoints, ` +
        `${recon.surfaces.length} surfaces, ${recon.failed.length} agent failure(s)` +
        ` -> advanced to ${state.current_stage}`,
    );
  } finally {
    await tokens.close().catch(() => {});
  }
}

const COMMANDS: Record<string, (arg?: string) => Promise<void>> = {
  hello,
  pentest,
};

async function main(argv: string[]): Promise<number> {
  const command = argv[0];
  if (!command || !(command in COMMANDS)) {
    const known = Object.keys(COMMANDS).join(", ");
    console.error(`Usage: bbh <command> [args]\nCommands: ${known}`);
    return command ? 1 : 0;
  }
  await COMMANDS[command]!(argv[1]);
  return 0;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(`[bbh] error: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  });
