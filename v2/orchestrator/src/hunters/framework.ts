// Tier 1 hunter framework.
//
// A hunter is a scoped agent spawned for one `(surface × vuln class)` cell of
// the hunt plan. This framework is the mechanical shell around that agent,
// mirroring the pure/injectable seam used by auth/recon/plan: the agent itself
// (the probe-driving logic behind `v2/prompts/hunters/<class>.md`) is injected
// as a `HunterRunner`, and the network is injected as a `ProbeTransport`, so
// everything the orchestrator OWNS stays unit-testable without a live target or
// a live LLM.
//
// The heart is the **probe firer** (`createProbeFirer`): the single path a
// hunter fires through. Before any byte leaves the process it enforces, in
// order — (1) the ledger dedupe (`isDuplicateProbe` on the 3-tuple), so a probe
// already tried is refused without a network call; (2) the rate-limit token, so
// a denied token drops the probe rather than trampling the shared req/s; and
// only then fires the transport and appends the result to `ledger.jsonl`. The
// Verifier's re-fire path deliberately does NOT go through here — re-firing a
// known PoC is the point.
//
// Findings are emitted to `findings/<id>/`, each with a runnable `poc.sh` the
// Verifier re-fires — the "smallest mechanical floor" of the verify loop.

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import type { Scope } from "../scope.ts";
import {
  payloadSig,
  isDuplicateProbe,
  appendLedger,
  readLedger,
  ledgerEntryKey,
  LedgerResultSchema,
  LedgerEntrySchema,
  type LedgerEntry,
  type LedgerResult,
  type ProbeKey,
} from "./ledger.ts";

// ---------------------------------------------------------------------------
// Prompt template rendering (clear errors on missing variables)
// ---------------------------------------------------------------------------

const PLACEHOLDER = /\{\{\s*([\w.]+)\s*\}\}/g;

/** The unique `{{variable}}` names a template references, in first-seen order. */
export function templateVars(template: string): string[] {
  const seen = new Set<string>();
  for (const m of template.matchAll(PLACEHOLDER)) seen.add(m[1]!);
  return [...seen];
}

/**
 * Render a `{{variable}}` template. Any placeholder with no matching key makes
 * the whole render throw — and the error names EVERY missing variable, not just
 * the first. This is the issue's "no silent failures": a prompt that expects a
 * variable the orchestrator forgot to supply fails loudly, rather than spawning
 * a hunter with a silent hole in its brief.
 */
export function renderTemplate(
  template: string,
  vars: Record<string, string>,
): string {
  const missing = new Set<string>();
  const out = template.replace(PLACEHOLDER, (_m, key: string) => {
    if (!Object.prototype.hasOwnProperty.call(vars, key)) {
      missing.add(key);
      return "";
    }
    return vars[key]!;
  });
  if (missing.size > 0) {
    throw new Error(
      `Hunter prompt template: missing variable(s): ${[...missing].join(", ")}`,
    );
  }
  return out;
}

/** Default `v2/prompts` dir, resolved from this file's location. */
export function defaultPromptsDir(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..", "prompts");
}

export function hunterPromptPath(vulnClass: string, dir = defaultPromptsDir()): string {
  return path.join(dir, "hunters", `${vulnClass}.md`);
}

/** Load `hunters/<class>.md`; a missing template is a clear, actionable error. */
export async function loadHunterPrompt(
  vulnClass: string,
  dir = defaultPromptsDir(),
): Promise<string> {
  const file = hunterPromptPath(vulnClass, dir);
  try {
    return await fs.readFile(file, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`No hunter prompt for class "${vulnClass}" (looked in ${file})`);
    }
    throw err;
  }
}

/** Load + render a class prompt with the supplied variables. */
export async function renderHunterPrompt(
  vulnClass: string,
  vars: Record<string, string>,
  dir = defaultPromptsDir(),
): Promise<string> {
  return renderTemplate(await loadHunterPrompt(vulnClass, dir), vars);
}

// ---------------------------------------------------------------------------
// Payloads + finding schema
// ---------------------------------------------------------------------------

/** One payload from the corpus handed to a hunter. */
export const PayloadSchema = z.object({
  id: z.string().min(1),
  value: z.unknown(),
  notes: z.string().optional(),
});
export type Payload = z.infer<typeof PayloadSchema>;

/**
 * A candidate finding a hunter emits. `poc` is REQUIRED and non-empty — the
 * verify loop is meaningless without a re-runnable PoC, so a finding that ships
 * without one fails validation here rather than sailing on to be un-verifiable.
 * `evidence` is a `{ filename: contents }` map written under `evidence/`.
 */
export const HunterFindingSchema = z.object({
  title: z.string().min(1),
  severity: z.string().min(1).default("unknown"),
  endpoint: z.string().min(1),
  method: z.string().default("GET"),
  vuln_class: z.string().min(1),
  poc: z.string().min(1),
  response: z.unknown().optional(),
  evidence: z.record(z.string(), z.string()).default({}),
  notes: z.string().optional(),
});
export type HunterFinding = z.infer<typeof HunterFindingSchema>;

// ---------------------------------------------------------------------------
// Probe firer — dedupe + token + ledger, the end-to-end repeat guard
// ---------------------------------------------------------------------------

/** A probe a hunter wants to fire. `payload` is the concrete value fired; its
 *  signature (`payloadSig`) is the second leg of the dedupe key. */
export interface ProbeRequest {
  endpoint: string;
  method?: string;
  payload_id: string;
  payload: unknown;
  session: string;
  context?: Record<string, unknown>;
}

/** The network seam: turn a probe into a result. Injected so the framework is
 *  testable without a live target; the real transport routes through the scoped
 *  fetch. */
export type ProbeTransport = (probe: ProbeRequest) => Promise<LedgerResult>;

/** Outcome of asking the firer to fire a probe. */
export type FireResult =
  | { fired: true; result: LedgerResult }
  | { fired: false; reason: "duplicate" | "rate_limited" };

/** A bound firer: one call fires (or refuses) one probe. */
export type ProbeFirer = (probe: ProbeRequest) => Promise<FireResult>;

export interface ProbeFirerConfig {
  workdir: string;
  pass: number;
  agent: string;
  surface: string;
  vuln_class: string;
  /** The known ledger. Mutated in place: appended probes are pushed on so a
   *  later fire in the same run sees them as duplicates. */
  ledger: LedgerEntry[];
  takeToken: () => Promise<boolean>;
  transport: ProbeTransport;
  now?: () => string;
}

/**
 * Build the firer a hunter fires every probe through. Guarantees, in order:
 *   1. dedupe — a probe whose `(endpoint, payload_sig, session)` is already in
 *      the ledger is refused (`duplicate`) without touching the network;
 *   2. rate limit — a denied governor token refuses the probe (`rate_limited`)
 *      without firing or logging;
 *   3. fire + record — the transport runs and the result is appended to
 *      `ledger.jsonl` and pushed onto the in-memory ledger.
 */
export function createProbeFirer(cfg: ProbeFirerConfig): ProbeFirer {
  const now = cfg.now ?? (() => new Date().toISOString());
  return async (probe: ProbeRequest): Promise<FireResult> => {
    const sig = payloadSig(probe.payload);
    const key: ProbeKey = {
      endpoint: probe.endpoint,
      payload_sig: sig,
      session: probe.session,
    };
    if (isDuplicateProbe(key, cfg.ledger)) {
      return { fired: false, reason: "duplicate" };
    }
    if (!(await cfg.takeToken())) {
      return { fired: false, reason: "rate_limited" };
    }
    const result = LedgerResultSchema.parse(await cfg.transport(probe));
    const entry: LedgerEntry = LedgerEntrySchema.parse({
      ts: now(),
      pass: cfg.pass,
      agent: cfg.agent,
      surface: cfg.surface,
      endpoint: probe.endpoint,
      method: probe.method ?? "GET",
      class: cfg.vuln_class,
      payload_id: probe.payload_id,
      payload_sig: sig,
      context: { session: probe.session, ...(probe.context ?? {}) },
      result,
    });
    await appendLedger(cfg.workdir, entry);
    cfg.ledger.push(entry);
    return { fired: true, result };
  };
}

// ---------------------------------------------------------------------------
// Findings emission
// ---------------------------------------------------------------------------

export function findingsDir(workdir: string): string {
  return path.join(workdir, "findings");
}

export function findingDir(workdir: string, id: string): string {
  return path.join(findingsDir(workdir), id);
}

/**
 * Next `f-NNNN` id, continuing past any findings already on disk so a re-run (or
 * a second hunter) never collides. Deterministic given directory contents.
 */
export async function nextFindingSeq(workdir: string): Promise<number> {
  let entries: string[] = [];
  try {
    entries = await fs.readdir(findingsDir(workdir));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  let max = 0;
  for (const name of entries) {
    const m = /^f-(\d+)$/.exec(name);
    if (m) max = Math.max(max, parseInt(m[1]!, 10));
  }
  return max + 1;
}

/** Build the `poc.sh` body: a self-contained, runnable re-fire script. */
function pocScript(finding: HunterFinding, id: string): string {
  const body = finding.poc.trim();
  if (body.startsWith("#!")) return body.endsWith("\n") ? body : body + "\n";
  return [
    "#!/usr/bin/env bash",
    `# PoC re-fire for finding ${id} — ${finding.title}`,
    `# ${finding.method} ${finding.endpoint}  (class=${finding.vuln_class})`,
    "# Auto-generated by the Tier 1 hunter. The Verifier re-fires this verbatim.",
    "set -euo pipefail",
    "",
    body,
    "",
  ].join("\n");
}

/**
 * Persist one candidate finding to `findings/<id>/`:
 *   - `poc.sh`        — runnable (0755) re-fire script,
 *   - `response.json` — the captured response,
 *   - `evidence/<name>` — supporting artifacts (names are basename-only so a
 *     malicious `../` name cannot escape the finding dir),
 *   - `finding.json`  — metadata for the Verifier.
 * Returns the finding directory path.
 */
export async function writeFinding(
  workdir: string,
  id: string,
  finding: HunterFinding,
): Promise<string> {
  const dir = findingDir(workdir, id);
  await fs.mkdir(dir, { recursive: true });

  const pocPath = path.join(dir, "poc.sh");
  await fs.writeFile(pocPath, pocScript(finding, id), "utf8");
  await fs.chmod(pocPath, 0o755);

  const respContent =
    typeof finding.response === "string"
      ? finding.response
      : JSON.stringify(finding.response ?? {}, null, 2);
  await fs.writeFile(path.join(dir, "response.json"), respContent + "\n", "utf8");

  const evidence = Object.entries(finding.evidence);
  if (evidence.length > 0) {
    const evDir = path.join(dir, "evidence");
    await fs.mkdir(evDir, { recursive: true });
    for (const [name, content] of evidence) {
      // basename-only: a name like `../escape.txt` cannot write outside evDir.
      await fs.writeFile(path.join(evDir, path.basename(name)), content, "utf8");
    }
  }

  await fs.writeFile(
    path.join(dir, "finding.json"),
    JSON.stringify(
      {
        id,
        title: finding.title,
        severity: finding.severity,
        vuln_class: finding.vuln_class,
        endpoint: finding.endpoint,
        method: finding.method,
        poc: "poc.sh",
        ...(finding.notes ? { notes: finding.notes } : {}),
      },
      null,
      2,
    ) + "\n",
    "utf8",
  );

  return dir;
}

// ---------------------------------------------------------------------------
// Stage orchestration — run one hunter
// ---------------------------------------------------------------------------

export interface HunterContext {
  agent: string;
  surface: string;
  vuln_class: string;
  endpoints: string[];
  payloads: Payload[];
  /** The account/identity this cell probes under (dedupe key's 3rd leg). */
  session: string;
  pass: number;
  /** Ledger slice for this (surface, class), pre-injected as dedupe keys so the
   *  agent can steer clear of repeats (PRD's hybrid memory pattern). */
  alreadyTried: ProbeKey[];
  /** The single path a probe fires through — dedupe + token + ledger. */
  fire: ProbeFirer;
  /** Consume one rate-limit token (for non-probe requests the agent makes). */
  takeToken: () => Promise<boolean>;
}

/** Injected agent implementation: probe the cell via `ctx.fire`, return findings. */
export type HunterRunner = (
  ctx: HunterContext,
) => Promise<{ findings: HunterFinding[] }>;

export interface RunHunterOptions {
  runner: HunterRunner;
  scope: Scope;
  surface: string;
  vuln_class: string;
  endpoints: string[];
  payloads: Payload[];
  transport: ProbeTransport;
  agent?: string;
  session?: string;
  pass?: number;
  takeToken?: () => Promise<boolean>;
  now?: () => string;
}

export interface WrittenFinding {
  id: string;
  dir: string;
  finding: HunterFinding;
}

export interface HunterOutcome {
  agent: string;
  surface: string;
  vuln_class: string;
  probesFired: number;
  duplicatesSkipped: number;
  findings: WrittenFinding[];
}

/**
 * Run a single Tier 1 hunter over one hunt-plan cell. Reads the ledger,
 * pre-injects the `(surface, class)` ALREADY_TRIED slice + a dedupe-and-token
 * enforcing `fire`, runs the injected agent, and writes every finding to
 * `findings/<id>/`. Because the firer refuses duplicates before firing, a
 * re-run of the same hunter re-fires nothing.
 */
export async function runHunter(
  workdir: string,
  opts: RunHunterOptions,
): Promise<HunterOutcome> {
  const agent = opts.agent ?? `H-${opts.vuln_class}`;
  const session = opts.session ?? opts.scope.auth.username ?? "default";
  const pass = opts.pass ?? 0;
  const takeToken = opts.takeToken ?? (async () => true);

  const ledger = await readLedger(workdir);
  const alreadyTried = ledger
    .filter((e) => e.class === opts.vuln_class && e.surface === opts.surface)
    .map(ledgerEntryKey);

  let probesFired = 0;
  let duplicatesSkipped = 0;
  const baseFirer = createProbeFirer({
    workdir,
    pass,
    agent,
    surface: opts.surface,
    vuln_class: opts.vuln_class,
    ledger,
    takeToken,
    transport: opts.transport,
    now: opts.now,
  });
  const fire: ProbeFirer = async (probe) => {
    const out = await baseFirer(probe);
    if (out.fired) probesFired += 1;
    else if (out.reason === "duplicate") duplicatesSkipped += 1;
    return out;
  };

  const ctx: HunterContext = {
    agent,
    surface: opts.surface,
    vuln_class: opts.vuln_class,
    endpoints: opts.endpoints,
    payloads: opts.payloads,
    session,
    pass,
    alreadyTried,
    fire,
    takeToken,
  };

  const { findings: rawFindings } = await opts.runner(ctx);

  const base = await nextFindingSeq(workdir);
  const findings: WrittenFinding[] = [];
  for (let i = 0; i < rawFindings.length; i += 1) {
    const id = `f-${String(base + i).padStart(4, "0")}`;
    const finding = HunterFindingSchema.parse(rawFindings[i]);
    const dir = await writeFinding(workdir, id, finding);
    findings.push({ id, dir, finding });
  }

  return {
    agent,
    surface: opts.surface,
    vuln_class: opts.vuln_class,
    probesFired,
    duplicatesSkipped,
    findings,
  };
}
