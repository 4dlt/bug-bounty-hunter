// Scope: the scope.yaml schema, the glob-based allowlist, and the single
// choke point every outbound request must pass through.
//
// The PRD's non-negotiable safety rule (user story 3, 39): the orchestrator
// must never send a request to an out-of-scope host. `checkScope` is the pure
// decision; `scopedFetch` is the only sanctioned way to issue an outbound
// request — it consults `checkScope` first and, on a block, records a
// `coverage_gap` and throws before any byte leaves the process.

import { promises as fs } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

export const BudgetSchema = z.object({
  max_probes: z.number().int().positive().default(10000),
  max_llm_calls: z.number().int().positive().default(2000),
  max_minutes: z.number().int().positive().default(480),
});
export type Budget = z.infer<typeof BudgetSchema>;

/**
 * Auth block. Credentials live in scope.yaml per PRD user story 2 (the hunter
 * places test-account creds so agents can probe authenticated surfaces without
 * prompting). `method: "none"` runs the engagement unauthenticated.
 */
export const AuthSchema = z
  .object({
    method: z.enum(["form", "none"]).default("form"),
    login_url: z.string().optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    // Optional signal the login succeeded (a substring expected on the
    // post-login page or in a set-cookie). Left to the auth-acquire agent.
    success_check: z.string().optional(),
  })
  .prefault({});
export type Auth = z.infer<typeof AuthSchema>;

export const ScopeSchema = z.object({
  target: z.string().min(1),
  // In-scope host globs. Empty => derive from the target host (see
  // `effectiveScopeGlobs`).
  scope: z.array(z.string()).default([]),
  // Out-of-scope host globs. Always take precedence over `scope`.
  out_of_scope: z.array(z.string()).default([]),
  auth: AuthSchema,
  min_payout_band: z.string().default("P3"),
  // Max Tier 1 hunters in flight during the parallel sweep (Stage 3). Tunable
  // per engagement; the default follows the PRD's 5-hunters-in-flight cap.
  sweep_concurrency: z.number().int().positive().default(5),
  budget: BudgetSchema.prefault({}),
});
export type Scope = z.infer<typeof ScopeSchema>;

/**
 * Parse scope.yaml text into a validated Scope. Wraps both the YAML syntax
 * error and the Zod validation error with a `scope.yaml`-tagged message so the
 * operator knows exactly which file to fix.
 */
export function loadScope(yamlText: string): Scope {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid scope.yaml (YAML syntax): ${msg}`);
  }
  const result = ScopeSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid scope.yaml (schema):\n${issues}`);
  }
  return result.data;
}

// ---------------------------------------------------------------------------
// Glob matching + scope decision
// ---------------------------------------------------------------------------

/** Extract a bare hostname from a URL or a bare host string. */
function hostOf(urlOrHost: string): string | null {
  try {
    return new URL(urlOrHost).hostname.toLowerCase();
  } catch {
    // Bare host (possibly host:port). Reject anything with a space or slash —
    // it is not a clean host and we do not want to guess.
    const trimmed = urlOrHost.trim();
    if (!trimmed || /[\s/]/.test(trimmed)) return null;
    return trimmed.split(":")[0]!.toLowerCase();
  }
}

/**
 * Match a hostname against a host glob. `*` matches one or more characters
 * within a label sequence; dots are literal. `*.target.com` therefore matches
 * `api.target.com` and `a.b.target.com` but not the apex `target.com`.
 */
export function matchesGlob(host: string, glob: string): boolean {
  const escaped = glob
    .toLowerCase()
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".+");
  return new RegExp(`^${escaped}$`).test(host.toLowerCase());
}

/** In-scope globs to enforce: explicit list, or the target host if empty. */
export function effectiveScopeGlobs(scope: Scope): string[] {
  if (scope.scope.length > 0) return scope.scope;
  const host = hostOf(scope.target);
  return host ? [host] : [];
}

export type ScopeDecision =
  | { allowed: true }
  | { allowed: false; reason: "out_of_scope" | "not_in_scope" | "unparseable" };

/**
 * Pure allowlist decision. Precedence: unparseable > out_of_scope > in_scope.
 * out_of_scope always wins over an in-scope match so a broad `*.target.com`
 * can never re-admit a specifically-excluded host.
 */
export function checkScope(scope: Scope, url: string): ScopeDecision {
  const host = hostOf(url);
  if (!host) return { allowed: false, reason: "unparseable" };

  if (scope.out_of_scope.some((g) => matchesGlob(host, g))) {
    return { allowed: false, reason: "out_of_scope" };
  }
  if (effectiveScopeGlobs(scope).some((g) => matchesGlob(host, g))) {
    return { allowed: true };
  }
  return { allowed: false, reason: "not_in_scope" };
}

// ---------------------------------------------------------------------------
// The outbound choke point
// ---------------------------------------------------------------------------

export interface CoverageGap {
  kind: "coverage_gap";
  // The blocked URL, or null for a non-request gap (e.g. an auth obstacle).
  url: string | null;
  host: string | null;
  reason: string;
}

export class ScopeError extends Error {
  readonly url: string;
  readonly reason: string;
  constructor(url: string, reason: string) {
    super(`Out-of-scope request blocked (${reason}): ${url}`);
    this.name = "ScopeError";
    this.url = url;
    this.reason = reason;
  }
}

/**
 * Append a coverage_gap to the engagement's append-only log. Append-only so the
 * blocked-request record is safe to write from any concurrent agent without a
 * lock (PRD: jsonl artifacts are append-only). Returns a recorder bound to the
 * workdir, suitable for the `onCoverageGap` hook of `scopedFetch`.
 */
export function coverageGapLogger(
  workdir: string,
): (gap: CoverageGap) => Promise<void> {
  const file = path.join(workdir, "coverage-gaps.jsonl");
  return async (gap: CoverageGap) => {
    await fs.mkdir(workdir, { recursive: true });
    await fs.appendFile(file, JSON.stringify(gap) + "\n", "utf8");
  };
}

export interface ScopedFetchDeps {
  fetch?: typeof fetch;
  onCoverageGap?: (gap: CoverageGap) => void;
}

/**
 * The ONLY sanctioned way to issue an outbound request. Consults `checkScope`
 * first; on a block it records a `coverage_gap` and throws `ScopeError` before
 * calling the underlying fetch. Every code path in the orchestrator that talks
 * to the target must go through here (PRD acceptance: "checkScope blocks
 * out-of-scope requests in every code path that issues HTTP").
 */
export async function scopedFetch(
  scope: Scope,
  url: string,
  init?: RequestInit,
  deps: ScopedFetchDeps = {},
): Promise<Response> {
  const decision = checkScope(scope, url);
  if (!decision.allowed) {
    deps.onCoverageGap?.({
      kind: "coverage_gap",
      url,
      host: hostOf(url),
      reason: decision.reason,
    });
    throw new ScopeError(url, decision.reason);
  }
  const doFetch = deps.fetch ?? fetch;
  return doFetch(url, init);
}
