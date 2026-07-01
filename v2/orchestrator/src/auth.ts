// Stage 0 — auth acquisition.
//
// Ports the methodology from v3-experimental's auth-acquire prompt: drive a
// login, capture the session (cookies + JWTs), write an `auth/state.json`
// artifact, and gate the pipeline on it — `auth` advances to `recon` only when
// a real session was captured. MFA / captcha halt the engagement with a clear
// `coverage_gap` rather than attempting a bypass (PRD acceptance criteria).
//
// The browser/HAR mechanics are left to an injected `login` function (a spawned
// dev-browser agent, per the issue's "agent is preferred" note) so the decision
// logic here is pure and unit-testable without a live target.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import type { CoverageGap } from "./scope.ts";
import type { Event } from "./state.ts";

export type { CoverageGap } from "./scope.ts";

// ---------------------------------------------------------------------------
// Artifact schema — auth/state.json
// ---------------------------------------------------------------------------

export const CookieSchema = z.object({
  name: z.string().min(1),
  value: z.string(),
  domain: z.string().min(1),
  path: z.string().optional(),
  expires: z.number().optional(),
  httpOnly: z.boolean().optional(),
  secure: z.boolean().optional(),
});

export const JwtSchema = z.object({
  name: z.string().min(1),
  token: z.string().min(1),
  // Where the token rides: an Authorization header, a cookie, localStorage…
  location: z.string().optional(),
  expires_at: z.string().optional(),
});

export const AuthArtifactSchema = z.object({
  acquired_at: z.string().min(1),
  cookies: z.array(CookieSchema).default([]),
  jwts: z.array(JwtSchema).default([]),
  // Optional opaque refresh material the monitor re-validates.
  refresh_token: z.string().optional(),
});
export type AuthArtifact = z.infer<typeof AuthArtifactSchema>;

export function authDir(workdir: string): string {
  return path.join(workdir, "auth");
}

export function authArtifactPath(workdir: string): string {
  return path.join(authDir(workdir), "state.json");
}

export async function writeAuthArtifact(
  workdir: string,
  art: AuthArtifact,
): Promise<void> {
  const validated = AuthArtifactSchema.parse(art);
  await fs.mkdir(authDir(workdir), { recursive: true });
  // Atomic-ish write: write a temp file then rename, so a monitor refresh never
  // exposes a half-written artifact to in-flight agents.
  const target = authArtifactPath(workdir);
  const tmp = `${target}.${process.pid}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(validated, null, 2) + "\n", "utf8");
  await fs.rename(tmp, target);
}

export async function readAuthArtifact(
  workdir: string,
): Promise<AuthArtifact> {
  const raw = await fs.readFile(authArtifactPath(workdir), "utf8");
  return AuthArtifactSchema.parse(JSON.parse(raw));
}

/** A captured session is only usable if it carries a cookie or a JWT. */
export function isAuthSuccessful(art: AuthArtifact): boolean {
  return art.cookies.length > 0 || art.jwts.length > 0;
}

// ---------------------------------------------------------------------------
// MFA / captcha detection
// ---------------------------------------------------------------------------

export interface AuthObstacle {
  kind: "mfa" | "captcha";
  evidence: string;
}

const CAPTCHA_PATTERNS = [/captcha/i, /recaptcha/i, /hcaptcha/i, /are you (a )?human/i];
const MFA_PATTERNS = [
  /\bmfa\b/i,
  /two[-\s]?factor/i,
  /\b2fa\b/i,
  /one[-\s]?time (code|password)/i,
  /\botp\b/i,
  /verification code/i,
  /authenticator app/i,
];

/** First pattern that matches `signal`, returned as its matched text. */
function firstMatch(signal: string, patterns: RegExp[]): string | null {
  for (const p of patterns) {
    const m = signal.match(p);
    if (m) return m[0];
  }
  return null;
}

/**
 * Inspect a login-response signal (page text, redirect URL, error body) for an
 * MFA or captcha challenge. Returns the obstacle, or null for an ordinary
 * login page. Captcha is checked first so a page mentioning both reports the
 * harder-blocking obstacle.
 */
export function detectAuthObstacle(signal: string): AuthObstacle | null {
  const captcha = firstMatch(signal, CAPTCHA_PATTERNS);
  if (captcha) return { kind: "captcha", evidence: captcha };
  const mfa = firstMatch(signal, MFA_PATTERNS);
  if (mfa) return { kind: "mfa", evidence: mfa };
  return null;
}

// ---------------------------------------------------------------------------
// Login outcome -> state transition
// ---------------------------------------------------------------------------

export type LoginOutcome =
  | { status: "success"; artifact: AuthArtifact }
  | { status: "obstacle"; obstacle: AuthObstacle }
  | { status: "failed"; reason: string };

export interface AuthPlan {
  event: Event;
  gap?: CoverageGap;
}

/**
 * Pure mapping from a login outcome to the pipeline event. This is the gate the
 * issue requires: `auth` advances to `recon` ONLY on a successful artifact that
 * actually carries session material; every other outcome halts. MFA / captcha
 * obstacles additionally emit a `coverage_gap` so the halt is explained rather
 * than silent.
 */
export function planAuthTransition(outcome: LoginOutcome): AuthPlan {
  switch (outcome.status) {
    case "success":
      if (isAuthSuccessful(outcome.artifact)) {
        return { event: { type: "advance" } };
      }
      return {
        event: { type: "halt", reason: "auth_captured_no_session" },
        gap: {
          kind: "coverage_gap",
          url: null,
          host: null,
          reason: "auth_captured_no_session",
        },
      };
    case "obstacle": {
      const reason = `auth_${outcome.obstacle.kind}`;
      return {
        event: { type: "halt", reason },
        gap: {
          kind: "coverage_gap",
          url: null,
          host: null,
          reason: `${reason}: ${outcome.obstacle.evidence}`,
        },
      };
    }
    case "failed":
      return { event: { type: "halt", reason: `auth_failed: ${outcome.reason}` } };
  }
}

// ---------------------------------------------------------------------------
// Stage orchestration
// ---------------------------------------------------------------------------

export interface AcquireAuthOptions {
  onCoverageGap?: (gap: CoverageGap) => void;
}

/**
 * Run the auth stage: perform the injected login, persist the artifact on
 * success, and return the pipeline transition. On any halt outcome no artifact
 * is written, so a resumed engagement sees no usable session and re-runs auth.
 */
export async function acquireAuth(
  workdir: string,
  login: () => Promise<LoginOutcome>,
  opts: AcquireAuthOptions = {},
): Promise<AuthPlan> {
  const outcome = await login();
  const plan = planAuthTransition(outcome);
  if (plan.gap) opts.onCoverageGap?.(plan.gap);
  if (outcome.status === "success" && plan.event.type === "advance") {
    await writeAuthArtifact(workdir, outcome.artifact);
  }
  return plan;
}
