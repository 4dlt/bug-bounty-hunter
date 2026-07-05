// Multi-identity auth + the real HTTP probe transport.
//
// Two pieces of the Phase-1 critical path that talk to the live target:
//
//   1. `captureSessions` — a real form/JSON login for each named identity in
//      scope.yaml (best-effort register first, then login), keyed by name. The
//      implicit unauthenticated identity is always present. Every request routes
//      through the scoped fetch, so an out-of-scope login attempt is blocked
//      before any byte leaves the process.
//
//   2. `createHttpTransport` — the `ProbeTransport` the hunter fires through. It
//      resolves a probe's endpoint against the target base URL, injects the
//      chosen identity's credential (or none for the unauth path), routes through
//      the SAME scoped fetch, and returns the status / body / timing the oracle
//      needs. It plugs in behind the existing dedupe + token + ledger firer
//      (`createProbeFirer`), so scope / rate-limit / no-repeat all hold by
//      construction.
//
// The network is injected as `fetch` so both pieces are unit-testable offline.

import { z } from "zod";
import {
  scopedFetch,
  type Scope,
  type Identity,
  type CoverageGap,
} from "../scope.ts";
import { payloadSig, type LedgerResult } from "../hunters/ledger.ts";
import type { ProbeRequest, ProbeTransport } from "../hunters/framework.ts";

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/** The implicit, always-available unauthenticated identity. */
export const UNAUTH_SESSION = "unauth";

/** A captured session keyed by identity name. A name-only session (no
 *  credential) is the unauthenticated identity or a login that failed. */
export interface IdentitySession {
  name: string;
  /** `Authorization` header value, e.g. `Bearer eyJ…`. */
  authorization?: string;
  /** `Cookie` header value. */
  cookie?: string;
}

/** Request headers this session rides on (empty for the unauth identity). */
export function sessionHeaders(session: IdentitySession | undefined): Record<string, string> {
  const h: Record<string, string> = {};
  if (session?.authorization) h["Authorization"] = session.authorization;
  if (session?.cookie) h["Cookie"] = session.cookie;
  return h;
}

/** True when a session actually carries a credential. */
export function isAuthenticatedSession(session: IdentitySession | undefined): boolean {
  return !!(session && (session.authorization || session.cookie));
}

export interface AuthDeps {
  fetch?: typeof fetch;
  onCoverageGap?: (gap: CoverageGap) => void;
}

/** A permissive view of a JSON login response — enough shapes to find a token. */
const LoginBodySchema = z.object({
  authentication: z
    .object({ token: z.string().optional(), bid: z.unknown().optional(), umail: z.string().optional() })
    .optional(),
  token: z.string().optional(),
  access_token: z.string().optional(),
});

/** Pull a bearer token out of a login response body, trying the known shapes. */
export function extractToken(body: unknown): string | undefined {
  const parsed = LoginBodySchema.safeParse(body);
  if (!parsed.success) return undefined;
  return (
    parsed.data.authentication?.token ??
    parsed.data.token ??
    parsed.data.access_token ??
    undefined
  );
}

/** Resolve a path/URL against the engagement target base. */
export function resolveUrl(target: string, endpoint: string): string {
  try {
    // Absolute URL: use as-is.
    return new URL(endpoint).toString();
  } catch {
    return new URL(endpoint, target).toString();
  }
}

/**
 * Log in one identity: best-effort register (a fresh test account may not exist
 * yet; a 4xx/409 there is expected and ignored), then a real login POST. Returns
 * a session carrying the captured bearer token and/or set-cookie, or a name-only
 * session when the login yielded no credential (surfaced by
 * `isAuthenticatedSession`, never thrown — a failed identity does not abort the
 * others). Every request goes through the scoped fetch.
 */
export async function loginIdentity(
  scope: Scope,
  identity: Identity,
  deps: AuthDeps = {},
): Promise<IdentitySession> {
  const base = scope.target;
  const loginUrl = resolveUrl(base, identity.login_url ?? scope.auth.login_url ?? "/rest/user/login");
  const registerUrl = resolveUrl(base, "/api/Users");

  // 1. Best-effort register. An already-registered account (409) or a target
  //    that does not expose registration (4xx) is fine — we proceed to login.
  try {
    await scopedFetch(
      scope,
      registerUrl,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: identity.username,
          password: identity.password,
          passwordRepeat: identity.password,
          securityQuestion: { id: 1 },
          securityAnswer: identity.name,
        }),
      },
      deps,
    );
  } catch {
    // Registration is best-effort; login is the gate.
  }

  // 2. Login.
  let res: Response;
  try {
    res = await scopedFetch(
      scope,
      loginUrl,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: identity.username, password: identity.password }),
      },
      deps,
    );
  } catch {
    return { name: identity.name };
  }

  const setCookie = res.headers.get("set-cookie") ?? undefined;
  let token: string | undefined;
  try {
    token = extractToken(await res.clone().json());
  } catch {
    token = undefined;
  }

  const session: IdentitySession = { name: identity.name };
  if (token) session.authorization = `Bearer ${token}`;
  if (setCookie) session.cookie = setCookie.split(";")[0];
  return session;
}

/**
 * Capture a session for every named identity plus the implicit unauthenticated
 * one. Identities log in independently (best-effort); a failed identity yields a
 * name-only session rather than aborting the engagement.
 */
export async function captureSessions(
  scope: Scope,
  deps: AuthDeps = {},
): Promise<Map<string, IdentitySession>> {
  const sessions = new Map<string, IdentitySession>();
  sessions.set(UNAUTH_SESSION, { name: UNAUTH_SESSION });
  for (const identity of scope.identities) {
    sessions.set(identity.name, await loginIdentity(scope, identity, deps));
  }
  return sessions;
}

// ---------------------------------------------------------------------------
// The HTTP probe transport
// ---------------------------------------------------------------------------

/** The raw HTTP outcome of one probe: status, body, and wall-clock timing. */
export interface HttpProbeResult {
  status: number;
  body: string;
  ms: number;
}

export interface HttpTransportConfig {
  scope: Scope;
  sessions: Map<string, IdentitySession>;
  fetch?: typeof fetch;
  onCoverageGap?: (gap: CoverageGap) => void;
  /** Monotonic clock for timing (ms). Injected so tests are deterministic. */
  now?: () => number;
  /** Cap on the captured body length written into the ledger evidence. */
  maxBodyLen?: number;
}

/** Fire one probe over real HTTP: resolve, inject the identity, capture the
 *  response + timing. Routes through the scoped fetch (scope enforced here). */
export async function httpProbe(
  cfg: HttpTransportConfig,
  probe: ProbeRequest,
): Promise<HttpProbeResult> {
  const now = cfg.now ?? (() => Date.now());
  const url = resolveUrl(cfg.scope.target, probe.endpoint);
  const session = cfg.sessions.get(probe.session);
  const headers = sessionHeaders(session);

  const start = now();
  const res = await scopedFetch(
    cfg.scope,
    url,
    { method: probe.method ?? "GET", headers },
    { fetch: cfg.fetch, onCoverageGap: cfg.onCoverageGap },
  );
  const body = await res.text();
  const ms = now() - start;
  return { status: res.status, body, ms };
}

/**
 * Build the `ProbeTransport` the hunter fires through. The captured body is
 * stashed in the ledger result's `evidence` field so the hunter can diff it
 * across identities and hand it to the oracle; the resp_sig fingerprints the
 * body so identical responses across identities are visible.
 */
export function createHttpTransport(cfg: HttpTransportConfig): ProbeTransport {
  const maxBodyLen = cfg.maxBodyLen ?? 8192;
  return async (probe: ProbeRequest): Promise<LedgerResult> => {
    const out = await httpProbe(cfg, probe);
    const body = out.body.length > maxBodyLen ? out.body.slice(0, maxBodyLen) : out.body;
    return {
      status: String(out.status),
      resp_sig: payloadSig(body),
      trigger_match: false,
      evidence: JSON.stringify({ status: out.status, ms: out.ms, body }),
    };
  };
}

/** Parse the `evidence` a `createHttpTransport` probe stored back into a
 *  differential response. Falls back to treating the raw evidence as the body. */
export function decodeProbeEvidence(
  evidence: string | undefined,
): { status: number; body: string } {
  if (!evidence) return { status: 0, body: "" };
  try {
    const parsed = JSON.parse(evidence) as { status?: number; body?: string };
    if (typeof parsed.status === "number" && typeof parsed.body === "string") {
      return { status: parsed.status, body: parsed.body };
    }
  } catch {
    // Not JSON — treat the whole thing as the body.
  }
  return { status: 0, body: evidence };
}
