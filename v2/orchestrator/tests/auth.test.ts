import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  AuthArtifactSchema,
  writeAuthArtifact,
  readAuthArtifact,
  isAuthSuccessful,
  detectAuthObstacle,
  planAuthTransition,
  acquireAuth,
  type AuthArtifact,
  type LoginOutcome,
  type CoverageGap,
} from "../src/auth.ts";

const artifact = (over: Partial<AuthArtifact> = {}): AuthArtifact => ({
  acquired_at: "2026-07-01T00:00:00.000Z",
  cookies: [{ name: "token", value: "abc", domain: "localhost" }],
  jwts: [],
  ...over,
});

describe("AuthArtifactSchema", () => {
  it("validates a cookie+jwt artifact and rejects a malformed cookie", () => {
    const ok = AuthArtifactSchema.parse(artifact({ jwts: [{ name: "access", token: "e.y.z" }] }));
    expect(ok.cookies[0]!.name).toBe("token");
    expect(() => AuthArtifactSchema.parse({ acquired_at: "x", cookies: [{ value: "v" }] })).toThrow();
  });
});

describe("isAuthSuccessful", () => {
  it("is true when at least one cookie or JWT was captured", () => {
    expect(isAuthSuccessful(artifact())).toBe(true);
    expect(isAuthSuccessful(artifact({ cookies: [], jwts: [{ name: "a", token: "t" }] }))).toBe(true);
  });

  it("is false when no session material was captured", () => {
    expect(isAuthSuccessful(artifact({ cookies: [], jwts: [] }))).toBe(false);
  });
});

describe("detectAuthObstacle", () => {
  it("flags a captcha challenge", () => {
    const o = detectAuthObstacle("Please solve the reCAPTCHA to continue");
    expect(o?.kind).toBe("captcha");
  });

  it("flags an MFA / OTP prompt", () => {
    expect(detectAuthObstacle("Enter your one-time verification code")?.kind).toBe("mfa");
    expect(detectAuthObstacle("Open your authenticator app")?.kind).toBe("mfa");
  });

  it("returns null for an ordinary login page", () => {
    expect(detectAuthObstacle("Email and password")).toBeNull();
  });
});

describe("planAuthTransition", () => {
  it("advances (auth -> recon) on a successful artifact", () => {
    const plan = planAuthTransition({ status: "success", artifact: artifact() });
    expect(plan.event).toEqual({ type: "advance" });
    expect(plan.gap).toBeUndefined();
  });

  it("halts with a coverage_gap on an MFA / captcha obstacle", () => {
    const plan = planAuthTransition({
      status: "obstacle",
      obstacle: { kind: "mfa", evidence: "otp" },
    });
    expect(plan.event.type).toBe("halt");
    expect(plan.gap?.reason).toMatch(/mfa/);
  });

  it("halts on a plain auth failure", () => {
    const plan = planAuthTransition({ status: "failed", reason: "bad_credentials" });
    expect(plan.event.type).toBe("halt");
  });

  it("halts (does not advance) when a 'successful' outcome carries no session material", () => {
    const plan = planAuthTransition({
      status: "success",
      artifact: artifact({ cookies: [], jwts: [] }),
    });
    expect(plan.event.type).toBe("halt");
  });
});

describe("acquireAuth", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-auth-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("writes auth/state.json and advances on success", async () => {
    const login = async (): Promise<LoginOutcome> => ({ status: "success", artifact: artifact() });
    const plan = await acquireAuth(dir, login);
    expect(plan.event).toEqual({ type: "advance" });
    const back = await readAuthArtifact(dir);
    expect(back.cookies[0]!.value).toBe("abc");
  });

  it("does not write an artifact and halts on an obstacle", async () => {
    const gaps: CoverageGap[] = [];
    const login = async (): Promise<LoginOutcome> => ({
      status: "obstacle",
      obstacle: { kind: "captcha", evidence: "recaptcha" },
    });
    const plan = await acquireAuth(dir, login, { onCoverageGap: (g) => gaps.push(g) });
    expect(plan.event.type).toBe("halt");
    expect(gaps).toHaveLength(1);
    await expect(readAuthArtifact(dir)).rejects.toBeTruthy();
  });
});
