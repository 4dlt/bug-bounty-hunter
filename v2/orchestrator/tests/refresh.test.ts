import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  RefreshMonitor,
  DEFAULT_REFRESH_INTERVAL_MS,
} from "../src/refresh.ts";
import { readAuthArtifact, type AuthArtifact } from "../src/auth.ts";

const artifact = (over: Partial<AuthArtifact> = {}): AuthArtifact => ({
  acquired_at: "2026-07-01T00:00:00.000Z",
  cookies: [{ name: "token", value: "v1", domain: "localhost" }],
  jwts: [],
  ...over,
});

describe("RefreshMonitor.runOnce", () => {
  it("persists the refreshed artifact", async () => {
    const updates: AuthArtifact[] = [];
    const mon = new RefreshMonitor({
      refresh: async () => artifact({ cookies: [{ name: "token", value: "v2", domain: "localhost" }] }),
      onUpdate: async (a) => void updates.push(a),
    });
    const r = await mon.runOnce();
    expect(r.ok).toBe(true);
    expect(updates).toHaveLength(1);
    expect(updates[0]!.cookies[0]!.value).toBe("v2");
  });

  it("swallows a refresh error and reports it, so the loop survives", async () => {
    const errors: unknown[] = [];
    const mon = new RefreshMonitor({
      refresh: async () => {
        throw new Error("refresh endpoint 401");
      },
      onUpdate: async () => {},
      onError: (e) => errors.push(e),
    });
    const r = await mon.runOnce();
    expect(r.ok).toBe(false);
    expect(errors).toHaveLength(1);
  });
});

describe("RefreshMonitor start/stop", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("fires on the interval and stops cleanly", async () => {
    let refreshes = 0;
    const mon = new RefreshMonitor({
      intervalMs: 1000,
      refresh: async () => {
        refreshes++;
        return artifact();
      },
      onUpdate: async () => {},
    });
    mon.start();
    await vi.advanceTimersByTimeAsync(3000);
    expect(refreshes).toBe(3);
    mon.stop();
    await vi.advanceTimersByTimeAsync(5000);
    expect(refreshes).toBe(3);
  });
});

describe("RefreshMonitor persistence integration", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-refresh-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("updates auth/state.json without leaving a partial file", async () => {
    const mon = RefreshMonitor.forWorkdir(dir, async () =>
      artifact({ jwts: [{ name: "access", token: "fresh.jwt.here" }] }),
    );
    await mon.runOnce();
    const back = await readAuthArtifact(dir);
    expect(back.jwts[0]!.token).toBe("fresh.jwt.here");
    // No stray temp files left behind.
    const files = await fs.readdir(path.join(dir, "auth"));
    expect(files).toEqual(["state.json"]);
  });
});

describe("defaults", () => {
  it("documents a sane default refresh interval", () => {
    expect(DEFAULT_REFRESH_INTERVAL_MS).toBeGreaterThan(0);
  });
});
