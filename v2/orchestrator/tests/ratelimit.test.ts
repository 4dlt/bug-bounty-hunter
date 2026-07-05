import { describe, it, expect, afterEach } from "vitest";
import {
  TokenBucket,
  startTokenServer,
  type TokenServer,
} from "../src/ratelimit.ts";

describe("TokenBucket", () => {
  it("grants up to capacity tokens per second, then denies", () => {
    let clock = 1000;
    const bucket = new TokenBucket(3, () => clock);
    expect(bucket.take()).toBe(true);
    expect(bucket.take()).toBe(true);
    expect(bucket.take()).toBe(true);
    expect(bucket.take()).toBe(false);
    expect(bucket.available()).toBe(0);
  });

  it("refills at the start of the next second", () => {
    let clock = 1000;
    const bucket = new TokenBucket(2, () => clock);
    bucket.take();
    bucket.take();
    expect(bucket.take()).toBe(false);
    clock += 1000;
    expect(bucket.take()).toBe(true);
  });

  it("rejects a non-positive capacity", () => {
    expect(() => new TokenBucket(0)).toThrow();
  });
});

describe("token endpoint", () => {
  let running: TokenServer | undefined;
  afterEach(async () => {
    await running?.close();
    running = undefined;
  });

  it("returns 200 with a token under load and 429 when the bucket is empty", async () => {
    let clock = 5000;
    const bucket = new TokenBucket(2, () => clock);
    running = await startTokenServer(bucket);

    const first = await fetch(`${running.url}/token`);
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ token: true });

    await fetch(`${running.url}/token`); // drains the second token

    const empty = await fetch(`${running.url}/token`);
    expect(empty.status).toBe(429);
    expect(await empty.json()).toEqual({ token: false });

    clock += 1000; // next window
    const refilled = await fetch(`${running.url}/token`);
    expect(refilled.status).toBe(200);
  });

  it("404s unknown paths", async () => {
    running = await startTokenServer(new TokenBucket(1));
    const res = await fetch(`${running.url}/nope`);
    expect(res.status).toBe(404);
  });

  it("binds to loopback only", async () => {
    running = await startTokenServer(new TokenBucket(1));
    expect(running.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });
});
