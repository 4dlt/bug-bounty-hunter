// Local HTTP rate-limit governor.
//
// The orchestrator (a long-running process) hosts a token-bucket endpoint at
// 127.0.0.1:<port>/token. Every hunter requests a token before firing a probe
// so the parallel swarm respects the program's req/s budget without shared
// files or flock. Later slices consume it; this slice provides the primitive.

import http from "node:http";
import type { AddressInfo } from "node:net";

/**
 * A per-second token bucket. `capacity` tokens are available each second;
 * `take()` succeeds while tokens remain and refills lazily on a clock tick.
 */
export class TokenBucket {
  readonly capacity: number;
  private readonly now: () => number;
  private tokens: number;
  private windowStart: number;

  constructor(capacity: number, now: () => number = () => Date.now()) {
    if (capacity <= 0) throw new Error("capacity must be positive");
    this.capacity = capacity;
    this.now = now;
    this.tokens = capacity;
    this.windowStart = now();
  }

  /** Take one token. Returns false when the bucket is empty this second. */
  take(): boolean {
    this.refill();
    if (this.tokens <= 0) return false;
    this.tokens -= 1;
    return true;
  }

  /** Tokens remaining in the current window (after any pending refill). */
  available(): number {
    this.refill();
    return this.tokens;
  }

  private refill(): void {
    const t = this.now();
    if (t - this.windowStart >= 1000) {
      this.tokens = this.capacity;
      this.windowStart = t;
    }
  }
}

export interface TokenServer {
  server: http.Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

/**
 * Start the token endpoint. GET /token returns 200 `{ "token": true }` while
 * the bucket has capacity and 429 `{ "token": false }` when it is empty.
 * Binds to 127.0.0.1 only. Pass port 0 to get an ephemeral port.
 */
export function startTokenServer(
  bucket: TokenBucket,
  port = 0,
  host = "127.0.0.1",
): Promise<TokenServer> {
  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/token") {
      const granted = bucket.take();
      res.writeHead(granted ? 200 : 429, {
        "content-type": "application/json",
      });
      res.end(JSON.stringify({ token: granted }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const addr = server.address() as AddressInfo;
      resolve({
        server,
        port: addr.port,
        url: `http://${host}:${addr.port}`,
        close: () =>
          new Promise<void>((res, rej) =>
            server.close((err) => (err ? rej(err) : res())),
          ),
      });
    });
  });
}
