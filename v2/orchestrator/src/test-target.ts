// Local OWASP Juice Shop test target — docker-compose lifecycle + reachability.
//
// `bbh hello` brings the target up, probes it, then tears it down. Kept in its
// own module so later integration slices can reuse the helpers.

import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path to v2/test-target (where the docker-compose.yml lives). */
export const TEST_TARGET_DIR = path.resolve(here, "..", "..", "test-target");

export const JUICE_SHOP_URL = "http://localhost:3000";

function run(
  cmd: string,
  args: string[],
  cwd: string,
): Promise<{ code: number; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, stdio: ["ignore", "inherit", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => (stderr += String(d)));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
  });
}

/** Bring the Juice Shop container up in the background. */
export async function composeUp(dir = TEST_TARGET_DIR): Promise<void> {
  const { code, stderr } = await run(
    "docker",
    ["compose", "up", "-d", "--wait"],
    dir,
  );
  if (code !== 0) throw new Error(`docker compose up failed: ${stderr.trim()}`);
}

/** Tear the Juice Shop container down. */
export async function composeDown(dir = TEST_TARGET_DIR): Promise<void> {
  const { code, stderr } = await run("docker", ["compose", "down"], dir);
  if (code !== 0) throw new Error(`docker compose down failed: ${stderr.trim()}`);
}

/** Poll until Juice Shop answers or the timeout elapses. */
export async function waitForJuiceShop(
  url = JUICE_SHOP_URL,
  timeoutMs = 120_000,
  intervalMs = 2_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastErr: unknown;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(intervalMs) });
      if (res.ok) return;
      lastErr = new Error(`status ${res.status}`);
    } catch (err) {
      lastErr = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(
    `Juice Shop not reachable at ${url} within ${timeoutMs}ms: ${String(lastErr)}`,
  );
}
