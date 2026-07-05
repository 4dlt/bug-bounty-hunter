// Stage 4 — the Verifier's PoC re-fire path.
//
// The Verifier re-fires each finding's `poc.sh` against the LIVE target and
// captures a fresh response, then diffs it against the response the hunter
// captured at discovery time (`response.json`). This is a DIFFERENT code path
// from the hunter's probe firer (`createProbeFirer`): it deliberately does NOT
// consult the ledger dedupe — re-firing a known PoC is the whole point of the
// verify loop, so the dedupe that stops a hunter re-probing must not stop the
// Verifier re-running the PoC.
//
// The process execution is injected as a `PocExecutor` seam so the re-fire logic
// is unit-testable without spawning a shell or hitting a live target; the default
// executor runs `bash poc.sh` in the finding directory.

import { promises as fs } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { findingDir } from "../hunters/framework.ts";

/** The raw result of running a finding's `poc.sh`. */
export interface PocRunResult {
  exit_code: number;
  stdout: string;
  stderr: string;
}

/**
 * The process seam: run the PoC script at `pocPath` with `cwd`, return its
 * captured streams + exit code. Injected so the re-fire path is testable without
 * a shell; the default (`spawnPocExecutor`) runs `bash poc.sh`.
 */
export type PocExecutor = (pocPath: string, cwd: string) => Promise<PocRunResult>;

/** Default executor: run `bash <poc.sh>` in the finding dir, capturing streams. */
export const spawnPocExecutor: PocExecutor = (pocPath, cwd) =>
  new Promise<PocRunResult>((resolve, reject) => {
    const child = spawn("bash", [pocPath], { cwd });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) =>
      resolve({ exit_code: code ?? 0, stdout, stderr }),
    );
  });

/** The re-fire outcome the Verifier reasons over. */
export interface PocRefireOutput {
  finding_id: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  /** The response captured at discovery time (`response.json`), verbatim. */
  captured_response: string;
  /** The fresh response from re-running the PoC now (its stdout). */
  fresh_response: string;
  /** True when the fresh response differs from the captured one. */
  differs: boolean;
}

/** Read the discovery-time `response.json`; a missing file yields "". */
async function readCapturedResponse(dir: string): Promise<string> {
  try {
    return await fs.readFile(path.join(dir, "response.json"), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "";
    throw err;
  }
}

/**
 * Re-fire one finding's `poc.sh` and capture the fresh response. Bypasses the
 * hunter dedupe by design (this is not `createProbeFirer`). Returns the fresh
 * stdout, the captured `response.json`, and whether they differ so the Verifier
 * can distinguish a stable repro from a flapping / no-longer-reproducing one.
 */
export async function refirePoc(
  workdir: string,
  findingId: string,
  deps: { execute: PocExecutor },
): Promise<PocRefireOutput> {
  const dir = findingDir(workdir, findingId);
  const pocPath = path.join(dir, "poc.sh");
  const captured = await readCapturedResponse(dir);
  const run = await deps.execute(pocPath, dir);
  const fresh = run.stdout;
  return {
    finding_id: findingId,
    exit_code: run.exit_code,
    stdout: run.stdout,
    stderr: run.stderr,
    captured_response: captured,
    fresh_response: fresh,
    differs: fresh.trim() !== captured.trim(),
  };
}
