// Token-refresh background monitor.
//
// Long engagements (the PRD assumes 4–8 hours) outlive the session tokens
// captured at Stage 0. This monitor periodically re-acquires/re-validates the
// session and rewrites `auth/state.json` atomically, so in-flight agents that
// re-read the artifact between probes always see a live session and never a
// half-written file. Loosely models v3-experimental's `lib/refresh-monitor.sh`.
//
// The refresh mechanics (hitting the refresh endpoint, re-driving login) are
// injected so the loop is testable with fake timers and no live target.

import { writeAuthArtifact, type AuthArtifact } from "./auth.ts";

/**
 * Default cadence. Short enough to stay ahead of typical access-token TTLs
 * (minutes to an hour) while cheap enough to run for the whole engagement.
 */
export const DEFAULT_REFRESH_INTERVAL_MS = 5 * 60 * 1000;

export interface RefreshMonitorOptions {
  /** Perform the refresh and return the new artifact to persist. */
  refresh: () => Promise<AuthArtifact>;
  /** Persist the refreshed artifact (defaults to writing auth/state.json). */
  onUpdate: (art: AuthArtifact) => Promise<void>;
  /** Interval between refreshes. */
  intervalMs?: number;
  /** Notified when a refresh cycle throws; the loop keeps running. */
  onError?: (err: unknown) => void;
}

export type RefreshResult =
  | { ok: true; artifact: AuthArtifact }
  | { ok: false; error: unknown };

export class RefreshMonitor {
  private readonly opts: Required<Omit<RefreshMonitorOptions, "onError">> &
    Pick<RefreshMonitorOptions, "onError">;
  private timer: ReturnType<typeof setInterval> | undefined;
  private running = false;

  constructor(opts: RefreshMonitorOptions) {
    this.opts = {
      intervalMs: DEFAULT_REFRESH_INTERVAL_MS,
      ...opts,
    };
  }

  /** Convenience: a monitor that persists straight into `<workdir>/auth/`. */
  static forWorkdir(
    workdir: string,
    refresh: () => Promise<AuthArtifact>,
    intervalMs = DEFAULT_REFRESH_INTERVAL_MS,
  ): RefreshMonitor {
    return new RefreshMonitor({
      refresh,
      onUpdate: (art) => writeAuthArtifact(workdir, art),
      intervalMs,
    });
  }

  /**
   * One refresh cycle. Never throws: a failed refresh is reported via `onError`
   * and returned as `{ ok: false }` so a stuck refresh endpoint cannot crash
   * the background loop or the engagement.
   */
  async runOnce(): Promise<RefreshResult> {
    try {
      const artifact = await this.opts.refresh();
      await this.opts.onUpdate(artifact);
      return { ok: true, artifact };
    } catch (error) {
      this.opts.onError?.(error);
      return { ok: false, error };
    }
  }

  /** Begin refreshing on the interval. Overlapping cycles are skipped. */
  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      if (this.running) return; // do not stack a second cycle on a slow refresh
      this.running = true;
      void this.runOnce().finally(() => {
        this.running = false;
      });
    }, this.opts.intervalMs);
    // Do not keep the process alive solely for the refresh loop.
    this.timer.unref?.();
  }

  /** Stop the interval. Safe to call when not started. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
