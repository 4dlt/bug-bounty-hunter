// Engagement state: the typed stage enum, a hand-rolled reducer over it, the
// Zod schemas for state.json / scope.yaml, and the persistence helpers.
//
// No state-machine library (per PRD). The reducer is exhaustively typed: every
// stage and every event is handled, and the compiler enforces it via the
// `assertNever` guard.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Stage enum + pipeline order
// ---------------------------------------------------------------------------

export const STAGES = [
  "auth",
  "recon",
  "plan",
  "sweep",
  "author",
  "review",
  "verify",
  "report",
  "done",
  "halted",
] as const;

export const StageSchema = z.enum(STAGES);
export type Stage = z.infer<typeof StageSchema>;

/**
 * Linear progression the `advance` event walks through: every stage except the
 * non-linear `halted`, which is reachable only via the `halt` event. Derived
 * from STAGES so the two lists cannot drift out of order.
 */
const PIPELINE: Stage[] = STAGES.filter((stage) => stage !== "halted");

// ---------------------------------------------------------------------------
// Zod schemas
// ---------------------------------------------------------------------------

export const StateSchema = z.object({
  engagement_id: z.string().min(1),
  target: z.string().min(1),
  current_stage: StageSchema,
  current_pass: z.number().int().nonnegative(),
  hypothesis_count: z.number().int().nonnegative(),
  status: z.enum(["in_progress", "done", "halted", "budget_exhausted"]),
});
export type State = z.infer<typeof StateSchema>;

// Scope + budget schemas live in scope.ts (alongside the allowlist that
// enforces them). Re-exported here so existing state.ts importers keep working.
export {
  BudgetSchema,
  ScopeSchema,
  AuthSchema,
  type Budget,
  type Scope,
  type Auth,
} from "./scope.ts";

// ---------------------------------------------------------------------------
// Reducer
// ---------------------------------------------------------------------------

export type Event =
  | { type: "advance" }
  | { type: "loop" }
  | { type: "halt"; reason: string };

function assertNever(x: never): never {
  throw new Error(`Unhandled event: ${JSON.stringify(x)}`);
}

/**
 * Pure transition. Returns a new state; never mutates the input.
 * - `advance`: step forward through the pipeline; `report` -> `done`.
 * - `loop`: verify re-queues back to `sweep`, bumping the pass counter.
 * - `halt`: enter the terminal `halted` stage from anywhere.
 */
export function transition(state: State, event: Event): State {
  if (state.current_stage === "done" || state.current_stage === "halted") {
    // Terminal stages reject all events, except re-halting an already-halted
    // state, which is an idempotent no-op.
    if (event.type === "halt" && state.current_stage === "halted") return state;
    throw new Error(
      `No transitions out of terminal stage "${state.current_stage}"`,
    );
  }

  switch (event.type) {
    case "advance": {
      const idx = PIPELINE.indexOf(state.current_stage);
      const next = PIPELINE[idx + 1];
      if (!next) {
        throw new Error(`Cannot advance past "${state.current_stage}"`);
      }
      return {
        ...state,
        current_stage: next,
        status: next === "done" ? "done" : state.status,
      };
    }
    case "loop": {
      if (state.current_stage !== "verify") {
        throw new Error(
          `"loop" is only valid from "verify", not "${state.current_stage}"`,
        );
      }
      return {
        ...state,
        current_stage: "sweep",
        current_pass: state.current_pass + 1,
      };
    }
    case "halt":
      return { ...state, current_stage: "halted", status: "halted" };
    default:
      return assertNever(event);
  }
}

export function initialState(engagementId: string, target: string): State {
  return {
    engagement_id: engagementId,
    target,
    current_stage: "auth",
    current_pass: 0,
    hypothesis_count: 0,
    status: "in_progress",
  };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

export function statePath(workdir: string): string {
  return path.join(workdir, "state.json");
}

export async function writeState(
  workdir: string,
  state: State,
): Promise<void> {
  const validated = StateSchema.parse(state);
  await fs.mkdir(workdir, { recursive: true });
  await fs.writeFile(
    statePath(workdir),
    JSON.stringify(validated, null, 2) + "\n",
    "utf8",
  );
}

export async function readState(workdir: string): Promise<State> {
  const raw = await fs.readFile(statePath(workdir), "utf8");
  return StateSchema.parse(JSON.parse(raw));
}
