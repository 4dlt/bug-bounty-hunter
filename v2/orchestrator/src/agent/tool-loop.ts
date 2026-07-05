// The agent tool-loop primitive.
//
// A bounded multi-turn tool-use loop over the LLM client — the one new
// orchestration primitive Phase 1 introduces, and the thing every real agent in
// the PRD (starting with the capable IDOR hunter) is built on.
//
// Given a system prompt, an initial user message, a set of tools (each a
// name + description + JSON-schema input + handler), a turn cap, and a
// designated TERMINAL tool, it:
//   1. calls the model with the tools advertised,
//   2. dispatches each `tool_use` block the model emits to its handler and
//      feeds the result back as a `tool_result`,
//   3. returns the input payload of the terminal tool the moment the model
//      calls it (that is the agent's structured answer), and
//   4. counts every model invocation against `max_llm_calls` via `onLlmCall`.
//
// It honours the turn cap (never runs the model more than `maxTurns` times) and
// is pure w.r.t. the network: the LLM client is injected structurally, so the
// whole loop is unit-testable with a scripted fake client and no live model.

import type { Level } from "../llm.ts";
import { modelForLevel } from "../llm.ts";

// ---------------------------------------------------------------------------
// Tool + client shapes
// ---------------------------------------------------------------------------

/**
 * A tool the loop can call. `input_schema` is the JSON Schema advertised to the
 * model; `handler` turns the model-supplied input into a result that is fed back
 * verbatim (stringified) as the tool result. The terminal tool is listed here
 * too (so the model can call it) but its handler is never invoked — the loop
 * intercepts it and returns its input.
 */
export interface AgentTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  handler: (input: unknown) => Promise<unknown> | unknown;
}

/** One block of a model response. A permissive view over the SDK's block union. */
export interface AgentContentBlock {
  type: string;
  text?: string;
  id?: string;
  name?: string;
  input?: unknown;
}

/** A model response — the subset of the SDK `Message` the loop reads. */
export interface AgentMessage {
  content: AgentContentBlock[];
  stop_reason?: string | null;
}

/**
 * Structural view of the Anthropic messages client. The real client satisfies
 * it; a scripted fake satisfies it too, so the loop runs offline in tests. The
 * `create` param is `any` so the SDK's overloaded, strongly-typed signature
 * remains assignable (a stricter param type breaks under contravariance).
 */
export interface MessagesClient {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  messages: { create(params: any): Promise<AgentMessage> };
}

// ---------------------------------------------------------------------------
// Loop options + result
// ---------------------------------------------------------------------------

export interface ToolLoopOptions {
  client: MessagesClient;
  system: string;
  /** The initial user turn that kicks the agent off. */
  prompt: string;
  /** Tools advertised to the model. MUST include the terminal tool. */
  tools: AgentTool[];
  /** The tool whose invocation ends the loop; its input is the returned payload. */
  terminalTool: string;
  /** Hard cap on model invocations (turns). The loop never exceeds it. */
  maxTurns: number;
  level?: Level;
  maxTokens?: number;
  /** Called once per model invocation — the `max_llm_calls` budget hook. */
  onLlmCall?: () => void;
}

export type ToolLoopStop = "terminal" | "end_turn" | "turn_cap";

export interface ToolLoopResult {
  stop: ToolLoopStop;
  /** Number of model invocations made (1-based; equals maxTurns on a turn cap). */
  turns: number;
  /** The terminal tool's input payload when `stop === "terminal"`, else null. */
  terminal: unknown | null;
  /** Concatenated text of the last assistant message (useful on `end_turn`). */
  text: string;
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

function textOf(content: AgentContentBlock[]): string {
  return content
    .filter((b) => b.type === "text")
    .map((b) => b.text ?? "")
    .join("");
}

/**
 * Run the bounded tool-use loop. See the module header. Returns as soon as the
 * model calls the terminal tool (`terminal`), stops on its own without a tool
 * call (`end_turn`), or the turn cap is hit (`turn_cap`).
 */
export async function runToolLoop(opts: ToolLoopOptions): Promise<ToolLoopResult> {
  if (!opts.tools.some((t) => t.name === opts.terminalTool)) {
    throw new Error(
      `runToolLoop: terminal tool "${opts.terminalTool}" is not in the advertised tool set`,
    );
  }
  const model = modelForLevel(opts.level ?? "standard");
  const toolDefs = opts.tools.map((t) => ({
    name: t.name,
    description: t.description,
    input_schema: t.input_schema,
  }));

  const messages: Array<{ role: string; content: unknown }> = [
    { role: "user", content: opts.prompt },
  ];
  let text = "";

  for (let turn = 1; turn <= opts.maxTurns; turn += 1) {
    opts.onLlmCall?.();
    const res = await opts.client.messages.create({
      model,
      max_tokens: opts.maxTokens ?? 2048,
      system: opts.system,
      tools: toolDefs,
      messages,
    });
    messages.push({ role: "assistant", content: res.content });
    text = textOf(res.content);

    const toolUses = res.content.filter((b) => b.type === "tool_use");
    if (toolUses.length === 0) {
      return { stop: "end_turn", turns: turn, terminal: null, text };
    }

    // The terminal tool ends the loop immediately; its input is the payload.
    const terminal = toolUses.find((b) => b.name === opts.terminalTool);
    if (terminal) {
      return { stop: "terminal", turns: turn, terminal: terminal.input ?? null, text };
    }

    // Dispatch every non-terminal tool call and feed the results back. A missing
    // tool or a throwing handler becomes an `is_error` result the model can
    // recover from, rather than aborting the whole hunt.
    const results: Array<Record<string, unknown>> = [];
    for (const use of toolUses) {
      const tool = opts.tools.find((t) => t.name === use.name);
      let content: string;
      let isError = false;
      try {
        if (!tool) {
          isError = true;
          content = `unknown tool: ${use.name}`;
        } else {
          const out = await tool.handler(use.input);
          content = typeof out === "string" ? out : JSON.stringify(out);
        }
      } catch (err) {
        isError = true;
        content = `tool error: ${(err as Error).message}`;
      }
      results.push({
        type: "tool_result",
        tool_use_id: use.id,
        content,
        ...(isError ? { is_error: true } : {}),
      });
    }
    messages.push({ role: "user", content: results });
  }

  return { stop: "turn_cap", turns: opts.maxTurns, terminal: null, text };
}
