import { describe, it, expect, vi } from "vitest";
import {
  runToolLoop,
  type AgentMessage,
  type AgentTool,
  type MessagesClient,
} from "../src/agent/tool-loop.ts";

// A scripted fake client: each `create` call returns the next pre-baked message.
// It also records the `messages` it was handed so a test can assert the loop fed
// tool results back.
function scriptedClient(script: AgentMessage[]): {
  client: MessagesClient;
  calls: Array<Record<string, unknown>>;
} {
  const calls: Array<Record<string, unknown>> = [];
  let i = 0;
  const client: MessagesClient = {
    messages: {
      create: async (params) => {
        calls.push(params);
        const msg = script[i];
        i += 1;
        if (!msg) throw new Error("scriptedClient ran out of scripted responses");
        return msg;
      },
    },
  };
  return { client, calls };
}

const echoTool = (name: string, handler: AgentTool["handler"]): AgentTool => ({
  name,
  description: `test tool ${name}`,
  input_schema: { type: "object" },
  handler,
});

const SUBMIT: AgentTool = echoTool("submit", () => {
  throw new Error("terminal handler must never run");
});

describe("runToolLoop", () => {
  it("dispatches a tool call to its handler, feeds the result back, and returns the terminal payload", async () => {
    const httpHandler = vi.fn(async (input: unknown) => {
      expect(input).toEqual({ endpoint: "/x" });
      return { status: 200, body: "leaked" };
    });
    const { client, calls } = scriptedClient([
      // Turn 1: the model calls the http tool.
      {
        content: [{ type: "tool_use", id: "t1", name: "http", input: { endpoint: "/x" } }],
      },
      // Turn 2: having seen the result, the model submits.
      {
        content: [{ type: "tool_use", id: "t2", name: "submit", input: { findings: [1] } }],
      },
    ]);

    const out = await runToolLoop({
      client,
      system: "sys",
      prompt: "go",
      tools: [echoTool("http", httpHandler), SUBMIT],
      terminalTool: "submit",
      maxTurns: 5,
    });

    expect(out.stop).toBe("terminal");
    expect(out.terminal).toEqual({ findings: [1] });
    expect(out.turns).toBe(2);
    expect(httpHandler).toHaveBeenCalledOnce();

    // The second model call must carry the tool_result fed back from turn 1.
    const secondMessages = calls[1]!.messages as Array<{ role: string; content: unknown }>;
    const toolResult = (secondMessages[2]!.content as Array<Record<string, unknown>>)[0]!;
    expect(toolResult.type).toBe("tool_result");
    expect(toolResult.tool_use_id).toBe("t1");
    expect(String(toolResult.content)).toContain("leaked");
  });

  it("counts one LLM call per turn via onLlmCall (the max_llm_calls budget hook)", async () => {
    const onLlmCall = vi.fn();
    const { client } = scriptedClient([
      { content: [{ type: "tool_use", id: "t1", name: "http", input: {} }] },
      { content: [{ type: "tool_use", id: "t2", name: "http", input: {} }] },
      { content: [{ type: "tool_use", id: "t3", name: "submit", input: {} }] },
    ]);
    await runToolLoop({
      client,
      system: "s",
      prompt: "go",
      tools: [echoTool("http", async () => "ok"), SUBMIT],
      terminalTool: "submit",
      maxTurns: 5,
      onLlmCall,
    });
    expect(onLlmCall).toHaveBeenCalledTimes(3);
  });

  it("honours the turn cap (never calls the model more than maxTurns times)", async () => {
    // The model never submits — every turn it fires the http tool again.
    const forever: AgentMessage = {
      content: [{ type: "tool_use", id: "t", name: "http", input: {} }],
    };
    const { client, calls } = scriptedClient([forever, forever, forever, forever, forever]);
    const out = await runToolLoop({
      client,
      system: "s",
      prompt: "go",
      tools: [echoTool("http", async () => "ok"), SUBMIT],
      terminalTool: "submit",
      maxTurns: 3,
    });
    expect(out.stop).toBe("turn_cap");
    expect(out.turns).toBe(3);
    expect(calls).toHaveLength(3);
  });

  it("stops on end_turn when the model answers with no tool call", async () => {
    const { client } = scriptedClient([{ content: [{ type: "text", text: "all done" }] }]);
    const out = await runToolLoop({
      client,
      system: "s",
      prompt: "go",
      tools: [SUBMIT],
      terminalTool: "submit",
      maxTurns: 3,
    });
    expect(out.stop).toBe("end_turn");
    expect(out.text).toBe("all done");
    expect(out.terminal).toBeNull();
  });

  it("feeds a throwing handler back as an is_error result rather than aborting", async () => {
    const { client, calls } = scriptedClient([
      { content: [{ type: "tool_use", id: "t1", name: "boom", input: {} }] },
      { content: [{ type: "tool_use", id: "t2", name: "submit", input: { ok: true } }] },
    ]);
    const out = await runToolLoop({
      client,
      system: "s",
      prompt: "go",
      tools: [
        echoTool("boom", () => {
          throw new Error("kaboom");
        }),
        SUBMIT,
      ],
      terminalTool: "submit",
      maxTurns: 5,
    });
    expect(out.stop).toBe("terminal");
    const secondMessages = calls[1]!.messages as Array<{ role: string; content: unknown }>;
    const toolResult = (secondMessages[2]!.content as Array<Record<string, unknown>>)[0]!;
    expect(toolResult.is_error).toBe(true);
    expect(String(toolResult.content)).toContain("kaboom");
  });

  it("throws if the terminal tool is not among the advertised tools", async () => {
    const { client } = scriptedClient([]);
    await expect(
      runToolLoop({
        client,
        system: "s",
        prompt: "go",
        tools: [echoTool("http", async () => "ok")],
        terminalTool: "submit",
        maxTurns: 3,
      }),
    ).rejects.toThrow(/terminal tool/);
  });
});
