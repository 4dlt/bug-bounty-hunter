import { describe, it, expect, vi } from "vitest";
import {
  resolveAuth,
  modelForLevel,
  complete,
  MODEL_BY_LEVEL,
  type Env,
} from "../src/llm.ts";

describe("resolveAuth", () => {
  it("prefers CLAUDE_CODE_OAUTH_TOKEN (subscription billing)", () => {
    const env: Env = {
      CLAUDE_CODE_OAUTH_TOKEN: "oauth-abc",
      ANTHROPIC_API_KEY: "sk-key",
    };
    expect(resolveAuth(env)).toEqual({ kind: "oauth", token: "oauth-abc" });
  });

  it("falls back to ANTHROPIC_API_KEY when the OAuth token is absent", () => {
    const env: Env = { ANTHROPIC_API_KEY: "sk-key" };
    expect(resolveAuth(env)).toEqual({ kind: "apiKey", key: "sk-key" });
  });

  it("throws a clear, actionable error when neither is set", () => {
    expect(() => resolveAuth({})).toThrow(/CLAUDE_CODE_OAUTH_TOKEN/);
    expect(() => resolveAuth({})).toThrow(/ANTHROPIC_API_KEY/);
  });

  it("treats whitespace-only credentials as absent", () => {
    expect(() => resolveAuth({ CLAUDE_CODE_OAUTH_TOKEN: "   " })).toThrow();
    const env: Env = { CLAUDE_CODE_OAUTH_TOKEN: "  ", ANTHROPIC_API_KEY: "sk" };
    expect(resolveAuth(env)).toEqual({ kind: "apiKey", key: "sk" });
  });
});

describe("modelForLevel", () => {
  it("routes each level to a distinct model", () => {
    expect(modelForLevel("fast")).toBe(MODEL_BY_LEVEL.fast);
    expect(modelForLevel("standard")).toBe(MODEL_BY_LEVEL.standard);
    expect(modelForLevel("smart")).toBe(MODEL_BY_LEVEL.smart);
    const models = new Set(Object.values(MODEL_BY_LEVEL));
    expect(models.size).toBe(3);
  });

  it("uses Opus for the smart tier", () => {
    expect(modelForLevel("smart")).toBe("claude-opus-4-8");
  });
});

describe("complete", () => {
  it("selects the model for the level and returns concatenated text", async () => {
    const create = vi.fn().mockResolvedValue({
      content: [
        { type: "text", text: "hello " },
        { type: "thinking", thinking: "ignored" },
        { type: "text", text: "world" },
      ],
    });
    const fakeClient = { messages: { create } } as never;

    const out = await complete(
      { level: "fast", prompt: "hi", maxTokens: 16 },
      fakeClient,
    );

    expect(out).toBe("hello world");
    expect(create).toHaveBeenCalledWith(
      expect.objectContaining({
        model: MODEL_BY_LEVEL.fast,
        max_tokens: 16,
        messages: [{ role: "user", content: "hi" }],
      }),
    );
  });
});
