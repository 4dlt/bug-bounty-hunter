// Vendored LLM client.
//
// Defaults to subscription billing via CLAUDE_CODE_OAUTH_TOKEN (created once
// with `claude setup-token`); falls back to ANTHROPIC_API_KEY when the OAuth
// token is absent; errors clearly when neither is set. Same shape
// mattpocock/sandcastle uses.
//
// The `level` axis ('fast' | 'standard' | 'smart') is accepted from day one so
// later slices can route thinking-heavy stages (Plan / Checklist Author /
// Reviewer) to a smarter model than probe-heavy stages (hunters / verifier)
// without changing call sites. The first version can route every level through
// one model if desired; the mapping lives here.

import Anthropic from "@anthropic-ai/sdk";

export type Level = "fast" | "standard" | "smart";

/** Model routing per capability level. See PRD "Model routing". */
export const MODEL_BY_LEVEL: Record<Level, string> = {
  fast: "claude-haiku-4-5",
  standard: "claude-sonnet-4-6",
  smart: "claude-opus-4-8",
};

export function modelForLevel(level: Level): string {
  return MODEL_BY_LEVEL[level];
}

export type Auth =
  | { kind: "oauth"; token: string }
  | { kind: "apiKey"; key: string };

/** Environment shape we read credentials from (a subset of process.env). */
export type Env = Record<string, string | undefined>;

/**
 * Resolve credentials with subscription-first precedence.
 *
 * 1. CLAUDE_CODE_OAUTH_TOKEN  -> subscription billing (preferred)
 * 2. ANTHROPIC_API_KEY        -> API-key fallback
 * 3. neither                  -> throw with an actionable message
 */
export function resolveAuth(env: Env = process.env): Auth {
  const token = env.CLAUDE_CODE_OAUTH_TOKEN?.trim();
  if (token) return { kind: "oauth", token };

  const key = env.ANTHROPIC_API_KEY?.trim();
  if (key) return { kind: "apiKey", key };

  throw new Error(
    "No Claude credentials found. Set CLAUDE_CODE_OAUTH_TOKEN (run `claude setup-token` " +
      "to use your subscription) or ANTHROPIC_API_KEY (to use API billing).",
  );
}

/** Build an Anthropic client wired to whichever credential is present. */
export function createClient(env: Env = process.env): Anthropic {
  const auth = resolveAuth(env);
  if (auth.kind === "oauth") {
    // OAuth tokens authenticate via Authorization: Bearer and require the
    // oauth beta header on /v1/messages.
    return new Anthropic({
      authToken: auth.token,
      defaultHeaders: { "anthropic-beta": "oauth-2025-04-20" },
    });
  }
  return new Anthropic({ apiKey: auth.key });
}

export interface CompleteOptions {
  level: Level;
  prompt: string;
  system?: string;
  maxTokens?: number;
}

/**
 * One-shot completion returning the concatenated text of the response.
 * Adaptive thinking is left off for this thin wrapper; slices that need it can
 * extend the call. Streaming is unnecessary at the small max_tokens used here.
 */
export async function complete(
  opts: CompleteOptions,
  client: Anthropic = createClient(),
): Promise<string> {
  const response = await client.messages.create({
    model: modelForLevel(opts.level),
    max_tokens: opts.maxTokens ?? 1024,
    ...(opts.system ? { system: opts.system } : {}),
    messages: [{ role: "user", content: opts.prompt }],
  });

  return response.content
    .filter((block): block is Anthropic.TextBlock => block.type === "text")
    .map((block) => block.text)
    .join("");
}
