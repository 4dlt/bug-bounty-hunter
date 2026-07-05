---
name: BugBountyHunter-v2
description: >-
  Run an AI-driven bug bounty assessment against a target using the v2
  self-verifying loop (plan -> execute -> verify -> repeat). Trigger with a
  natural-language pentest request such as "pentest target.com". Shells out to
  the TypeScript orchestrator binary.
---

# BugBountyHunter v2

Thin trigger for the v2 orchestrator. The state machine, LLM client, rate-limit
governor, and pentest logic live in the TypeScript binary at
`v2/orchestrator/src/main.ts`; this skill just invokes it.

## When to use

The user asks to run a bug bounty assessment or pentest against a target —
e.g. "pentest target.com", "run a bug bounty assessment on example.com".

## How to invoke

Run the orchestrator from the repo root, passing the subcommand and args:

```bash
bun v2/orchestrator/src/main.ts <command> [args]
```

Commands available in Slice 0:

- `hello` — end-to-end smoke test. Boots the local OWASP Juice Shop test
  target, makes one LLM call, writes and re-validates `state.json`, then tears
  the target down. Use this to confirm the runtime, credentials, and test
  target are all wired up:

  ```bash
  bun v2/orchestrator/src/main.ts hello
  ```

Later slices add `pentest <target>` and `resume <engagement_id>`.

## Prerequisites

- **Credentials** — either `CLAUDE_CODE_OAUTH_TOKEN` (run `claude setup-token`
  once to bill against your subscription) or `ANTHROPIC_API_KEY`.
- **Docker** — the `hello` smoke and later engagements use the docker-compose
  test target at `v2/test-target/docker-compose.yml`.
- No dependency on PAI or any path under `~/.claude/PAI/`.
