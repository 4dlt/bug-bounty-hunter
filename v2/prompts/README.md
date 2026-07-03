# v2 agent prompts

Markdown prompts for the v2 agent roles live here, added slice by slice:

- Auth acquisition (Stage 0) — `auth-acquire.md` ✅ (Slice 1)
- Recon R1–R4 (Stage 1) — `recon-r1-assets.md`, `recon-r2-content.md`,
  `recon-r3-fingerprint.md`, `recon-r4-js-analysis.md` ✅ (Slice 2)
- Plan (Stage 2) — `plan.md` ✅ (Slice 3a)
- Tier 1 sweep hunters (Stage 3)
- Checklist Author (Stage 3.5) / Checklist Reviewer (Stage 3.6)
- Verifier (Stage 4)
- Tier 2 deep hunters

Slice 0 shipped the scaffolding, LLM client, state machine, rate-limit
governor, and Juice Shop test target. Slice 1 adds Stage 0: the scope.yaml
schema + allowlist (`src/scope.ts`), the auth-acquire agent prompt and stage
(`src/auth.ts`), and the token-refresh monitor (`src/refresh.ts`). Slice 2 adds
Stage 1 recon: the parallel R1–R4 orchestration + merge (`src/recon.ts`), the
governor client (`acquireToken` in `src/ratelimit.ts`), and the four recon agent
prompts above. Slice 3a adds Stage 2 Plan: the hunt-plan / a-priori-hypothesis
schemas + surface-compatibility filter + seeding (`src/plan.ts`), the `bbh plan`
subcommand, and the `plan.md` prompt.
