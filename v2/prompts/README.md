# v2 agent prompts

Markdown prompts for the v2 agent roles live here, added slice by slice:

- Auth acquisition (Stage 0) — `auth-acquire.md` ✅ (Slice 1)
- Recon R1–R4 (Stage 1) — `recon-r1-assets.md`, `recon-r2-content.md`,
  `recon-r3-fingerprint.md`, `recon-r4-js-analysis.md` ✅ (Slice 2)
- Plan (Stage 2) — `plan.md` ✅ (Slice 3a)
- Tier 1 sweep hunters (Stage 3) — all 13 classes ✅ (Slice 3b: `hunters/idor.md`;
  Slice 3c: `hunters/{xss_reflected,xss_stored,sqli,ssrf,auth_bypass,
  business_logic,file_upload,api,websocket,ssti,lfi,race_condition}.md`)
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
subcommand, and the `plan.md` prompt. Slice 3b adds Stage 3's Tier 1 hunter
framework: the append-only `ledger.jsonl` + the `(endpoint, payload_sig,
session)` dedupe primitive (`src/hunters/ledger.ts`), the hunter framework —
prompt rendering, the dedupe+token+ledger probe firer, and `findings/<id>/`
emission (`src/hunters/framework.ts`), the one concrete IDOR hunter
(`hunters/idor.md`), and the `bbh sweep --class idor` subcommand. Slice 3c
completes Stage 3: the remaining 12 Tier 1 hunter prompts, the parallel sweep
with a concurrency-capped worker pool (`src/hunters/sweep.ts`,
`scope.sweep_concurrency` default 5), the reactive hypothesis stream
(`source: "tier1_reactive"` → `hypotheses.jsonl`, capped at 15/engagement), the
ledger-derived coverage matrix (`src/hunters/coverage.ts` →
`coverage.json`, cells classified `swept` / `deep_dived` / `GAP`), and the
`bbh sweep` subcommand now sweeping every `(surface × class)` cell.
