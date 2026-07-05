# BugBountyHunter — Roadmap

The product direction and phased build plan. For the full design rationale (and the
grilling + research that produced it) see `Plans/witty-twirling-valiant.md` and the
research briefs alongside it.

## North Star

**Point the system at a target you're authorized to test, and it returns a short,
ranked list of _real, reproduced_ vulnerabilities worth submitting — and it gets
better every time you run it.**

Under the hood: capable specialist AI hunters that know real technique (from a
curated knowledge base distilled from disclosed reports), that **dig deep** instead
of surface-scanning, that **prove** each finding so you aren't chasing false
positives — ranked and handed to a human who makes the final call. Every engagement
grows the knowledge base.

## Where we are today

- The v2 **orchestration skeleton is built and tested** — state machine, scope
  check, ledger dedupe, budget halts, resume, report, verify routing (245 tests).
- But **every agent is a stub** — `bbh pentest` halts at Stage 0 (auth) and finds
  nothing.
- **Next up: Phase 1** — drop one real hunter into the skeleton and prove it finds
  and proves a real bug.

## The pipeline

```
 scope.yaml ─▶ AUTH ─▶ RECON ─▶ PLAN ─▶ TIER-1 SWEEP ─▶ CHECKLIST ─▶ VERIFY ─▶ REPORT ─▶ YOU
  target                         per-class specialists    guard      oracle proves +   ranked,
  creds                          + real tools             kills      reviewer scores;  proven
  identities                          │                   noise      re-dispatch;      findings
                                      │                              nothing dropped
                                      └▶ hypotheses ─▶ TIER-2 DEEP HUNT (depth) ─────┘
                                                             ▲
   KNOWLEDGE BASE (curated) ──── arms every hunter ──────────┤
   grows via Curator write-back ◀── stuck lead ─▶ GET-UNSTUCK RESEARCH ─▶ resume

  ── across every stage: ledger dedupe · budget halts · resume ──
```

## The four phases

Four capability jumps. Each is shippable and proven before the next.

| Phase | Name | Capability jump | Delivers |
|---|---|---|---|
| **1** | Make it hunt | finds nothing → one real, proven bug | one capable IDOR hunter + differential oracle, on Juice Shop |
| **2** | Make it hunt everything | one bug type → many classes, any target | the swarm (per-class + depth), real recon, full tool arsenal |
| **3** | Make it hunt smart | obvious bugs → paying bugs | curated knowledge base injected into hunters |
| **4** | Make it get smarter | static → improves each run | learning loop: research-when-stuck + write-back + precedent check |

### Phase 1 — Make it hunt  *(next)*

The **walking skeleton**: replace the stubs with ONE real, capable **IDOR** hunter
that finds **and proves** one real cross-tenant bug on Juice Shop. Effort is
concentrated on the risk:

- **Capable hunter** — a tool-using loop with **2 real identities** and an
  `idor` playbook.
- **Differential oracle** — proves the finding in code (authed reads a private
  field that unauth cannot), so "confirmed" is a fact, not an opinion.
- **Real auth** (2-identity HTTP login) because IDOR needs it.
- **Recon + plan stay trivial/hardcoded** — hand the hunter Juice Shop's known
  id-bearing endpoints. Tools = `http_request` + identities only.
- **Success:** `report.md` with ≥1 real, oracle-reproduced IDOR. Reuses the whole
  v2 spine.

### Phase 2 — Make it hunt everything

From one hunter to the full swarm: **per-class specialists** (breadth) + the
class-agnostic **Tier-2 depth agent**; real recon/plan feeding them; the full
installed arsenal wrapped as tools (`nuclei`, `sqlmap`, `ffuf`, `dalfox`,
`dev-browser`); the oracle framework generalized per class; the single grounded
reviewer with re-dispatch-for-evidence; the ranked report.

### Phase 3 — Make it hunt smart

Seed the **curated knowledge base** (distilled from the on-disk skills + top sources:
PortSwigger Academy, HackTricks, PayloadsAllTheThings, curated disclosed-report
datasets) and inject each class's playbook into its hunter, so it hunts with real
technique rather than generic guessing.

### Phase 4 — Make it get smarter

The **learning loop**: a get-unstuck research agent (web + KB) for blocked leads, a
**Curator** that writes proven techniques back to the KB, and a **precedent check**
that flags likely-already-public findings. Every engagement grows the KB and skips
known bugs.

## Core design decisions

1. **Capable, looping agents** with real tools — not a rigid payload-firer.
2. **Scope stays simple** — reuse the existing one-line `checkScope`; no sandbox or
   egress proxy (that's for unattended fleets, not a human-in-the-loop tool).
3. **Verification = oracle + one reviewer, nothing dropped, the human is the gate.**
   Deterministic per-class oracles *label* confidence where they cheaply apply; one
   independent, grounded reviewer handles the variety and can *re-dispatch for more
   evidence*. Recall-first: candidates are ranked, never discarded.
4. **Identities are per-engagement** (`0 / 1 / 2+`), declared in `scope.yaml`.
5. **Two-tier specialization** — per-class breadth specialists + one class-agnostic
   depth agent for chains and business logic.
6. **Knowledge is curated, not scraped** — small, sharp per-class playbooks distilled
   from real reports; written back only with *proven* techniques.

## How we verify each phase

- **P1:** live `bbh pentest http://localhost:3000` → ≥1 real IDOR in `report.md`,
  reproduced by the oracle; `ledger.jsonl` shows real probes; resume-after-kill
  works. Offline seam tests (fake LLM client, injected `fetch`, pure oracle) green.
- **P2:** the swarm finds ≥2 distinct real bugs on a seeded vulnerable app;
  per-class oracle unit tests; a planted false positive is *labeled low*, not dropped.
- **P3:** a KB-armed hunter beats the same hunter KB-less on recall (A/B).
- **P4:** a stuck lead is unblocked by research and the technique lands in the KB; a
  known-public finding is precedent-flagged.
