// Stage 6 — the Tier 2 structured recipe prompt.
//
// Every Tier 2 deep-hunt iteration receives a fresh prompt with six FIXED
// sections (PRD user story 19). Keeping the agent's brief to a rigid recipe is
// what stops a high-budget deep hunter from wandering: it must confirm or reject
// ONE hypothesis, it is told what has already been tried, it is handed the
// verifier's rejection reasons as mutation seeds, and it must return one of three
// parseable outcomes.
//
//   HYPOTHESIS      — one specific claim to confirm or reject
//   CONTEXT         — surface, endpoint, auth, target user/tenant setup
//   ALREADY_TRIED   — ledger slice: payload_ids attempted before (this class)
//   MUTATION_HINTS  — the verifier's / prior iterations' rejection reasons
//   BUDGET          — max probes, max minutes
//   OUTPUT_SCHEMA   — the JSON shape it must return
//
// buildRecipe is a pure string builder so the "every section populated" contract
// is one testable unit. A section with no data still renders a non-empty
// placeholder — a blank section reads as "nothing to try" and the recipe is the
// agent's whole brief, so silence is a bug.

import type { Hypothesis } from "../plan.ts";

/** The runaway-protection budget one deep-hunt iteration is handed. */
export interface RecipeBudget {
  max_probes: number;
  max_minutes: number;
}

export interface RecipeInput {
  hypothesis: Hypothesis;
  /** 1-based iteration number (fresh agent each time). */
  iteration: number;
  /** Surface, endpoint, auth, and target user/tenant setup, prose. */
  context: string;
  /** Ledger slice: payload_ids already fired on this hypothesis's class. */
  alreadyTried: string[];
  /** The verifier's / prior iterations' rejection reasons, newest last. */
  mutationHints: string[];
  budget: RecipeBudget;
}

/**
 * The OUTPUT_SCHEMA the deep hunter must return — one of three outcomes. Kept as
 * a shared constant so the prompt the agent reads and the schema the orchestrator
 * validates (deep-hunter.ts) never drift.
 */
export const OUTPUT_SCHEMA_DOC = [
  "Return EXACTLY one JSON object, one of these three shapes:",
  '  { "outcome": "finding", "finding": { "title", "severity", "endpoint",',
  '      "method", "vuln_class", "poc", "response"?, "evidence"?, "notes"? } }',
  '  { "outcome": "rejected", "reason": "<why this hypothesis does not hold>" }',
  '  { "outcome": "needs_more_budget", "reason": "<what remains>",',
  '      "mutation_hint": "<what the next iteration should vary>" }',
  "A `finding` MUST ship a runnable `poc` (the Verifier re-fires it).",
].join("\n");

/** Render a bullet list, or a single placeholder line when the list is empty. */
function bullets(items: string[], emptyPlaceholder: string): string {
  if (items.length === 0) return emptyPlaceholder;
  return items.map((i) => `- ${i}`).join("\n");
}

/**
 * Build the six-section recipe for one deep-hunt iteration. Every section is
 * guaranteed non-empty: an absent ALREADY_TRIED / MUTATION_HINTS renders an
 * explicit "(none …)" line rather than a blank, so the agent never mistakes a
 * missing section for an empty brief.
 */
export function buildRecipe(input: RecipeInput): string {
  const h = input.hypothesis;
  const firstIteration = input.iteration <= 1;
  return [
    `# Tier 2 deep-hunt — iteration ${input.iteration}`,
    "",
    "HYPOTHESIS:",
    `- ${h.hypothesis}`,
    `- id: ${h.id} · class: ${h.class} · source: ${h.source}`,
    "",
    "CONTEXT:",
    bullets(
      [
        `target_endpoint: ${h.target_endpoint}`,
        ...(input.context.trim() ? [input.context.trim()] : []),
        ...(h.signal_evidence.trim()
          ? [`signal_evidence: ${h.signal_evidence.trim()}`]
          : []),
      ],
      `- target_endpoint: ${h.target_endpoint}`,
    ),
    "",
    "ALREADY_TRIED:",
    bullets(
      input.alreadyTried,
      firstIteration
        ? "- (none tried yet — this is the first iteration)"
        : "- (no prior probes on this class in the ledger)",
    ),
    "- HARD RULE: grep ledger.jsonl for the (endpoint, payload_sig, session)",
    "  3-tuple before firing ANY novel probe; a match means skip it.",
    "",
    "MUTATION_HINTS:",
    bullets(
      input.mutationHints,
      firstIteration
        ? "- (none — open with the most direct probe of the hypothesis)"
        : "- (prior iteration left no hint — vary payload shape or session)",
    ),
    "",
    "BUDGET:",
    `- max_probes: ${input.budget.max_probes}`,
    `- max_minutes: ${input.budget.max_minutes}`,
    "",
    "OUTPUT_SCHEMA:",
    OUTPUT_SCHEMA_DOC,
    "",
  ].join("\n");
}

/** The six required section headers, in order — the recipe contract. */
export const RECIPE_SECTIONS = [
  "HYPOTHESIS:",
  "CONTEXT:",
  "ALREADY_TRIED:",
  "MUTATION_HINTS:",
  "BUDGET:",
  "OUTPUT_SCHEMA:",
] as const;
