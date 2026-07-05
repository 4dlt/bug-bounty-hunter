// The hardcoded Phase-1 tracer: the trivial "recon + plan" that hands the IDOR
// hunter the target's known id-bearing endpoints (PRD user story 5).
//
// No LLM, no crawl — Phase 1 concentrates effort on the hunter + the oracle, so
// the surface is handed to the pipeline. A multi-identity engagement (≥2 named
// identities in scope.yaml) yields one cross-tenant probe per (attacker, victim)
// pair against each id-bearing endpoint template, using the victim identity's
// username as the leak marker. Endpoints are Juice-Shop-tuned defaults an
// operator can extend; the oracle — not this list — decides what is a real bug.

import type { Scope } from "../scope.ts";
import { IdorProbeSpecSchema, type IdorProbeSpec } from "./probe.ts";

/**
 * Id-bearing endpoints the hardcoded IDOR probe targets. `{vid}` is substituted
 * with a victim object id. Juice Shop exposes a user's basket at `/rest/basket/N`
 * and user records at `/api/Users/N`; a real engagement extends this list.
 */
export const IDOR_ENDPOINT_TEMPLATES = ["/rest/basket/{vid}", "/api/Users/{vid}"] as const;

/** The victim object id the tracer substitutes into each template by default. */
export const DEFAULT_VICTIM_OBJECT_ID = "2";

export interface TracerOptions {
  /** Victim object id to substitute into the endpoint templates. */
  victimObjectId?: string;
  /** Endpoint templates to expand (defaults to IDOR_ENDPOINT_TEMPLATES). */
  templates?: readonly string[];
}

/**
 * Build the hardcoded IDOR probe specs for an engagement. Empty when fewer than
 * two identities are declared (cross-tenant testing needs an attacker AND a
 * distinct victim). Identity 0 is the attacker; every other identity is a victim.
 */
export function buildTracerSpecs(scope: Scope, opts: TracerOptions = {}): IdorProbeSpec[] {
  if (scope.identities.length < 2) return [];
  const vid = opts.victimObjectId ?? DEFAULT_VICTIM_OBJECT_ID;
  const templates = opts.templates ?? IDOR_ENDPOINT_TEMPLATES;
  const attacker = scope.identities[0]!;
  const specs: IdorProbeSpec[] = [];
  for (const victim of scope.identities.slice(1)) {
    for (const template of templates) {
      specs.push(
        IdorProbeSpecSchema.parse({
          endpoint: template.replace("{vid}", vid),
          attacker: attacker.name,
          private_field: "email",
          victim_marker: victim.username,
          attacker_marker: attacker.username,
          payload_id: `idor-${template.replace(/[^a-z0-9]+/gi, "-")}-${vid}`,
        }),
      );
    }
  }
  return specs;
}

/** The single hunt-plan surface the tracer sweeps (the handed id-bearing API). */
export const TRACER_SURFACE = "api";
