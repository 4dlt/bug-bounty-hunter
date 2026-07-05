// The hardcoded IDOR probe — Phase 1's tracer-bullet hunter (no LLM).
//
// A `HunterRunner` that, for each declared id-bearing victim object, fires the
// SAME request twice through `ctx.fire` (the dedupe + token + ledger firer):
// once as the attacking identity A, once unauthenticated. When A's read
// succeeds it emits a candidate finding carrying:
//   - a self-checking `poc.sh` that exits non-zero unless the cross-tenant read
//     AND the unauth-denied condition BOTH hold, and
//   - an `evidence/oracle.json` with the differential the oracle rules on.
// The oracle-wired Verifier is the confirmation gate; this hunter only produces
// the candidate + its proof harness.
//
// It is "hardcoded" in that the victim objects + markers are handed to it (a
// trivial recon feeds them) rather than discovered by an LLM — but every probe
// still fires through the real transport and the real ledger path.

import { z } from "zod";
import type {
  HunterContext,
  HunterFinding,
  HunterRunner,
  HunterYield,
  FireResult,
} from "../hunters/framework.ts";
import {
  UNAUTH_SESSION,
  decodeProbeEvidence,
  type IdentitySession,
} from "./transport.ts";
import type { DifferentialResponse, IdorObservation } from "./oracle.ts";

/**
 * One hardcoded cross-tenant probe: read `endpoint` (a victim's object) as the
 * attacker and unauthenticated, looking for `victim_marker` in the response.
 */
export const IdorProbeSpecSchema = z.object({
  /** The victim object endpoint (path or absolute URL). */
  endpoint: z.string().min(1),
  method: z.string().default("GET"),
  /** Identity name of the attacker (must be a captured session). */
  attacker: z.string().min(1),
  /** The field claimed private (documentary; drives the finding title/reason). */
  private_field: z.string().min(1),
  /** A value unique to the victim's object; its leak proves cross-tenant read. */
  victim_marker: z.string().min(1),
  /** The attacker's own equivalent value (own-data guard), optional. */
  attacker_marker: z.string().optional(),
  /** Mutation-recipe label recorded on the ledger row. */
  payload_id: z.string().default("idor-object-substitution"),
  severity: z.string().default("high"),
});
export type IdorProbeSpec = z.infer<typeof IdorProbeSpecSchema>;

/** Body + status a fired probe returned (decoded from the ledger evidence). */
function readResponse(fire: FireResult): DifferentialResponse {
  if (!fire.fired) return { status: 0, body: "" };
  return decodeProbeEvidence(fire.result.evidence);
}

/**
 * Build the self-checking `poc.sh` body. It re-fires the cross-tenant read as the
 * attacker and unauthenticated and EXITS NON-ZERO unless both the cross-tenant
 * leak and the unauth-deny hold — so the Verifier's re-fire is a mechanical
 * pass/fail, not a judgement call. The attacker credential is baked in; the base
 * URL is overridable via `$TARGET`.
 */
export function buildPocScript(
  spec: IdorProbeSpec,
  attackerAuth: string | undefined,
  base: string,
): string {
  const authArg = attackerAuth ? `-H 'Authorization: ${attackerAuth}'` : "";
  return [
    "#!/usr/bin/env bash",
    `# Self-checking PoC — cross-tenant IDOR on ${spec.endpoint}`,
    `# Private field: ${spec.private_field}. Exits 0 ONLY if the bug reproduces.`,
    "set -uo pipefail",
    `BASE="\${TARGET:-${base}}"`,
    `EP="${spec.endpoint}"`,
    `MARKER='${spec.victim_marker}'`,
    "",
    "# 1. Cross-tenant read as the attacking identity must expose the victim marker.",
    `attacker=$(curl -s ${authArg} "$BASE$EP")`,
    'echo "$attacker"',
    'if ! printf "%s" "$attacker" | grep -qF "$MARKER"; then',
    '  echo "FAIL: cross-tenant read did not expose the victim marker" >&2',
    "  exit 1",
    "fi",
    "",
    "# 2. The same read unauthenticated must be denied or must NOT expose the marker.",
    `unauth_code=$(curl -s -o /tmp/bbh_idor_unauth.$$ -w '%{http_code}' "$BASE$EP")`,
    'if [ "$unauth_code" -lt 400 ] && grep -qF "$MARKER" /tmp/bbh_idor_unauth.$$; then',
    '  rm -f /tmp/bbh_idor_unauth.$$',
    '  echo "FAIL: unauthenticated request also exposes the marker (public-by-design)" >&2',
    "  exit 1",
    "fi",
    'rm -f /tmp/bbh_idor_unauth.$$',
    'echo "PASS: cross-tenant IDOR reproduced (leaked to attacker, denied unauthenticated)"',
    "exit 0",
    "",
  ].join("\n");
}

/**
 * Assemble the candidate finding for a probe whose attacker read succeeded. The
 * differential the oracle rules on is written to `evidence/oracle.json`; the PoC
 * is the mechanical proof harness.
 */
export function buildIdorFinding(
  spec: IdorProbeSpec,
  base: string,
  attackerSession: IdentitySession | undefined,
  attacker: DifferentialResponse,
  unauth: DifferentialResponse,
): HunterFinding {
  const observation: IdorObservation = {
    private_field: spec.private_field,
    victim_marker: spec.victim_marker,
    attacker_marker: spec.attacker_marker,
    attacker,
    unauth,
  };
  return {
    title: `Cross-tenant IDOR on ${spec.endpoint} (${spec.private_field} exposed)`,
    severity: spec.severity,
    endpoint: spec.endpoint,
    method: spec.method,
    vuln_class: "idor",
    poc: buildPocScript(spec, attackerSession?.authorization, base),
    response: attacker.body,
    evidence: { "oracle.json": JSON.stringify(observation, null, 2) },
    notes:
      `Fired as "${spec.attacker}" vs unauthenticated. The oracle confirms iff the ` +
      `victim marker leaked to the attacker and was denied unauthenticated.`,
  };
}

/**
 * Build the hardcoded IDOR hunter runner. Closes over the captured sessions so
 * it can bake the attacker credential into each PoC; the actual probe firing
 * goes through `ctx.fire` (which injects the credential via the transport and
 * enforces dedupe + token + ledger).
 */
export function createIdorHunterRunner(
  specs: IdorProbeSpec[],
  sessions: Map<string, IdentitySession>,
  base: string,
): HunterRunner {
  const parsed = specs.map((s) => IdorProbeSpecSchema.parse(s));
  return async (ctx: HunterContext): Promise<HunterYield> => {
    const findings: HunterFinding[] = [];
    for (const spec of parsed) {
      // Fire as the attacker, then unauthenticated. Different session => the
      // dedupe treats these as two legitimately distinct probes.
      const attackerFire = await ctx.fire({
        endpoint: spec.endpoint,
        method: spec.method,
        payload_id: spec.payload_id,
        payload: `${spec.payload_id}:${spec.attacker}`,
        session: spec.attacker,
      });
      const unauthFire = await ctx.fire({
        endpoint: spec.endpoint,
        method: spec.method,
        payload_id: spec.payload_id,
        payload: `${spec.payload_id}:${UNAUTH_SESSION}`,
        session: UNAUTH_SESSION,
      });

      const attacker = readResponse(attackerFire);
      const unauth = readResponse(unauthFire);

      // A candidate is raised only when the attacker's read actually succeeded —
      // otherwise access control held and there is nothing to confirm. Whether it
      // is a TRUE cross-tenant leak (vs public-by-design / own-data) is the
      // oracle's call, not the hunter's.
      if (attacker.status >= 200 && attacker.status < 300 && attacker.body.length > 0) {
        findings.push(
          buildIdorFinding(spec, base, sessions.get(spec.attacker), attacker, unauth),
        );
      }
    }
    return { findings };
  };
}
