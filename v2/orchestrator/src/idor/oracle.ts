// The IDOR differential oracle (pure).
//
// This is the deterministic gate that turns a *candidate* cross-tenant read into
// a *confirmed* IDOR — the "confirmed means proven, not asserted" guarantee (PRD
// user stories 8-9). It reasons over a differential: the same victim object read
//   (a) as the attacking identity A, and
//   (b) unauthenticated.
// A finding is confirmed ONLY when the claimed-private field is present for the
// attacker AND absent/denied unauthenticated — i.e. a genuine cross-tenant leak,
// not a public-by-design endpoint and not the attacker's own data.
//
// It is a PURE function (no disk, clock, or network) so the whole decision table
// is one exhaustively-tested unit. It NEVER drops a finding: a non-confirmation
// is a labelled `confirmed:false` verdict the caller surfaces/escalates, never a
// silent discard.

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/** One side of the differential: an HTTP status + response body. */
export interface DifferentialResponse {
  status: number;
  body: string;
}

/**
 * Everything the oracle needs to rule on one candidate IDOR.
 *  - `private_field`   the field claimed private (documentary; drives the reason)
 *  - `victim_marker`   a value unique to the VICTIM's object; its presence in the
 *                      attacker's response is the cross-tenant leak signal
 *  - `attacker_marker` the ATTACKER's own equivalent value (optional). If the
 *                      read returns this and NOT the victim marker, the endpoint
 *                      served the attacker their own data — not an IDOR.
 *  - `attacker`        the victim object read AS identity A
 *  - `unauth`          the same victim object read UNAUTHENTICATED
 */
export interface IdorObservation {
  private_field: string;
  victim_marker: string;
  attacker_marker?: string;
  attacker: DifferentialResponse;
  unauth: DifferentialResponse;
}

export type Confidence = "high" | "medium" | "low";

/** The oracle's structured signals — surfaced so a verdict is explainable. */
export interface OracleSignals {
  /** Attacker's read returned a 2xx. */
  attacker_read_ok: boolean;
  /** The victim's marker appears in the attacker's response (cross-tenant leak). */
  victim_data_leaked: boolean;
  /** The attacker's own marker (not the victim's) came back — own-data, not IDOR. */
  own_data: boolean;
  /** Unauthenticated read was denied OR did not expose the victim marker. */
  unauth_denied: boolean;
  /** Unauthenticated read ALSO exposed the victim marker — public-by-design. */
  public_by_design: boolean;
}

export interface IdorOracleVerdict {
  confirmed: boolean;
  confidence: Confidence;
  reason: string;
  signals: OracleSignals;
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

/** Marker presence: a substring hit in the body. Markers are unique values
 *  (an email, a token, an address line), so a substring match is unambiguous. */
function bodyHas(body: string, marker: string): boolean {
  return marker.length > 0 && body.includes(marker);
}

/**
 * Rule on one candidate IDOR. Confirmed IFF all three hold:
 *   1. the attacker's read succeeded (2xx),
 *   2. the victim's marker is present in the attacker's body (cross-tenant leak),
 *   3. the unauthenticated read was denied or did not expose that marker.
 * Anything else is a labelled non-confirmation (public-by-design, own-data,
 * attacker denied, or no leak) — never a drop.
 */
export function runIdorOracle(obs: IdorObservation): IdorOracleVerdict {
  const attacker_read_ok = is2xx(obs.attacker.status);
  const victim_data_leaked = bodyHas(obs.attacker.body, obs.victim_marker);
  const attacker_marker_present =
    obs.attacker_marker !== undefined && bodyHas(obs.attacker.body, obs.attacker_marker);
  const own_data = attacker_marker_present && !victim_data_leaked;

  const unauth_has_victim = bodyHas(obs.unauth.body, obs.victim_marker);
  const unauth_allowed = is2xx(obs.unauth.status);
  const public_by_design = unauth_allowed && unauth_has_victim;
  const unauth_denied = !public_by_design;

  const signals: OracleSignals = {
    attacker_read_ok,
    victim_data_leaked,
    own_data,
    unauth_denied,
    public_by_design,
  };

  const confirmed = attacker_read_ok && victim_data_leaked && unauth_denied;

  if (confirmed) {
    // A hard unauthenticated deny (4xx/5xx) is stronger proof of an access-control
    // boundary than a soft one (2xx but the marker absent), so it rates higher.
    const unauthHardDeny = obs.unauth.status >= 400;
    const confidence: Confidence = unauthHardDeny ? "high" : "medium";
    return {
      confirmed: true,
      confidence,
      reason:
        `cross-tenant IDOR: private field "${obs.private_field}" leaked to the ` +
        `attacking identity (victim marker present) and ` +
        (unauthHardDeny
          ? `denied unauthenticated (HTTP ${obs.unauth.status}).`
          : `absent unauthenticated (HTTP ${obs.unauth.status}, marker not returned).`),
      signals,
    };
  }

  // Non-confirmations — each labelled so the caller can surface, not drop.
  let reason: string;
  if (!attacker_read_ok) {
    reason = `not confirmed: attacker read denied (HTTP ${obs.attacker.status}) — access control held.`;
  } else if (own_data) {
    reason = `not confirmed: attacker's own data returned, not the victim's ("${obs.private_field}" own-data, not cross-tenant).`;
  } else if (!victim_data_leaked) {
    reason = `not confirmed: victim marker for "${obs.private_field}" not present in the attacker's response.`;
  } else {
    // victim data leaked to the attacker AND to unauthenticated => public.
    reason = `not confirmed: public-by-design — the unauthenticated request also returns "${obs.private_field}".`;
  }
  return { confirmed: false, confidence: "low", reason, signals };
}
