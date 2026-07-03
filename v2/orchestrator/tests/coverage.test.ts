import { describe, it, expect } from "vitest";
import {
  deriveCoverage,
  countGaps,
  isDeepDiveEntry,
  type Coverage,
} from "../src/hunters/coverage.ts";
import { LedgerEntrySchema, type LedgerEntry } from "../src/hunters/ledger.ts";
import { HuntPlanCellSchema, type HuntPlanCell } from "../src/plan.ts";

// A committed spec for the (surface × endpoint × class) coverage matrix — the
// pre-report gap check derived from the ledger + hunt plan.

const cell = (
  surface: string,
  vuln_class: string,
  relevant_endpoints: string[],
): HuntPlanCell => HuntPlanCellSchema.parse({ surface, vuln_class, relevant_endpoints });

const entry = (over: Partial<LedgerEntry>): LedgerEntry =>
  LedgerEntrySchema.parse({
    ts: "2026-07-03T00:00:00.000Z",
    pass: 0,
    agent: "H-idor",
    surface: "api",
    endpoint: "/api/Users/2",
    method: "GET",
    class: "idor",
    payload_id: "p",
    payload_sig: "sig:aaaa",
    context: { session: "userA" },
    result: { status: "200", trigger_match: false },
    ...over,
  });

describe("isDeepDiveEntry", () => {
  it("flags T2- / deep- agents as deep dives, Tier 1 hunters as not", () => {
    expect(isDeepDiveEntry(entry({ agent: "T2-idor" }))).toBe(true);
    expect(isDeepDiveEntry(entry({ agent: "deep-idor" }))).toBe(true);
    expect(isDeepDiveEntry(entry({ agent: "H-idor" }))).toBe(false);
  });
});

describe("deriveCoverage", () => {
  it("marks a planned endpoint with no probes as GAP", () => {
    const cov = deriveCoverage(
      [cell("api", "idor", ["/api/Users/2", "/api/Users/3"])],
      [entry({ endpoint: "/api/Users/2" })],
    );
    expect(cov["api"]!["/api/Users/2"]!["idor"]!.status).toBe("swept");
    expect(cov["api"]!["/api/Users/3"]!["idor"]).toEqual({
      payloads_tried: 0,
      last_pass: null,
      status: "GAP",
    });
  });

  it("counts distinct payload signatures and the highest pass", () => {
    const cov = deriveCoverage(
      [cell("api", "idor", ["/api/Users/2"])],
      [
        entry({ payload_sig: "sig:a", pass: 0 }),
        entry({ payload_sig: "sig:b", pass: 0 }),
        entry({ payload_sig: "sig:a", pass: 0 }), // repeat sig — not double-counted
      ],
    );
    const c = cov["api"]!["/api/Users/2"]!["idor"]!;
    expect(c.payloads_tried).toBe(2);
    expect(c.status).toBe("swept");
  });

  it("promotes a cell to deep_dived when a Tier 2 probe touched it", () => {
    const cov = deriveCoverage(
      [cell("api", "idor", ["/api/Users/2"])],
      [entry({ agent: "H-idor", pass: 0 }), entry({ agent: "T2-idor", pass: 1 })],
    );
    const c = cov["api"]!["/api/Users/2"]!["idor"]!;
    expect(c.status).toBe("deep_dived");
    expect(c.last_pass).toBe(1);
  });

  it("includes an off-plan probed endpoint (never invisible)", () => {
    const cov = deriveCoverage(
      [cell("api", "idor", ["/api/Users/2"])],
      [entry({ endpoint: "/api/Cards/9", surface: "api", class: "idor" })],
    );
    expect(cov["api"]!["/api/Cards/9"]!["idor"]!.status).toBe("swept");
    // The planned-but-unprobed endpoint is still a GAP.
    expect(cov["api"]!["/api/Users/2"]!["idor"]!.status).toBe("GAP");
  });
});

describe("countGaps", () => {
  it("totals the GAP cells across the matrix", () => {
    const cov: Coverage = deriveCoverage(
      [
        cell("api", "idor", ["/a", "/b"]),
        cell("admin", "xss_reflected", ["/x"]),
      ],
      [entry({ surface: "api", endpoint: "/a", class: "idor" })],
    );
    // /b and /x are unprobed -> 2 gaps; /a is swept.
    expect(countGaps(cov)).toBe(2);
  });
});
