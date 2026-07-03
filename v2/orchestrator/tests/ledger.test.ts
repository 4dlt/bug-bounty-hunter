import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  payloadSig,
  isDuplicateProbe,
  probeDedupeKey,
  appendLedger,
  readLedger,
  ledgerPath,
  LedgerEntrySchema,
  type LedgerEntry,
  type ProbeKey,
} from "../src/hunters/ledger.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(here, "fixtures", "ledger");

async function loadFixtureLedger(name: string): Promise<LedgerEntry[]> {
  const raw = await fs.readFile(path.join(FIXTURES, name), "utf8");
  return raw
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => LedgerEntrySchema.parse(JSON.parse(l)));
}

describe("payloadSig", () => {
  it("is deterministic for identical payloads", () => {
    expect(payloadSig("GET /api/Users/2")).toBe(payloadSig("GET /api/Users/2"));
  });

  it("changes when the payload is mutated (novel probe -> novel sig)", () => {
    expect(payloadSig("/api/Users/2")).not.toBe(payloadSig("/api/Users/3"));
  });

  it("is stable across object key order", () => {
    expect(payloadSig({ id: 2, method: "GET" })).toBe(
      payloadSig({ method: "GET", id: 2 }),
    );
  });

  it("is namespaced with a sig: prefix", () => {
    expect(payloadSig("x")).toMatch(/^sig:[0-9a-f]{16}$/);
  });
});

describe("isDuplicateProbe (table-driven, keyed on endpoint+payload_sig+session)", () => {
  let ledger: LedgerEntry[];
  beforeEach(async () => {
    ledger = await loadFixtureLedger("base.jsonl");
  });

  // The four cases the PRD's dedupe seam must pin down.
  const cases: Array<{
    name: string;
    probe: ProbeKey & { waf?: string };
    expected: boolean;
  }> = [
    {
      name: "same-payload-different-session -> novel",
      probe: { endpoint: "/api/Users/2", payload_sig: "sig:1111111111111111", session: "userB" },
      expected: false,
    },
    {
      name: "mutated-payload (new payload_sig) -> novel",
      probe: { endpoint: "/api/Users/2", payload_sig: "sig:9999999999999999", session: "userA" },
      expected: false, // novel
    },
    {
      name: "exact-repeat -> duplicate",
      probe: { endpoint: "/api/Users/2", payload_sig: "sig:1111111111111111", session: "userA" },
      expected: true,
    },
    {
      name: "same-payload-same-session-same-WAF -> duplicate (WAF not part of the key)",
      probe: { endpoint: "/rest/basket/1", payload_sig: "sig:2222222222222222", session: "userA", waf: "none" },
      expected: true,
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      expect(isDuplicateProbe(c.probe, ledger)).toBe(c.expected);
    });
  }

  it("keys purely on the 3-tuple, ignoring extra context like WAF", () => {
    const differentWaf: ProbeKey = {
      endpoint: "/rest/basket/1",
      payload_sig: "sig:2222222222222222",
      session: "userA",
    };
    // The fixture row has waf:"none"; a probe with any/other WAF is still a dup.
    expect(isDuplicateProbe(differentWaf, ledger)).toBe(true);
  });

  it("treats an empty ledger as all-novel", () => {
    expect(
      isDuplicateProbe(
        { endpoint: "/api/Users/2", payload_sig: "sig:1111111111111111", session: "userA" },
        [],
      ),
    ).toBe(false);
  });
});

describe("probeDedupeKey", () => {
  it("collides only on all three fields", () => {
    const base = { endpoint: "/a", payload_sig: "sig:1", session: "s" };
    expect(probeDedupeKey(base)).toBe(probeDedupeKey({ ...base }));
    expect(probeDedupeKey(base)).not.toBe(probeDedupeKey({ ...base, session: "t" }));
    expect(probeDedupeKey(base)).not.toBe(probeDedupeKey({ ...base, endpoint: "/b" }));
    expect(probeDedupeKey(base)).not.toBe(probeDedupeKey({ ...base, payload_sig: "sig:2" }));
  });
});

describe("ledger persistence", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "bbh-ledger-"));
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  const entry = (over: Partial<LedgerEntry> = {}): LedgerEntry =>
    LedgerEntrySchema.parse({
      ts: "2026-07-03T00:00:00.000Z",
      pass: 0,
      agent: "H-idor",
      surface: "api",
      endpoint: "/api/Users/2",
      class: "idor",
      payload_id: "p1",
      payload_sig: "sig:abc",
      context: { session: "userA" },
      result: { status: "200" },
      ...over,
    });

  it("appends rows (never truncates) and round-trips through readLedger", async () => {
    await appendLedger(dir, entry({ payload_sig: "sig:a" }));
    await appendLedger(dir, entry({ payload_sig: "sig:b" }));
    const back = await readLedger(dir);
    expect(back.map((e) => e.payload_sig)).toEqual(["sig:a", "sig:b"]);
  });

  it("returns an empty ledger when the file is missing", async () => {
    expect(await readLedger(dir)).toEqual([]);
  });

  it("writes valid JSONL that re-parses against the schema", async () => {
    await appendLedger(dir, entry());
    const raw = await fs.readFile(ledgerPath(dir), "utf8");
    const line = raw.trim();
    expect(() => LedgerEntrySchema.parse(JSON.parse(line))).not.toThrow();
  });
});
