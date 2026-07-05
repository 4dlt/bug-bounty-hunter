// Stage 6 — the Report generator.
//
// Reads `verdicts/pass-*.json` for every `confirmed` finding and produces a
// single `report.md`: title, severity (P1–P4 by impact, NOT bounty), affected
// endpoint, PoC reference, evidence reference, and a suggested fix. Findings the
// verify loop escalated to `ready-for-human` get their own section.
//
// PRD (user stories 27, 28, 40): the report contains ONLY confirmed findings and
// carries NO bounty estimation — severity reflects true impact. A source-level
// test greps this module to prove the string `bounty` never appears.

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { findingDir } from "../hunters/framework.ts";
import { FindingMetaSchema, type FindingMeta } from "../checklist/author.ts";
import { verdictsDir, VerdictSchema, type Verdict } from "../verify/verifier.ts";
import { readyForHumanPath } from "../verify/stage.ts";
import type { State } from "../state.ts";

// ---------------------------------------------------------------------------
// Severity → priority (impact, not bounty)
// ---------------------------------------------------------------------------

/** P1–P4 impact bands. P1 is the highest impact, P4 the lowest. */
export type Priority = "P1" | "P2" | "P3" | "P4";

/**
 * Map a finding's severity band to a P1–P4 impact priority. This is an IMPACT
 * ranking, not a bounty prediction (PRD: no bounty estimation). Anything the
 * hunter left `unknown` is conservatively floored to P4 so the report never
 * over-states impact it did not observe.
 */
export function severityToPriority(severity: string): Priority {
  switch (severity.trim().toLowerCase()) {
    case "critical":
      return "P1";
    case "high":
      return "P2";
    case "medium":
      return "P3";
    case "low":
    case "info":
    case "informational":
    case "unknown":
    default:
      return "P4";
  }
}

// ---------------------------------------------------------------------------
// Suggested fixes (per vuln class, generic remediation guidance)
// ---------------------------------------------------------------------------

const SUGGESTED_FIX: Record<string, string> = {
  idor: "Enforce object-level authorization: verify the authenticated principal owns (or is entitled to) the referenced object before returning it. Do not rely on unguessable ids.",
  auth_bypass: "Re-check authentication and authorization server-side on every request; never trust client-supplied role, tenant, or identity claims.",
  sqli: "Use parameterized queries / prepared statements; never concatenate untrusted input into SQL. Apply least-privilege DB accounts.",
  xss_reflected: "Context-encode all untrusted output and apply a strict Content-Security-Policy. Validate/allowlist input where feasible.",
  xss_stored: "Context-encode untrusted output at render time and sanitize on input; apply a strict Content-Security-Policy.",
  ssrf: "Allowlist outbound destinations, resolve and validate hostnames, and block requests to internal/link-local ranges.",
  ssti: "Never render user input as a template; use a sandboxed engine and pass untrusted data only as data, not template source.",
  lfi: "Canonicalize and allowlist file paths; reject traversal sequences and never pass untrusted input to filesystem APIs.",
  business_logic: "Enforce the invariant server-side at every step of the flow; do not assume client-driven ordering or values.",
  file_upload: "Validate content type and magic bytes, store outside the web root, randomize names, and never execute uploaded files.",
  api: "Apply authentication, authorization, and rate limiting uniformly across every API route, including undocumented ones.",
  websocket: "Authenticate and authorize the WebSocket handshake and every message; enforce origin checks.",
  race_condition: "Serialize the critical section with a lock or atomic operation; enforce idempotency on state-changing endpoints.",
};

/** Suggested remediation for a finding's class; a generic default otherwise. */
export function suggestedFix(vulnClass: string): string {
  return (
    SUGGESTED_FIX[vulnClass.trim().toLowerCase()] ??
    "Validate and authorize the request server-side, and add a regression test that reproduces this finding."
  );
}

// ---------------------------------------------------------------------------
// Reading confirmed findings + escalations
// ---------------------------------------------------------------------------

/** `verdicts/pass-N.json` — the confirmed verdicts promoted in pass N. */
const PassVerdictsSchema = z.object({
  pass: z.number().int().nonnegative(),
  verdicts: z.array(VerdictSchema),
});

/** A ready-for-human escalation line (verify/stage.ts writes these). */
const EscalationSchema = z.object({
  finding_id: z.string().min(1),
  label: z.string().optional(),
  reason: z.string().default(""),
  evidence_dir: z.string().optional(),
});
export type Escalation = z.infer<typeof EscalationSchema>;

/** A confirmed finding, ready for the report: its verdict + on-disk metadata. */
export interface ConfirmedFinding {
  meta: FindingMeta;
  verdict: Verdict;
}

/**
 * Collect every `confirmed` verdict across all `verdicts/pass-*.json` files,
 * deduped by finding_id (the highest pass wins — the most recent verdict), and
 * pair each with the finding metadata on disk. A confirmed verdict whose
 * `finding.json` is missing or unparseable is skipped rather than crashing the
 * report (the same defensive contract `readFindings` follows).
 */
export async function readConfirmedFindings(
  workdir: string,
): Promise<ConfirmedFinding[]> {
  const dir = verdictsDir(workdir);
  let files: string[] = [];
  try {
    files = (await fs.readdir(dir)).filter((f) => /^pass-\d+\.json$/.test(f));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }

  // Highest pass wins for a given finding_id.
  const byFinding = new Map<string, { pass: number; verdict: Verdict }>();
  for (const file of files) {
    const pass = parseInt(/^pass-(\d+)\.json$/.exec(file)![1]!, 10);
    let parsed;
    try {
      parsed = PassVerdictsSchema.parse(
        JSON.parse(await fs.readFile(path.join(dir, file), "utf8")),
      );
    } catch {
      continue; // a half-written pass file cannot crash the report
    }
    for (const verdict of parsed.verdicts) {
      if (verdict.verdict !== "confirmed") continue;
      const prev = byFinding.get(verdict.finding_id);
      if (!prev || pass >= prev.pass) byFinding.set(verdict.finding_id, { pass, verdict });
    }
  }

  const out: ConfirmedFinding[] = [];
  for (const [findingId, { verdict }] of byFinding) {
    const file = path.join(findingDir(workdir, findingId), "finding.json");
    try {
      const meta = FindingMetaSchema.parse(JSON.parse(await fs.readFile(file, "utf8")));
      out.push({ meta, verdict });
    } catch {
      continue; // missing/half-written finding.json → skip, don't crash
    }
  }
  // Stable order: highest impact first, then finding id.
  out.sort(
    (a, b) =>
      PRIORITY_ORDER[severityToPriority(a.meta.severity)] -
        PRIORITY_ORDER[severityToPriority(b.meta.severity)] ||
      a.meta.id.localeCompare(b.meta.id),
  );
  return out;
}

const PRIORITY_ORDER: Record<Priority, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

/** Read the `ready-for-human.jsonl` escalations; a missing file yields none. */
export async function readEscalations(workdir: string): Promise<Escalation[]> {
  let raw: string;
  try {
    raw = await fs.readFile(readyForHumanPath(workdir), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw err;
  }
  const out: Escalation[] = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(EscalationSchema.parse(JSON.parse(line)));
    } catch {
      continue; // skip a malformed escalation line
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rendering (pure)
// ---------------------------------------------------------------------------

/** The report-relative path to a finding's `evidence/` subdir. */
function evidenceRef(findingId: string): string {
  return `findings/${findingId}/evidence/`;
}

/** Render one confirmed finding's section. */
function renderFinding(index: number, cf: ConfirmedFinding): string {
  const { meta } = cf;
  const priority = severityToPriority(meta.severity);
  const lines = [
    `### ${index}. ${meta.title}  [${priority}]`,
    "",
    `- **Severity:** ${priority} (${meta.severity})`,
    `- **Vulnerability class:** ${meta.vuln_class}`,
    `- **Affected endpoint:** \`${meta.method} ${meta.endpoint}\``,
    `- **Proof of concept:** \`findings/${meta.id}/poc.sh\``,
    `- **Evidence:** \`${evidenceRef(meta.id)}\` (captured response: \`findings/${meta.id}/response.json\`)`,
    `- **Suggested fix:** ${suggestedFix(meta.vuln_class)}`,
  ];
  if (meta.notes) lines.push("", meta.notes.trim());
  return lines.join("\n");
}

/** Render one ready-for-human escalation entry. */
function renderEscalation(esc: Escalation): string {
  return [
    `### ${esc.finding_id}${esc.reason ? ` — ${esc.reason}` : ""}`,
    "",
    `- **Evidence:** \`${esc.evidence_dir ?? evidenceRef(esc.finding_id)}\``,
    `- **PoC:** \`findings/${esc.finding_id}/poc.sh\``,
  ].join("\n");
}

/**
 * Build the full `report.md` string. Pure: no disk, no clock. `confirmed` is
 * rendered one section per finding; `escalations` (if any) get a clearly
 * separated "Ready for Human Review" section. Contains no bounty estimation.
 */
export function buildReport(
  state: State,
  confirmed: ConfirmedFinding[],
  escalations: Escalation[],
): string {
  const parts: string[] = [];
  parts.push(`# Bug Bounty Report — ${state.target}`);
  parts.push("");
  parts.push(`- **Engagement:** ${state.engagement_id}`);
  parts.push(`- **Status:** ${state.status}`);
  parts.push(`- **Confirmed findings:** ${confirmed.length}`);
  if (escalations.length > 0) {
    parts.push(`- **Findings needing human review:** ${escalations.length}`);
  }
  parts.push("");
  parts.push(
    "> Severity is a P1–P4 impact ranking. This report contains no monetary estimation.",
  );
  parts.push("");

  parts.push("## Confirmed Findings");
  parts.push("");
  if (confirmed.length === 0) {
    parts.push("_No findings were confirmed in this engagement._");
  } else {
    confirmed.forEach((cf, i) => {
      parts.push(renderFinding(i + 1, cf));
      parts.push("");
    });
  }

  if (escalations.length > 0) {
    parts.push("## Ready for Human Review");
    parts.push("");
    parts.push(
      "These findings could not be auto-confirmed by the verify loop and need manual triage. Evidence is preserved on disk.",
    );
    parts.push("");
    for (const esc of escalations) {
      parts.push(renderEscalation(esc));
      parts.push("");
    }
  }

  return parts.join("\n").replace(/\n+$/, "\n");
}

// ---------------------------------------------------------------------------
// Persistence + stage driver
// ---------------------------------------------------------------------------

export function reportPath(workdir: string): string {
  return path.join(workdir, "report.md");
}

/**
 * Generate `report.md` from the confirmed findings + escalations on disk and
 * write it. Returns the rendered markdown. Safe to call at any point (including
 * a budget-exhausted partial halt) — it reports whatever is confirmed to date.
 */
export async function writeReport(
  workdir: string,
  state: State,
): Promise<string> {
  const confirmed = await readConfirmedFindings(workdir);
  const escalations = await readEscalations(workdir);
  const markdown = buildReport(state, confirmed, escalations);
  await fs.mkdir(workdir, { recursive: true });
  await fs.writeFile(reportPath(workdir), markdown, "utf8");
  return markdown;
}
