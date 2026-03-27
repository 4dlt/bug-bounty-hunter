---
name: ImpactValidator
description: Validates pentest findings for real exploitability, chains vulnerabilities for maximum impact, classifies severity P1-P5, filters bounty-worthiness, and generates HackerOne/Bugcrowd-formatted reports. Use after attack agents complete testing to validate and report findings. USE WHEN validate findings, chain vulnerabilities, classify severity, bounty report, impact validation, exploit verification, PoC verification, bug bounty report, finding triage, vulnerability chain, severity classification, report generation, bounty filter, finding validation, pentest reporting.
---

## Customization

**Before executing, check for user customizations at:**
`~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/ImpactValidator/`

If this directory exists, load and apply any PREFERENCES.md, configurations, or resources found there. These override default behavior. If the directory does not exist, proceed with skill defaults.

# ImpactValidator

Every finding from attack agents passes through this validator before reporting. The validator answers three questions for each finding, and drops anything that fails:

### The Three Questions

1. **Is this actually exploitable?** — Not theoretical, not a false positive. Can you reproduce it right now, independently, with a working PoC?
2. **Can this be chained with other findings for higher impact?** — A P4 alone might be noise; chained to P2 it becomes a submission.
3. **Is this worth submitting to a bug bounty program?** — Does it pass the bounty-worthiness filter, is it in scope, and will a triager accept it?

If any answer is NO and cannot be remedied, the finding is dropped.

## Workflow

### Step 1: Load Findings

Read all findings from the shared state file:
```
/tmp/pentest-<id>/state.json
```

Expected structure per finding:
```json
{
  "id": "FINDING-001",
  "type": "sqli",
  "endpoint": "POST /api/users/search",
  "parameter": "query",
  "description": "SQL injection in search parameter",
  "evidence": {
    "request": "curl ...",
    "response": "...",
    "payload": "' OR 1=1--"
  },
  "agent": "sqli-agent",
  "timestamp": "2026-03-27T20:00:00Z"
}
```

### Step 2: Reproduce Each Finding Independently

For EVERY finding:

1. **Reconstruct the exploit** from the finding's evidence — build fresh curl commands or dev-browser scripts
2. **Execute the exploit** against the target — do NOT rely on the attack agent's evidence alone
3. **Run it 3 times minimum** — ensure consistency (not a one-time fluke, race condition artifact, or cached response)
4. **Capture fresh evidence** — new request/response pairs, timestamps, response body diffs

If reproduction fails after 3 attempts with variations:
- Try the original payload exactly as the agent used it
- Try URL-encoded, double-encoded, and case variations
- Try from a different session/IP if possible
- If still fails → **DROP the finding** with reason "reproduction_failed"

### Step 3: Verify Real Impact

For each successfully reproduced finding, verify the impact is REAL:

| Vuln Type | What "Real Impact" Means | How to Verify |
|-----------|-------------------------|---------------|
| SQLi | Data actually extracted from database | Show extracted rows/columns in response |
| XSS | Script actually executes in victim context | dev-browser confirms JS execution, cookie access |
| SSRF | Internal resource actually reached | Response differs from normal, contains internal data |
| IDOR | Other user's data actually returned | Compare response with authorized vs unauthorized request |
| RCE | Command actually executed on server | Show command output (whoami, id, hostname) |
| Auth Bypass | Actually accessed protected resource | Show admin panel content, restricted API response |
| CSRF | State actually changed without consent | Show before/after state (email changed, settings modified) |
| File Upload | Malicious file actually accessible/executable | Access uploaded file URL, confirm execution |

If impact cannot be demonstrated concretely → **DROP the finding** with reason "impact_not_demonstrated"

### Step 4: Chain Vulnerabilities

Cross-reference all validated findings against chain patterns (see `ChainPatterns.md`):

1. Load all validated findings into a working set
2. For each finding, check if it can serve as a LINK in a known chain
3. For each potential chain:
   a. Verify preconditions are met (e.g., "cookies without HttpOnly" for XSS→ATO)
   b. Walk through the chain steps with actual PoCs
   c. Verify the COMBINED impact (not just individual links)
4. If a chain is confirmed:
   - Mark individual findings as "chained" (do not submit separately)
   - Create a new CHAIN finding with combined severity
   - The chain's severity is based on the FINAL impact, not the weakest link

### Step 5: Classify Severity

Apply the severity matrix (see `SeverityMatrix.md`) to each finding:

1. Match the finding type + demonstrated impact to the matrix
2. For chains: classify based on the chain's terminal impact
3. Verify the severity is justified — a P1 requires P1-level demonstrated impact
4. Estimate bounty payout based on program history and severity class
5. Add CVSS score and CWE classification

### Step 6: Filter and Report

Apply the bounty-worthiness filter (see `BountyFilter.md`):

1. Check each finding against the drop list
2. Check the program's scope.yaml for excluded findings
3. Check the program's scope.yaml for excluded domains/endpoints
4. For surviving findings: generate reports using the template (see `ReportTemplate.md`)
5. Prioritize submission order: P1 first, then P2, etc.

## Validation Checklist

For EVERY finding, verify ALL of the following before reporting:

- [ ] **Reproducible** — Can reproduce independently (not a one-time fluke)
- [ ] **Impact demonstrated** — Not just "vulnerable to X" — show the data/action
- [ ] **PoC consistent** — Works 3 out of 3 runs minimum
- [ ] **In scope** — Check scope.yaml domains, endpoints, vulnerability types
- [ ] **Not excluded** — Finding type not in program's excluded list
- [ ] **Severity justified** — Classification matches actual demonstrated impact
- [ ] **Steps clear** — A triager with no context can reproduce from the report
- [ ] **Business impact stated** — Concrete: N users affected, data types exposed, financial risk
- [ ] **Not a duplicate** — Check program's disclosed/resolved reports if accessible
- [ ] **Chain checked** — Attempted chaining with all other findings before finalizing

## Key Rules

1. **NEVER report a finding you haven't verified yourself** — reproduce the exploit independently
2. **A finding without a working PoC is NOT a finding** — drop it immediately
3. **Always attempt chaining before finalizing severity** — a P4 chained to P2 is worth more
4. **If a P4 chains to P2, report the CHAIN as P2** — not the individual findings
5. **Drop anything the program explicitly excludes** — check scope.yaml excluded_findings
6. **Estimate bounty payout** based on program history and severity class
7. **Write reports in business impact terms** — not just technical jargon
8. **One vulnerability per report** — unless it is a chain (report the full chain)
9. **Do not oversell severity** — triagers respect accuracy over hype
10. **Include remediation** — specific technical fix, not "validate input"

## Integration

This module is called by the BugBountyHunter orchestrator in **Phase 3: Validation & Reporting**.

**Input:** findings array from `/tmp/pentest-<id>/state.json`
**Output:** validated findings with:
- Fresh PoC evidence (reproduced independently)
- Severity classification (P1-P5 with CVSS and CWE)
- Chain analysis (individual findings linked into chains where applicable)
- Bounty-worthiness assessment (pass/fail with reason)
- Formatted reports (HackerOne/Bugcrowd ready)
- Estimated bounty payout per finding

**State file update:** Write validated findings back to state.json under `validated_findings` key:
```json
{
  "validated_findings": [
    {
      "id": "VALIDATED-001",
      "original_ids": ["FINDING-001"],
      "type": "sqli_data_extraction",
      "severity": "P1",
      "cvss": 9.8,
      "cwe": "CWE-89",
      "chain": null,
      "bounty_estimate": "$5000-$15000",
      "report": "...",
      "poc": { "curl": "...", "response": "..." },
      "status": "ready_to_submit"
    }
  ],
  "dropped_findings": [
    {
      "id": "FINDING-003",
      "reason": "reproduction_failed",
      "attempts": 3,
      "notes": "Endpoint returned 404 on all attempts — may have been patched"
    }
  ]
}
```

## Reference Files

| File | Purpose |
|------|---------|
| `ChainPatterns.md` | 10 known vulnerability chains with step-by-step exploitation |
| `SeverityMatrix.md` | P1-P5 classification with dollar ranges and evidence requirements |
| `BountyFilter.md` | Findings to DROP before reporting (with exceptions) |
| `ReportTemplate.md` | HackerOne/Bugcrowd report template optimized for payouts |
