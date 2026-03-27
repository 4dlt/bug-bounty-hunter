# WebAssessment Upgrades for BugBountyHunter

These are additions made to the `Security/WebAssessment/SKILL.md` skill file to support the BugBountyHunter system. If you have the `ai-security-arsenal` installed, apply these sections to your existing `Security/WebAssessment/SKILL.md`.

## What Was Changed

1. **Added autonomous authentication directive** -- agents handle login, token refresh, and CSRF extraction without stopping
2. **Added 9-category business logic testing checklist** from AllAboutBugBounty research
3. **Added OWASP WSTG v4.2 test case taxonomy** reference for systematic coverage
4. **Replaced Playwright MCP references with dev-browser CLI** patterns

## Sections to Add

### 1. Autonomous Behaviors Directive (add near the top of SKILL.md)

```markdown
## Autonomous Behaviors (MANDATORY -- ZERO EXCEPTIONS)

When credentials are provided for a target, the agent MUST handle authentication autonomously:

### What You MUST Do Yourself
1. Navigate to the login page using dev-browser
2. Fill credentials and submit the login form
3. Extract all auth tokens (JWT from localStorage, session cookies, CSRF tokens from meta tags or hidden fields)
4. Store tokens for use in subsequent requests
5. Auto-refresh tokens when they expire (detect 401 response --> re-authenticate)
6. Extract new CSRF tokens before each state-changing request (read from page source)
7. Follow redirects through SSO/OAuth flows
8. Handle MFA if OTP/code is provided by the user

### What You MUST NOT Do
- Stop to ask the user for tokens when credentials are provided
- Stop to ask about CSRF tokens -- extract them from the page
- Stop to ask about session management -- handle it yourself
- Report "I need a token" or "I need to be authenticated" -- DO IT YOURSELF
- Ask the user to "provide the session cookie" -- get it from the browser
- Pause for any auth-related task you can complete with the provided credentials

### dev-browser Authentication Pattern
```bash
dev-browser --ignore-https-errors <<'EOF'
const page = await browser.getPage("auth");
await page.goto("LOGIN_URL");
await page.fill("input[name='username'], input[name='email'], #username, #email", "USERNAME");
await page.fill("input[name='password'], #password", "PASSWORD");
await page.click("button[type='submit'], input[type='submit']");
await page.waitForLoadState("networkidle");

// Extract all auth artifacts
const cookies = await page.context().cookies();
const jwt = await page.evaluate(() => {
  for (const [k, v] of Object.entries(localStorage)) {
    if (v && v.startsWith('eyJ')) return { key: k, token: v };
  }
  return null;
});
const csrf = await page.evaluate(() => {
  const meta = document.querySelector('meta[name="csrf-token"], meta[name="_csrf"]');
  const input = document.querySelector('input[name="_csrf"], input[name="csrf_token"]');
  return meta?.content || input?.value || null;
});

console.log(JSON.stringify({ cookies, jwt, csrf }, null, 2));
EOF
```
```

### 2. Business Logic Testing Checklist (add as new section)

```markdown
## Business Logic Testing Checklist

Systematically test 9 business logic categories. These are often the highest-paying findings because they require understanding the application, not just running tools.

### 1. Reviews / Ratings
- Submit reviews for products/services you haven't purchased
- Manipulate rating values beyond the expected range (set rating to 0, -1, 999)
- Bypass "one review per purchase" limits via race condition or parameter tampering
- Submit reviews as another user (IDOR on reviewer_id)
- Modify existing reviews of other users

### 2. Coupons / Discounts
- Apply the same coupon multiple times (race condition -- send parallel requests)
- Use expired coupon codes (remove/modify expiry check in request)
- Stack incompatible discounts (apply multiple coupon codes in sequence)
- Modify discount percentage in the request body
- Apply coupons to items excluded from promotions
- Predict coupon codes (sequential patterns, weak generation)

### 3. Delivery Charges
- Manipulate delivery fee parameters in the checkout request
- Change delivery address after payment calculation (switch to expensive address)
- Bypass minimum order requirements for free delivery
- Set negative delivery charges
- Use address injection to get different pricing

### 4. Currency Confusion
- Change currency code while keeping the same price value (pay 100 JPY instead of 100 USD)
- Exploit rounding differences between currencies during conversion
- Switch currency between cart and checkout
- Use unsupported currency codes to trigger fallback behavior

### 5. Premium Features
- Access premium API endpoints without an active subscription
- Manipulate subscription tier parameter in requests (`plan=free` --> `plan=enterprise`)
- Bypass trial expiration by manipulating client-side timestamps
- Downgrade and immediately upgrade to reset trial period
- Access premium content via direct URL if only the UI enforces restrictions

### 6. Refunds
- Request refund while retaining access to the service/product
- Double refund via race condition (send two refund requests simultaneously)
- Manipulate refund amount in the request
- Refund to a different payment method than the original
- Partial refund manipulation (refund more than the partial amount)

### 7. Cart / Checkout
- Negative quantity to generate credit
- Price tampering: modify price field in the cart or checkout request
- Add items after payment amount has been calculated
- Remove items after discount has been applied (keep discount on remaining items)
- Change product variant (size/color) to one with a different price after adding to cart
- Modify quantity to 0 but still process the order

### 8. Comments / Posts
- Bypass character/word limits by manipulating the request body
- Inject content into notification emails (XSS in comment that appears in email)
- Manipulate timestamps to backdate or future-date posts
- Post as another user by modifying author_id parameter
- Bypass approval/moderation queue

### 9. Parameter Tampering
- Change `user_id` to access/modify other users' data
- Modify `role` or `is_admin` parameters in profile update requests
- Tamper with `plan_type`, `subscription_tier`, or `account_level`
- Modify `price`, `amount`, `quantity` in transaction requests
- Change `status` fields (order status, account status, verification status)
```

### 3. OWASP WSTG v4.2 Taxonomy Reference (add as new section)

```markdown
## OWASP WSTG v4.2 Test Case Reference

Use this taxonomy to ensure systematic coverage. Walk through each category:

| ID | Category | Key Tests |
|----|----------|-----------|
| **WSTG-INFO** | Information Gathering | Fingerprint web server, review webpage content for info leakage, identify entry points, map execution paths |
| **WSTG-CONF** | Configuration Management | Test HTTP methods, test file extensions handling, review old backup files, enumerate admin interfaces, test HTTP strict transport security |
| **WSTG-IDNT** | Identity Management | Test role definitions, test user registration process, test account provisioning, test account enumeration |
| **WSTG-ATHN** | Authentication | Test for credentials over HTTP, test default credentials, test weak lockout mechanism, test bypass authentication, test remember password, test browser cache weaknesses, test weak password policy, test weak security questions, test password change/reset |
| **WSTG-ATHZ** | Authorization | Test directory traversal/file include, test bypass authorization schema, test privilege escalation, test IDOR |
| **WSTG-SESS** | Session Management | Test session management schema, test cookies attributes, test session fixation, test exposed session variables, test CSRF, test logout functionality, test session timeout, test session puzzling |
| **WSTG-INPV** | Input Validation | Test reflected XSS, test stored XSS, test HTTP verb tampering, test HTTP parameter pollution, test SQL injection, test LDAP injection, test XML injection, test SSI injection, test XPath injection, test IMAP/SMTP injection, test code injection, test command injection, test format string, test incubated vulnerability, test HTTP splitting/smuggling, test SSTI, test SSRF |
| **WSTG-ERRH** | Error Handling | Test improper error handling, test stack traces |
| **WSTG-CRYP** | Cryptography | Test weak TLS/SSL, test padding oracle, test sensitive info sent unencrypted, test weak encryption |
| **WSTG-BUSL** | Business Logic | Test data validation, test ability to forge requests, test integrity checks, test process timing, test number of function use limits, test circumvention of work flows, test defenses against application misuse, test upload of unexpected file types, test upload of malicious files |
| **WSTG-CLNT** | Client-Side | Test DOM-based XSS, test JavaScript execution, test HTML injection, test client-side URL redirect, test CSS injection, test client-side resource manipulation, test CORS, test cross-site flashing, test clickjacking, test WebSocket, test web messaging, test browser storage, test SSJI |
```

### 4. dev-browser Migration (replace Playwright MCP references)

Replace all Playwright MCP tool calls throughout the skill with dev-browser patterns:

```markdown
# Old (Playwright MCP):
mcp__playwright__browser_navigate(url="https://target.com")
mcp__playwright__browser_snapshot()

# New (dev-browser):
dev-browser --ignore-https-errors <<'EOF'
const page = await browser.getPage("assessment");
await page.goto("https://target.com");
const snapshot = await page.snapshotForAI();
console.log(snapshot.full);
EOF
```
