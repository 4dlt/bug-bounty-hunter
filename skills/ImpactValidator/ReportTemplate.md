# Bug Bounty Report Template

Optimized for HackerOne and Bugcrowd submissions. This template maximizes clarity for triagers and demonstrates real impact -- the two factors that most influence acceptance rates and bounty amounts.

---

## Template

```
# [Vulnerability Type] in [Component/Endpoint] allows [Specific Impact]

**Severity:** [P1-P4] | **CVSS:** [X.X] | **CWE:** [CWE-XXX]
**Bounty Estimate:** $X,XXX -- $XX,XXX
**Affected Asset:** [URL/endpoint/feature in scope]

## Summary

[2-3 sentences maximum. What the vulnerability is, exactly where it exists (endpoint, parameter, feature), and what an attacker can achieve. Be specific -- "An IDOR vulnerability in the GET /api/v2/users/{id} endpoint allows any authenticated user to retrieve the full profile (including email, phone, address, and payment method) of any other user by changing the id parameter." NOT "There is a vulnerability in the user API."]

## Steps to Reproduce

1. [Create/use a test account at https://target.com/signup]
2. [Navigate to / send request to EXACT_URL]
3. [Perform EXACT_ACTION with EXACT_PARAMETERS]
4. [Observe EXACT_RESULT]
5. [Continue with additional steps if needed]

**Note:** Every step must be reproducible by a triager who has never seen your report before. Include exact URLs, parameters, headers, and expected responses. Do not assume any context.

### For API-Based Findings

Include complete curl commands:

curl -s -X [METHOD] 'https://target.com/api/endpoint' \
  -H 'Authorization: Bearer [TOKEN]' \
  -H 'Content-Type: application/json' \
  -d '{"parameter": "value"}'

Expected response:
{
  "sensitive_field": "exposed_value",
  "email": "victim@example.com"
}

### For Browser-Based Findings

Include dev-browser or browser console scripts:

// Paste this into browser console while logged in as attacker
fetch('/api/users/VICTIM_ID', {
  headers: {'Authorization': 'Bearer ATTACKER_TOKEN'}
})
.then(r => r.json())
.then(d => console.log(d));

## Proof of Concept

### Before (Normal Behavior)
[Show what happens with a legitimate request -- the baseline.]

Example:
Request: GET /api/users/1001 (my own ID)
Response: {"id": 1001, "email": "me@test.com", "role": "user"}

### After (Exploited Behavior)
[Show what happens with the exploit -- the deviation from expected behavior.]

Example:
Request: GET /api/users/1 (admin's ID, using my token)
Response: {"id": 1, "email": "admin@target.com", "role": "admin", "api_key": "sk_live_xxx"}

### Evidence
[Include response bodies, screenshots for browser findings, or any other concrete proof. Redact only truly sensitive data (full credit card numbers, SSNs) but leave enough to prove the issue (last 4 digits, email format).]

## Impact

[Business impact in concrete, quantifiable terms. Triagers and security teams care about business risk, not just technical severity.]

Structure your impact statement with:

- **Who is affected:** [e.g., "All 2.3M registered users" or "Any user with a public profile" or "Admin accounts only"]
- **What data is exposed:** [e.g., "Full PII including email, phone number, billing address, and last 4 digits of payment method"]
- **What actions an attacker can perform:** [e.g., "Read any user's profile, modify their email address, and trigger password reset to attacker-controlled email"]
- **Scale of exploitation:** [e.g., "Automated enumeration possible -- tested extraction of 100 profiles in under 60 seconds"]
- **Financial risk:** [e.g., "PII breach affecting N users triggers mandatory breach notification under GDPR Article 33, potential fine up to 4% of annual revenue"]
- **Regulatory implications:** [e.g., "GDPR, CCPA, PCI-DSS, HIPAA -- specify which apply based on data types exposed"]

### Impact Example (GOOD):
"Any authenticated user can access the full profile of any other user, including email, phone number, physical address, and the last 4 digits of their payment method. With sequential user IDs (1 to ~2.3M), an attacker can exfiltrate the entire user database in approximately 6 hours at 100 requests/second. This constitutes a mass PII breach affecting all registered users, triggering GDPR Article 33 breach notification requirements and potential CCPA penalties."

### Impact Example (BAD):
"User data can be accessed by unauthorized users, which is a security risk."

## Remediation

[Specific, implementable technical fix. Not generic advice like "validate input" or "implement proper access controls."]

### Remediation Example (GOOD):
"Add an authorization check in the UserController.getProfile() method (likely at /src/controllers/UserController.js) to verify that request.user.id matches the requested user ID, or that the requesting user has an admin role. Example:

if (req.user.id !== requestedUserId && req.user.role !== 'admin') {
  return res.status(403).json({ error: 'Forbidden' });
}

Additionally, replace sequential integer IDs with UUIDs in the public API to prevent enumeration."

### Remediation Example (BAD):
"Fix the authorization issue. Implement proper access controls."
```

---

## Report Writing Tips

### Title

Your title is the first thing the triager reads. It determines whether they take your report seriously.

**Formula:** `[Vulnerability Type] in [Specific Component] allows [Concrete Impact]`

**GOOD titles:**
- "IDOR in /api/v2/users/{id} allows reading any user's PII including payment data"
- "Stored XSS in comment field chains to account takeover via session theft"
- "SSRF in /api/webhooks/test allows reading AWS IAM credentials from IMDS"
- "Race condition in /api/coupons/redeem allows unlimited coupon usage"

**BAD titles:**
- "IDOR vulnerability" (too vague)
- "Security issue in user API" (says nothing)
- "Critical vulnerability found!!!" (no information, looks spammy)
- "Multiple vulnerabilities in target.com" (submit one per report)

### Severity

- **Be honest.** Triagers respect accurate self-assessment far more than inflated severity. If your XSS is reflected and requires user interaction, call it P4 -- do not call it P1.
- **Classify based on demonstrated impact.** If you found SQL injection but could only extract the database version (not user data), that is P3, not P1. If you extracted the users table with passwords, that is P1.
- **Do not argue with triager downgrades** based on "but it COULD be worse." The triager assesses based on what you demonstrated.

### PoC Quality

- **Working curl commands** that the triager can copy-paste and run
- **Screenshots** for browser-based findings (with timestamps visible)
- **Before/after comparison** showing normal vs. exploited behavior
- **Response bodies** (not just status codes) proving data exposure
- **Multiple examples** for IDOR (show 2-3 different users, not just one)

### Common Mistakes That Get Reports Closed

1. **No PoC** -- "I believe this is vulnerable" without proof
2. **Scanner output** -- pasting Burp/ZAP/Nuclei output without verification
3. **Multiple vulns in one report** -- submit one finding per report (chains are one finding)
4. **Out of scope** -- not reading the program rules before submitting
5. **Known issues** -- not checking disclosed/resolved reports for duplicates
6. **Inflated severity** -- calling everything Critical/P1
7. **Generic impact** -- "this is a security risk" without specifics
8. **Missing steps** -- triager cannot reproduce because steps skip context
9. **Submitting too fast** -- racing to be first instead of writing a quality report
10. **Arguing with triagers** -- professional disagreement is fine, but hostility gets you nowhere

### Submission Timing

- **Do not rush.** A well-written report submitted an hour later beats a sloppy report submitted immediately. Triagers prioritize quality.
- **Check for duplicates first.** Look at the program's disclosed reports. If someone reported the same endpoint/parameter, your report will be marked duplicate.
- **Submit chains together.** If you have XSS + CSRF + ATO, submit ONE report showing the full chain. Do not submit three separate reports.

---

## Template Variants

### For Vulnerability Chains

When reporting a chain, structure the report to show each link:

```
# [Chain Summary: Entry Vuln] chains to [Terminal Impact]

## Chain Overview
- Link 1: [First vulnerability] -- [what it enables]
- Link 2: [Second vulnerability/action] -- [what it enables]
- Link 3: [Final impact] -- [what the attacker achieves]

## Steps to Reproduce
[Walk through the ENTIRE chain end-to-end, showing each link with evidence]

## Impact
[Report the TERMINAL impact of the chain, not the individual links]
```

### For Race Conditions

```
## Steps to Reproduce
1. [Setup: create account, add balance/coupon, etc.]
2. [Prepare N parallel requests (include exact curl/script)]
3. [Send all requests simultaneously]
4. [Verify: check that the operation executed N times]

## Financial Impact Calculation
- Operation value: $X per execution
- Successful parallel executions: N
- Total impact per attack: $X * N = $Y
- Repeatable: [Yes/No -- can the attacker do this repeatedly?]
```

### For Authentication Bypass

```
## Steps to Reproduce
1. [Show normal authentication flow (legitimate login)]
2. [Show the bypass technique]
3. [Demonstrate access to protected resource without valid credentials]
4. [Show that the bypassed session has full permissions]

## Affected Endpoints
[List ALL endpoints accessible via the bypassed authentication]
```

---

## CVSS Calculator Quick Reference

For consistent CVSS 3.1 scoring in your reports:

| Factor | Common Values |
|--------|--------------|
| Attack Vector | Network (most web vulns), Adjacent (local network), Physical |
| Attack Complexity | Low (straightforward exploit), High (requires specific conditions) |
| Privileges Required | None (unauthenticated), Low (regular user), High (admin) |
| User Interaction | None (no victim action), Required (victim must click/visit) |
| Scope | Unchanged (same component), Changed (affects other components) |
| Confidentiality | None, Low (limited data), High (all data) |
| Integrity | None, Low (limited modification), High (full modification) |
| Availability | None, Low (degraded), High (full DoS) |

Use https://www.first.org/cvss/calculator/3.1 for exact scores.
