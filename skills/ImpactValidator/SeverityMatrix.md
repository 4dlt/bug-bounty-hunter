# Severity Classification Matrix

Classify validated findings into P1-P5 based on demonstrated impact. The key word is **demonstrated** — classification is based on what you proved, not what is theoretically possible.

**Golden rule:** If you cannot demonstrate the impact described in a severity tier, you cannot classify the finding at that tier. A "potential RCE" without executed commands is not P1 — it's P3 at best.

---

## P1 — Critical | $10,000 - $250,000+

**Impact:** Direct compromise of user accounts, systems, or sensitive data at scale. Immediate threat requiring emergency response.

**CVSS Range:** 9.0 - 10.0

### Vulnerability Types

| Finding | Required Evidence | Typical Bounty |
|---------|------------------|----------------|
| **Remote Code Execution** | Executed command output (whoami, id, hostname, cat /etc/passwd) | $20K-$250K |
| **SQL Injection with data extraction** | Extracted sensitive data (user table, credentials, PII) from database | $10K-$100K |
| **Full Account Takeover** | Logged in as another user, accessed their data, performed actions | $10K-$75K |
| **Authentication Bypass to admin** | Accessed admin panel, performed admin actions without credentials | $15K-$100K |
| **SSRF with cloud credential theft** | Extracted AWS/GCP/Azure credentials, accessed cloud resources | $10K-$50K |
| **Payment/financial manipulation** | Demonstrated monetary gain or bypass of payment (with exact dollar amount) | $10K-$100K |
| **Mass PII breach (>1000 records)** | Extracted >1000 records of sensitive PII (SSN, financial, health) | $15K-$100K |
| **Privilege escalation to admin** | Regular user performing admin-only actions with evidence | $10K-$50K |
| **JWT forgery with admin access** | Forged admin JWT accepted by server, admin endpoints accessible | $10K-$50K |
| **Chained attack leading to ATO** | Full chain demonstrated end-to-end with evidence at each step | $10K-$75K |

### Evidence Requirements for P1
- Working PoC that executes in 3/3 attempts
- Concrete output showing the impact (extracted data, executed commands, accessed resources)
- Before/after state showing the compromise
- If chain: evidence at each link, not just the terminal step

---

## P2 — High | $2,000 - $50,000

**Impact:** Significant data exposure or unauthorized actions on individual accounts. Requires remediation but not emergency response.

**CVSS Range:** 7.0 - 8.9

### Vulnerability Types

| Finding | Required Evidence | Typical Bounty |
|---------|------------------|----------------|
| **IDOR exposing PII** | Accessed specific other user's PII (email, phone, address, payment info) | $2K-$20K |
| **Privilege escalation (user→moderator)** | Performed higher-privilege actions, not admin but above regular user | $3K-$25K |
| **Stored XSS with demonstrated impact** | Executed XSS that performs an action (cookie theft with HttpOnly, CSRF, data exfil) | $2K-$15K |
| **Significant credential/key exposure** | Found credentials/API keys AND demonstrated what they access | $2K-$20K |
| **CSRF on critical actions** | Changed victim's password, email, or payment method via CSRF | $2K-$15K |
| **Blind SSRF with confirmed internal access** | Response differences proving internal network reach, but no credential extraction | $2K-$10K |
| **SQL Injection (blind/time-based)** | Confirmed SQLi with data extraction, but limited scope or non-sensitive tables | $3K-$20K |
| **Cross-tenant data access** | Accessed another tenant/organization's data in multi-tenant app | $5K-$50K |
| **File upload leading to stored XSS** | Uploaded file serves XSS payload to other users | $2K-$10K |
| **OAuth misconfiguration** | Token leakage or scope escalation without full ATO | $3K-$20K |

### Evidence Requirements for P2
- Working PoC reproducible 3/3 times
- Specific data or action demonstrated (not "could potentially access")
- Clear identification of affected data types and approximate scope
- If IDOR: show at least 2-3 different users' data accessed

---

## P3 — Medium | $500 - $5,000

**Impact:** Moderate risk requiring remediation. Exploitable but with limited scope, requiring user interaction, or with partial impact.

**CVSS Range:** 4.0 - 6.9

### Vulnerability Types

| Finding | Required Evidence | Typical Bounty |
|---------|------------------|----------------|
| **Stored XSS without ATO chain** | XSS fires on authenticated page, but HttpOnly + CSP limits impact | $500-$3K |
| **CSRF on sensitive non-critical actions** | Changed profile settings, preferences, non-security settings | $500-$2K |
| **Credential/token disclosure without demonstrated access** | Found leaked key but could not demonstrate what it accesses (expired, limited) | $500-$3K |
| **Blind SSRF without confirmed internal access** | DNS callback confirms SSRF exists but no internal data extracted | $500-$2K |
| **Open redirect without chain** | Confirmed redirect to arbitrary domain but no OAuth/ATO chain | $500-$2K |
| **Subdomain takeover (confirmed)** | Claimed the subdomain, served content, but no cookie/CORS/OAuth abuse | $1K-$5K |
| **IDOR on non-sensitive data** | Accessed other users' public profiles, non-PII metadata | $500-$2K |
| **Broken access control (minor)** | Accessed resources above your role but no sensitive data or admin functions | $500-$3K |
| **Server-Side Template Injection (limited)** | SSTI confirmed but sandboxed — no RCE, limited to info disclosure | $1K-$5K |
| **GraphQL introspection exposing internal schema** | Full schema disclosed including internal types, mutations, admin endpoints | $500-$3K |

### Evidence Requirements for P3
- Working PoC reproducible 3/3 times
- Impact demonstrated but limited in scope or severity
- Clear description of what IS and IS NOT possible with this finding

---

## P4 — Low | $100 - $1,000

**Impact:** Minor security concern. Requires specific conditions, significant user interaction, or has minimal real-world impact.

**CVSS Range:** 0.1 - 3.9

### Vulnerability Types

| Finding | Required Evidence | Typical Bounty |
|---------|------------------|----------------|
| **Reflected XSS** | XSS fires but requires victim to click attacker-crafted URL | $100-$500 |
| **DOM-based XSS** | Client-side XSS via DOM manipulation, requires specific user action | $100-$500 |
| **CSRF on non-sensitive actions** | Changed non-security UI settings (language, theme, notification prefs) | $100-$300 |
| **Verbose error messages** | Stack traces, internal paths, technology versions exposed | $100-$500 |
| **Open redirect (no chain, basic)** | Simple redirect, no sensitive context, no OAuth | $100-$300 |
| **Information disclosure (non-sensitive)** | Internal IP addresses, software versions, debug info (no credentials) | $100-$500 |
| **Missing security headers with minor impact** | Missing headers AND demonstrated minor exploitation (e.g., clickjacking on settings page) | $100-$300 |
| **CORS misconfiguration (limited)** | Overly permissive CORS but only on endpoints returning non-sensitive data | $100-$500 |
| **Insecure direct object reference (trivial)** | IDOR but only on truly non-sensitive data (public content, own data in different format) | $100-$300 |
| **Path traversal (limited)** | File read confirmed but only non-sensitive files (public assets, default configs) | $200-$1K |

### Evidence Requirements for P4
- Working PoC demonstrating the issue
- Honest assessment that impact is limited
- Explanation of what conditions are required for exploitation
- Any potential for chaining (if yes, attempt chain before submitting as P4)

---

## P5 — Informational | $0 - $100

**Impact:** Best practice violation or theoretical concern. Most programs do not pay for P5 findings. Only submit if the program explicitly accepts informational findings.

**CVSS Range:** 0.0 (or N/A)

### Vulnerability Types

| Finding | Why P5 | Submit? |
|---------|--------|---------|
| **Missing security headers (no exploitation)** | CSP, X-Frame-Options, HSTS missing but no demonstrated attack | Usually no |
| **Theoretical attacks without PoC** | "This could be vulnerable to X" without proof | Never |
| **Self-XSS** | XSS only affects the user who inputs it (no chain to other users) | No (unless chained) |
| **Clickjacking on non-sensitive pages** | Framing login/homepage/marketing pages with no state change | Usually no |
| **Software version disclosure** | Server header reveals Apache 2.4.x, nginx 1.x — no known CVE for version | Usually no |
| **Best practices violations** | Cookie without Secure flag on HTTPS-only site, no rate limiting on non-sensitive endpoints | No |
| **SPF/DKIM/DMARC issues** | Email security misconfiguration without demonstrated email spoofing | Usually no |
| **Mixed content warnings** | HTTP resources on HTTPS page — browsers block by default | No |
| **Username enumeration** | Registration/login reveals valid usernames — many programs exclude this | Depends on program |
| **Lack of rate limiting (non-auth)** | No rate limit on search, public API — not on login/auth | No |

### Evidence Requirements for P5
- If submitting: must still have a PoC, just showing the observation
- Be explicit that this is informational
- Do NOT attempt to inflate P5 to P4 — triagers will downgrade and note it

---

## Severity Decision Tree

```
START
  │
  ├─ Can you execute code on the server?
  │   └─ YES → P1 (RCE)
  │
  ├─ Can you take over any user's account?
  │   └─ YES → P1 (ATO)
  │
  ├─ Can you access cloud credentials or admin systems?
  │   └─ YES → P1
  │
  ├─ Can you extract mass PII (>1000 records)?
  │   └─ YES → P1
  │
  ├─ Can you manipulate payments/finances?
  │   └─ YES → P1 (with demonstrated $ impact)
  │
  ├─ Can you access other users' PII?
  │   └─ YES → P2 (IDOR + PII)
  │
  ├─ Can you escalate privileges (not to admin)?
  │   └─ YES → P2
  │
  ├─ Can you perform critical actions as another user?
  │   └─ YES → P2 (CSRF on critical actions)
  │
  ├─ Does XSS have demonstrated impact beyond alert(1)?
  │   ├─ Stored + cookie theft or action execution → P2
  │   ├─ Stored + no further impact → P3
  │   └─ Reflected → P4
  │
  ├─ Is it information disclosure?
  │   ├─ Credentials + demonstrated access → P2
  │   ├─ Credentials without demonstrated access → P3
  │   └─ Non-sensitive internal info → P4
  │
  ├─ Does it require significant user interaction?
  │   └─ YES → probably P4
  │
  └─ Is it theoretical or best-practice only?
      └─ YES → P5 (probably don't submit)
```

---

## CVSS Quick Reference

Use CVSS 3.1 for scoring. Common scores by finding type:

| Finding | Attack Vector | Attack Complexity | Privileges | User Interaction | CVSS |
|---------|:---:|:---:|:---:|:---:|:---:|
| RCE (unauthenticated) | Network | Low | None | None | 9.8 |
| SQLi (data extraction) | Network | Low | None | None | 9.8 |
| ATO (stored XSS chain) | Network | Low | Low | Required | 8.1 |
| IDOR (PII exposure) | Network | Low | Low | None | 6.5 |
| Stored XSS (no chain) | Network | Low | Low | Required | 5.4 |
| CSRF (password change) | Network | Low | None | Required | 8.1 |
| Reflected XSS | Network | Low | None | Required | 6.1 |
| Open redirect | Network | Low | None | Required | 4.7 |
| Info disclosure | Network | Low | None | None | 5.3 |
| Missing headers | Network | Low | None | None | 0.0 |

---

## CWE Quick Reference

Common CWE IDs for report tagging:

| Vulnerability | CWE |
|---------------|-----|
| SQL Injection | CWE-89 |
| XSS (Stored) | CWE-79 |
| XSS (Reflected) | CWE-79 |
| SSRF | CWE-918 |
| IDOR | CWE-639 |
| CSRF | CWE-352 |
| RCE (Command Injection) | CWE-78 |
| RCE (Code Injection) | CWE-94 |
| Path Traversal | CWE-22 |
| Auth Bypass | CWE-287 |
| Privilege Escalation | CWE-269 |
| Open Redirect | CWE-601 |
| Information Disclosure | CWE-200 |
| Race Condition | CWE-362 |
| JWT Issues | CWE-347 |
| File Upload | CWE-434 |
| SSTI | CWE-1336 |
| Subdomain Takeover | CWE-284 |
| Broken Access Control | CWE-284 |
| Insecure Deserialization | CWE-502 |
