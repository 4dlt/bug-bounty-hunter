# Bounty-Worthiness Filter

Findings to DROP before submitting to bug bounty programs. For each: what it is, why programs reject it, and the ONE exception where it might be accepted.

**Core principle:** Submitting findings that programs routinely reject wastes triager time, damages your reputation, and can get you flagged as a noise reporter. Filter aggressively -- only submit findings with real, demonstrated impact.

---

## 1. Self-XSS

**What:** XSS that only affects the user who inputs it (e.g., XSS in "My Profile Name" that only renders on your own profile page).

**Why rejected:** No impact on other users. The attacker can only attack themselves. Programs consider this a non-vulnerability because it requires the victim to inject the payload into their own browser.

**Exception:** Self-XSS that can be chained to affect other users. For example: Self-XSS in a field that gets included in an admin dashboard viewed by support staff, or Self-XSS combined with login CSRF (force victim to log into attacker's account, triggering the stored XSS). If you can demonstrate the chain, report the CHAIN -- not the Self-XSS alone.

---

## 2. Missing Security Headers (Without Exploitation)

**What:** Absence of CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, or Permissions-Policy headers.

**Why rejected:** Missing headers alone are not a vulnerability -- they are defense-in-depth measures. Without demonstrating a concrete attack that the missing header would have prevented, there is no exploitable issue. Every scanner flags these, and triagers are overwhelmed with reports.

**Exception:** Missing X-Frame-Options or CSP frame-ancestors on a page with a sensitive state-changing action (e.g., "Delete Account" button) where you can demonstrate clickjacking leading to that action being performed. You must show the full clickjacking PoC with the iframe overlay performing the action.

---

## 3. Clickjacking on Non-Sensitive Pages

**What:** Framing the login page, homepage, marketing pages, or any page without state-changing functionality.

**Why rejected:** Clickjacking requires a state-changing action to be meaningful. Framing a login page does not steal credentials (the form submits to the legitimate site). Framing a static page does nothing.

**Exception:** Clickjacking on a page with a one-click state-changing action (e.g., "Enable 2FA bypass", "Delete account", "Transfer funds") where the victim's single click through the iframe completes the action. Must be demonstrated with a working PoC showing the action completes.

---

## 4. CSRF on Logout

**What:** Forcing a user to log out via a cross-site request.

**Why rejected:** Logging a user out causes minimal harm -- they simply log back in. There is no data loss, no account compromise, and no persistent effect. This is universally excluded by every major program.

**Exception:** Essentially none. Even in edge cases (e.g., combined with session fixation after re-login), programs almost never accept CSRF on logout. Do not submit.

---

## 5. CSRF on Non-State-Changing GET Requests

**What:** GET requests that are "vulnerable to CSRF" but do not change any server state (e.g., search queries, page views, data reads).

**Why rejected:** CSRF is only meaningful when it causes a state change on the server. GET requests that only read data are not CSRF -- they are normal browser behavior. The same-origin policy prevents the attacker from reading the response anyway.

**Exception:** None. This is not a vulnerability by definition. If a GET request changes state, report the insecure HTTP method usage instead.

---

## 6. Rate Limiting Issues (Without Abuse Scenario)

**What:** Reporting that an endpoint lacks rate limiting or has a high rate limit threshold.

**Why rejected:** Rate limiting is an operational concern, not a security vulnerability. Without demonstrating a concrete abuse scenario (e.g., brute-forcing credentials, account enumeration, resource exhaustion causing DoS), the absence of rate limiting is a best-practice recommendation.

**Exception:** Missing rate limiting on authentication endpoints where you can demonstrate successful credential brute-forcing or OTP bypass. For example: showing that you can enumerate valid usernames via timing differences, or that a 4-digit OTP can be brute-forced in under 10 minutes because there is no rate limit or lockout.

---

## 7. Content Spoofing / Text Injection

**What:** Injecting text (not HTML/JS) into a page that changes the displayed content but does not execute code or modify server state.

**Why rejected:** Text injection without code execution is cosmetic. The attacker cannot steal data, modify state, or perform actions. Most programs explicitly exclude "content injection" or "text injection" as non-impactful.

**Exception:** Text injection in a context where it creates a convincing phishing scenario -- for example, injecting a fake "Your session has expired, re-enter your password" message with a form that posts to an attacker-controlled server. This is rare and must be very convincing to be accepted.

---

## 8. SPF/DKIM/DMARC Misconfiguration

**What:** Missing or misconfigured email authentication records (SPF, DKIM, DMARC) that could allow email spoofing.

**Why rejected:** Email security configuration is almost universally excluded from bug bounty scope. It is an infrastructure/IT concern, not an application security vulnerability. Even with misconfiguration, modern email providers (Gmail, Outlook) have their own spoofing detection.

**Exception:** Demonstrated email spoofing that bypasses the target's email infrastructure AND lands in inbox (not spam) of the target's employees, combined with a realistic phishing scenario. This is extremely rare and usually only accepted in programs with "social engineering" in scope.

---

## 9. Software Version Disclosure

**What:** Server headers, error pages, or other responses revealing software versions (Apache 2.4.51, nginx 1.21.6, PHP 8.1.2, etc.).

**Why rejected:** Version disclosure alone is not exploitable. It is information that might help an attacker, but without a specific CVE for that version that you can demonstrate, it is purely informational. Every scanner flags this.

**Exception:** Software version disclosure of a specific version with a known, exploitable CVE where you can demonstrate the exploitation. For example: "Server runs Apache 2.4.49 which is vulnerable to CVE-2021-41773 (path traversal) -- here is the working exploit." Report the CVE exploitation, not the version disclosure.

---

## 10. Theoretical Attacks Without Working PoC

**What:** Reports stating "this endpoint is vulnerable to X" without a working proof of concept. Common examples: "This parameter might be vulnerable to SQL injection" without extracted data, "This field could be XSS" without executing JavaScript.

**Why rejected:** Bug bounty is about demonstrated impact. Theoretical vulnerability assessments are the job of internal security teams and scanners. Without a PoC, the triager cannot verify the issue, cannot assess severity, and cannot prioritize remediation.

**Exception:** None for bug bounty programs. If you believe something is vulnerable but cannot prove it, keep working on the PoC until you can. If you truly cannot exploit it, it may not actually be vulnerable.

---

## 11. Issues Requiring Physical Device Access

**What:** Attacks that require physical access to the victim's device (e.g., reading data from an unlocked phone, installing malware via USB, shoulder surfing).

**Why rejected:** Physical access negates the remote attack model that bug bounties are designed for. If you have physical access, you already have full control. These are physical security concerns, not application security vulnerabilities.

**Exception:** None for standard web/mobile bug bounty programs. Hardware bounty programs (Tesla, hardware wallets) may accept physical access attacks -- check the specific program scope.

---

## 12. Social Engineering

**What:** Phishing, pretexting, or other human-manipulation attacks against the target's employees.

**Why rejected:** Most bug bounty programs explicitly exclude social engineering because it targets people, not technology. The risk and liability of testing social engineering on real employees is too high for most programs.

**Exception:** Programs that explicitly include social engineering in scope (rare -- usually red team engagements, not bug bounty). Some programs accept phishing-related technical findings (e.g., email infrastructure allows spoofing + open redirect creates convincing phishing URL).

---

## 13. Self-Signed Certificates on Non-Production Domains

**What:** SSL/TLS certificate issues on staging, development, or internal domains.

**Why rejected:** Non-production environments are expected to have self-signed or invalid certificates. This is not a security finding -- it is standard development practice. Only production SSL issues matter.

**Exception:** Self-signed certificate on a production domain that users actually visit, combined with demonstrated MITM capability. This is rare since browsers show prominent warnings for invalid certificates.

---

## 14. Missing Cookie Flags on Non-Session Cookies

**What:** Reporting that a tracking cookie, preference cookie, or analytics cookie is missing Secure, HttpOnly, or SameSite flags.

**Why rejected:** Cookie security flags are meaningful only for session cookies or cookies containing sensitive data. A tracking cookie for analytics or a UI preference cookie (language, theme) does not need HttpOnly or Secure flags because there is nothing sensitive to protect.

**Exception:** Missing flags on session cookies or authentication tokens. If the session cookie lacks HttpOnly and you can demonstrate XSS-based session theft (Chain 1), report the XSS+theft chain. If the session cookie lacks Secure and you can demonstrate session hijacking over HTTP, report the hijacking.

---

## 15. Password Policy Complaints

**What:** Reporting that the application allows weak passwords (e.g., "password123"), does not enforce special characters, or does not have a minimum length.

**Why rejected:** Password policy is a business decision, not a security vulnerability. Programs set their own password requirements based on their user base and threat model. Reporting that "the password policy should be stricter" is a feature request, not a bug.

**Exception:** If you can demonstrate that the password policy allows credentials that appear in known breach databases (credential stuffing) AND the application has no brute-force protection, AND you can demonstrate successful credential stuffing, report the credential stuffing attack -- not the password policy.

---

## 16. CORS Misconfiguration on Public APIs

**What:** Overly permissive CORS headers (Access-Control-Allow-Origin: *) on API endpoints that serve publicly available data.

**Why rejected:** If the API endpoint only returns public data (no authentication required, no PII, no sensitive information), permissive CORS is not a vulnerability -- it is intentional. CORS restrictions protect sensitive cross-origin data, not public data.

**Exception:** CORS misconfiguration on authenticated endpoints that return sensitive user data, where the Access-Control-Allow-Credentials: true header is also set. You must demonstrate that an attacker page can read the victim's sensitive data cross-origin. Show the full PoC: attacker page makes fetch() with credentials:include, reads the response containing PII.

---

## 17. Host Header Injection (Without Impact)

**What:** The application reflects the Host header in responses, but this cannot be leveraged for any concrete attack.

**Why rejected:** Host header reflection alone is not exploitable. It becomes a vulnerability only when combined with a concrete attack vector: password reset poisoning (reset link uses attacker's host), cache poisoning (cached response serves attacker content to other users), or SSRF.

**Exception:** Host header injection that leads to: (a) Password reset poisoning -- reset email contains a link to attacker's domain, stealing the reset token. (b) Web cache poisoning -- attacker's host header is cached and served to other users. (c) SSRF -- host header is used in server-side requests. Must demonstrate the full attack, not just the reflection.

---

## 18. Open Ports That Are Intentionally Public

**What:** Reporting that port 80, 443, 22, or other standard service ports are open on the target's infrastructure.

**Why rejected:** Open ports are how services work. A web server needs port 80/443 open. An SSH server needs port 22 open. Reporting open ports without an associated vulnerability is not a finding.

**Exception:** Open ports running services that should not be publicly exposed (database ports 3306/5432/27017 accessible from the internet, admin panels on non-standard ports, debug/profiling services like pprof or JMX). You must demonstrate that the service is accessible and what data/access it provides.

---

## 19. Denial of Service via Resource Exhaustion

**What:** Sending many requests to overload a service, or finding an endpoint that consumes excessive resources (CPU, memory, disk).

**Why rejected:** Most bug bounty programs explicitly exclude DoS because: (a) testing it can harm the production service and other users, (b) resource exhaustion is usually an infrastructure scaling concern, and (c) it is difficult to distinguish from legitimate high traffic.

**Exception:** Application-level DoS via a single request that crashes the server or causes persistent degradation. For example: a regex DoS (ReDoS) where a single crafted input causes the server to hang for minutes, or an XML bomb that consumes all memory. The key is that ONE request causes disproportionate impact. Check program scope first -- many still exclude all DoS.

---

## 20. Username Enumeration

**What:** Login, registration, or password reset flows that reveal whether a username/email exists in the system (e.g., "No account found with this email" vs. "Invalid password").

**Why rejected:** Many applications intentionally differentiate error messages for UX reasons. Username enumeration is a low-impact issue that most programs have accepted as a design tradeoff. Modern applications are moving toward unified error messages, but this is not universally enforced.

**Exception:** Username enumeration combined with a demonstrated credential stuffing or brute-force attack where the enumeration was a necessary precondition. For example: used enumeration to identify valid accounts, then brute-forced passwords against those accounts with no rate limiting. Report the full attack chain.

---

## Pre-Submission Checklist

Before submitting any finding, run it through these filters:

1. Is the finding on this DROP list? If yes, does it meet the exception criteria?
2. Is the finding in the program's explicit exclusion list (scope.yaml)?
3. Is the finding on a domain/endpoint that is out of scope?
4. Does the finding have a working PoC? (If no, do not submit)
5. Is the impact real and demonstrated? (If theoretical, do not submit)
6. Have you checked for duplicates in the program's disclosed reports?
7. Is the severity honest? (Do not inflate -- triagers will downgrade)
8. Would YOU accept this finding if you were the triager?

**If you answered NO to question 8, do not submit.**
