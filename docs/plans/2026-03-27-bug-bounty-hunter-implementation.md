# Bug Bounty Hunter System — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an autonomous bug bounty pentesting system with parallel agents, scope compliance, impact validation, and real-world payload databases.

**Architecture:** Master orchestrator skill (`BugBountyHunter`) spawns parallel agents for recon (3) and attack (8), each using upgraded existing skills. Shared state file enables cross-agent discovery sharing. Impact validator chains and validates findings before generating bounty-ready reports.

**Tech Stack:** Claude Code skills (markdown), dev-browser CLI, ProjectDiscovery tools (subfinder, httpx, nuclei, katana), ffuf, sqlmap, curl, YAML payload databases.

**Design doc:** `docs/plans/2026-03-27-bug-bounty-hunter-design.md`

---

## Build Order Rationale

```
Task 1: Payload Database         (foundation — other skills reference payloads)
Task 2: Recon Skill Upgrade      (Phase 1 agents depend on this)
Task 3: DastAutomation Upgrade   (biggest attack skill, gets WAF bypasses + payloads)
Task 4: ApiSecurity Upgrade      (JWT, GraphQL, param mining)
Task 5: IdorPentest Upgrade      (impact validation, chaining)
Task 6: WebAssessment Upgrade    (autonomous auth, business logic)
Task 7: Impact Validator Module  (Phase 3 — validates all findings)
Task 8: BugBountyHunter Orchestrator (ties everything together)
Task 9: Fresh Technique Fetcher  (enhancement — pulls latest CVEs/techniques)
Task 10: Tool Installation Check (verify all tools available)
Task 11: Integration Test        (run against a test target)
```

Dependencies: Task 1 before 2-6. Tasks 2-6 are independent (parallelizable). Task 7 after 2-6. Task 8 after all others. Task 9-11 after 8.

---

### Task 1: Payload Database

**Files:**
- Create: `~/.claude/skills/Security/Payloads/xss.yaml`
- Create: `~/.claude/skills/Security/Payloads/ssrf.yaml`
- Create: `~/.claude/skills/Security/Payloads/sqli.yaml`
- Create: `~/.claude/skills/Security/Payloads/idor.yaml`
- Create: `~/.claude/skills/Security/Payloads/lfi.yaml`
- Create: `~/.claude/skills/Security/Payloads/auth-bypass.yaml`
- Create: `~/.claude/skills/Security/Payloads/business-logic.yaml`
- Create: `~/.claude/skills/Security/Payloads/403-bypass.yaml`
- Create: `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`
- Create: `~/.claude/skills/Security/Payloads/ssti.yaml`
- Create: `~/.claude/skills/Security/Payloads/README.md`

**Step 1: Create the Payloads directory and README**

```bash
mkdir -p ~/.claude/skills/Security/Payloads
```

Write `README.md` explaining the payload database structure:
- Each YAML file contains payloads for one vulnerability class
- Structure: `payloads` array with `name`, `payload`, `context` (where to use), `waf_bypass` (which WAFs it bypasses), `source` (attribution)
- Files are referenced by attack agents during Phase 2

**Step 2: Create xss.yaml — XSS payloads with WAF bypasses**

Source from AllAboutBugBounty (26 techniques) + research. Structure:

```yaml
# xss.yaml — XSS Payloads with WAF Bypass Intelligence
metadata:
  version: 1.0
  sources:
    - AllAboutBugBounty/daffainfo
    - PortSwigger XSS cheat sheet
  last_updated: 2026-03-27

# Generic payloads (no WAF)
generic:
  - name: basic_script
    payload: '<script>alert(1)</script>'
    context: html_body
  - name: img_onerror
    payload: '<img src=x onerror=alert(1)>'
    context: html_body
  - name: svg_onload
    payload: '<svg onload=alert(1)>'
    context: html_body
  # ... 26 techniques from AllAboutBugBounty

# WAF-specific bypasses
waf_bypasses:
  cloudflare:
    - name: cf_bypass_1
      payload: '<svg/onload=alert(1)//>'
      notes: Cloudflare may miss self-closing svg
    # ... more Cloudflare bypasses
  imperva:
    - name: imperva_bypass_1
      payload: '<details open ontoggle=alert(1)>'
      notes: Imperva often misses ontoggle events
    # ... more Imperva bypasses
  aws_waf:
    # ... AWS WAF bypasses
  cloudfront:
    # ... CloudFront bypasses
  modsecurity:
    # ... ModSecurity bypasses
  akamai:
    # ... Akamai bypasses
```

Populate with ALL payloads from:
1. AllAboutBugBounty XSS file (26 techniques + 7 WAF bypass sections)
2. Research intelligence (context-specific payloads: HTML body, attribute, JS, template literal)
3. PortSwigger XSS cheat sheet patterns

**Step 3: Create ssrf.yaml — SSRF payloads with IP encoding permutations**

```yaml
# ssrf.yaml — SSRF Payloads with IP Encoding Permutations
metadata:
  version: 1.0
  sources:
    - AllAboutBugBounty/daffainfo
  last_updated: 2026-03-27

# Target IPs to test with each encoding
target_ips:
  aws_metadata: "169.254.169.254"
  gcp_metadata: "metadata.google.internal"
  azure_metadata: "169.254.169.254"
  localhost: "127.0.0.1"

# IP encoding variants (8 from AllAboutBugBounty)
ip_encodings:
  - name: decimal
    example: "http://2852039166/"  # 169.254.169.254 as decimal
  - name: hex
    example: "http://0xa9fea9fe/"
  - name: octal
    example: "http://0251.0376.0251.0376/"
  - name: mixed
    example: "http://169.0xfe.0251.254/"
  - name: url_encoded
    example: "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/"
  - name: ipv6
    example: "http://[::ffff:a9fe:a9fe]/"
  - name: dns_rebinding
    example: "http://A.169.254.169.254.1time.127.0.0.1.forever.rebind.network/"
  - name: bubble_text
    example: "uses Unicode representation"

# Protocol schemes
protocols:
  - "file:///etc/passwd"
  - "dict://localhost:6379/info"
  - "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a"
  - "ftp://localhost:21"
  - "tftp://localhost:69/file"

# Cloud metadata payloads
cloud_metadata:
  aws_imdsv1:
    - "http://169.254.169.254/latest/meta-data/"
    - "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    - "http://169.254.169.254/latest/user-data/"
  aws_imdsv2:
    token_request: "PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'"
    metadata_request: "GET http://169.254.169.254/latest/meta-data/ -H 'X-aws-ec2-metadata-token: TOKEN'"
  gcp:
    - url: "http://metadata.google.internal/computeMetadata/v1/"
      headers: { "Metadata-Flavor": "Google" }
    - url: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
      headers: { "Metadata-Flavor": "Google" }
  azure:
    - url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
      headers: { "Metadata": "true" }
```

**Step 4: Create sqli.yaml — SQL injection payloads per database**

Structure with sections for: error-based, UNION-based, blind boolean, blind time-based, out-of-band, stacked queries. Per-database variants: MySQL, PostgreSQL, MSSQL, Oracle, SQLite. Include WAF bypass via encoding/commenting techniques.

Source from AllAboutBugBounty SQLi + expand with blind/time-based/OOB from research.

**Step 5: Create remaining payload files**

Create `idor.yaml` (16 bypass techniques from IdorPentest), `lfi.yaml` (14 techniques + PHP wrappers from AllAboutBugBounty), `auth-bypass.yaml` (JWT, MFA, OAuth, password reset, session attacks), `business-logic.yaml` (9 categories from AllAboutBugBounty), `403-bypass.yaml`, `rate-limit-bypass.yaml`, `ssti.yaml` (per-engine payloads for Jinja2, Twig, Freemarker, etc.).

Each file follows the same YAML structure with metadata, categorized payloads, and source attribution.

**Step 6: Verify all payload files are valid YAML**

```bash
for f in ~/.claude/skills/Security/Payloads/*.yaml; do
  python3 -c "import yaml; yaml.safe_load(open('$f'))" && echo "OK: $f" || echo "FAIL: $f"
done
```

Expected: All files OK.

**Step 7: Commit**

```bash
cd ~/.claude
git add skills/Security/Payloads/
git commit -m "feat: add payload database for bug bounty hunter system

Structured YAML payload files for XSS (with WAF bypasses), SSRF (IP
encodings + cloud metadata), SQLi (per-database), IDOR (16 layers),
LFI (PHP wrappers), auth bypass, business logic, 403/429 bypass, SSTI.
Sources: AllAboutBugBounty, PortSwigger, HackerOne research."
```

---

### Task 2: Upgrade Security/Recon Skill

**Files:**
- Modify: `~/.claude/skills/Security/Recon/SKILL.md` (513 lines)
- Create: `~/.claude/skills/Security/Recon/Workflows/JsAnalysis.md`
- Create: `~/.claude/skills/Security/Recon/Workflows/HistoricalUrls.md`
- Create: `~/.claude/skills/Security/Recon/Workflows/DorkGeneration.md`
- Create: `~/.claude/skills/Security/Recon/Workflows/CloudAssetDiscovery.md`

**Step 1: Read the current SKILL.md**

```bash
cat ~/.claude/skills/Security/Recon/SKILL.md
```

Understand the existing structure, workflow index, and how new workflows integrate.

**Step 2: Add JS analysis workflow**

Create `JsAnalysis.md` with:
- Crawl target with katana to find all JS files
- Extract endpoints using LinkFinder regex patterns (relative URLs, absolute URLs, API paths)
- Extract secrets using SecretFinder patterns (API keys, tokens, passwords, AWS keys)
- Extract hidden parameters from JS variable assignments
- Output: list of discovered endpoints, secrets, and parameters to shared state

Key patterns to include:
```
# LinkFinder patterns
/(https?:\/\/[^\s"'<>]+)/g
/["'](\/[a-zA-Z0-9_\-\/]+)["']/g
/["'](https?:\/\/[^\s"'<>]+)["']/g

# SecretFinder patterns
/['"](AIza[0-9A-Za-z\-_]{35})['"]/  # Google API key
/['"](AKIA[0-9A-Z]{16})['"]/  # AWS access key
/['"]([0-9a-f]{32})['"]/  # Generic API key
/password\s*[:=]\s*['"]([^'"]+)['"]/i  # Passwords
```

**Step 3: Add historical URL mining workflow**

Create `HistoricalUrls.md` with:
- Run gau (GetAllUrls) against target domain
- Run waybackurls as secondary source
- Filter for interesting extensions (.json, .xml, .config, .env, .sql, .bak, .old)
- Filter for API endpoints (/api/, /v1/, /v2/, /graphql, /rest/)
- Filter for admin/internal paths (/admin, /debug, /internal, /staging)
- Deduplicate with sort -u
- Probe surviving URLs with httpx
- Output: categorized URL list to shared state

**Step 4: Add dork generation workflow**

Create `DorkGeneration.md` with:
- Google dorks: `site:target.com filetype:pdf|doc|xls|env|config|sql|bak`
- Google dorks: `site:target.com inurl:admin|login|dashboard|api|debug`
- GitHub dorks: `org:target "password" OR "secret" OR "api_key" OR "token"`
- Shodan dorks: `ssl.cert.subject.cn:target.com`, `hostname:target.com`
- Execute dorks and collect results
- Output: discovered files, credentials, exposed services

**Step 5: Add cloud asset discovery workflow**

Create `CloudAssetDiscovery.md` with:
- S3 bucket enumeration: `target-com`, `target`, `target-backup`, `target-dev`, `target-staging`, `target-assets`, `target-uploads`
- Azure blob: `target.blob.core.windows.net`
- GCP storage: `storage.googleapis.com/target`
- Check for public read/write/list permissions
- Output: discovered cloud assets with permissions

**Step 6: Update SKILL.md with new workflows and Haddix technique**

Add to the workflow index:
- JsAnalysis workflow reference
- HistoricalUrls workflow reference
- DorkGeneration workflow reference
- CloudAssetDiscovery workflow reference

Add to the methodology section:
- Recursive 401 path brute-forcing (Haddix technique):
  ```
  When ffuf returns 401 on a path like /internal/:
  1. Don't stop — brute-force deeper: /internal/FUZZ
  2. Repeat recursively on each new 401
  3. Often reveals unprotected sub-paths 2-3 levels deep
  ```

**Step 7: Verify and commit**

```bash
cd ~/.claude
git add skills/Security/Recon/
git commit -m "feat: upgrade Recon skill with JS analysis, historical URLs, dorks, cloud assets

Add 4 new workflows: JsAnalysis (endpoint/secret extraction from JS),
HistoricalUrls (gau/waybackurls mining), DorkGeneration (Google/GitHub/Shodan),
CloudAssetDiscovery (S3/Azure/GCP enumeration). Add Haddix recursive 401
brute-forcing technique to methodology."
```

---

### Task 3: Upgrade DastAutomation Skill

**Files:**
- Modify: `~/.claude/skills/DastAutomation/SKILL.md` (1047 lines)
- Reference: `~/.claude/skills/Security/Payloads/xss.yaml`
- Reference: `~/.claude/skills/Security/Payloads/ssrf.yaml`
- Reference: `~/.claude/skills/Security/Payloads/lfi.yaml`
- Reference: `~/.claude/skills/Security/Payloads/403-bypass.yaml`
- Reference: `~/.claude/skills/Security/Payloads/rate-limit-bypass.yaml`

**Step 1: Read the current SKILL.md**

```bash
cat ~/.claude/skills/DastAutomation/SKILL.md
```

Understand the 10-phase methodology, existing payload sections, and Playwright integration points.

**Step 2: Replace Playwright MCP references with dev-browser**

Find all instances of Playwright MCP invocation and replace with dev-browser CLI patterns:
- `mcp__playwright__browser_navigate` → `dev-browser <<'EOF' ... page.goto(url) ... EOF`
- `mcp__playwright__browser_snapshot` → `dev-browser <<'EOF' ... page.snapshotForAI() ... EOF`
- `mcp__playwright__browser_click` → `dev-browser <<'EOF' ... page.click(selector) ... EOF`
- Update the prerequisites section to list dev-browser instead of Playwright MCP
- Update all example interactions to use dev-browser script patterns

**Step 3: Add WAF bypass intelligence to XSS testing phase**

In Phase 3 (XSS Detection), add:
- WAF detection step: check response headers for `cf-ray` (Cloudflare), `x-imperva-id` (Imperva), `x-amz-cf-id` (CloudFront), `server: AkamaiGHost`, etc.
- Based on detected WAF, load corresponding bypass payloads from `Security/Payloads/xss.yaml`
- Test payloads in order: generic first, then WAF-specific if generic fails
- Include context-specific testing: HTML body, attribute, JS string, template literal

**Step 4: Add SSRF IP encoding engine to SSRF testing phase**

In Phase 9 (SSRF Testing), add:
- Load IP encoding permutations from `Security/Payloads/ssrf.yaml`
- For each SSRF candidate parameter, test ALL 8 IP encoding variants
- Test all protocol schemes (file, dict, gopher, ftp, tftp)
- Test cloud metadata endpoints (AWS IMDSv1/v2, GCP, Azure) with proper headers
- Add DNS rebinding attack pattern
- Add redirect chain technique (host a redirect to internal IP)

**Step 5: Add LFI PHP wrapper chain**

Add new phase or extend injection testing with:
- Load payloads from `Security/Payloads/lfi.yaml`
- Test 14 LFI techniques: basic traversal, 4 URL encodings, null byte, path truncation, 6 PHP wrappers
- PHP wrapper chain for RCE: `php://filter/convert.base64-encode/resource=` → read source → identify writable paths → `php://input` or `data://` for RCE

**Step 6: Add 403 bypass and rate limit bypass techniques**

Add to reconnaissance or as pre-test step:
- When endpoint returns 403, automatically try bypass techniques from `Security/Payloads/403-bypass.yaml`:
  - Header injection: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For: 127.0.0.1`
  - Path manipulation: `/./path`, `//path`, `/path/..;/`, `/PATH` (case variation)
  - HTTP method override: `X-HTTP-Method-Override: GET`
- When 429 rate-limited, try bypasses from `Security/Payloads/rate-limit-bypass.yaml`

**Step 7: Add single-packet race condition testing**

Add to Phase 7 (Business Logic) or as new Phase 11:
- Explain James Kettle's single-packet attack technique
- Provide curl HTTP/2 multiplexed request pattern
- Common targets: coupon redemption, fund transfer, vote/like, account creation
- Detection: compare sequential vs parallel results for inconsistency

**Step 8: Verify and commit**

```bash
cd ~/.claude
git add skills/DastAutomation/
git commit -m "feat: upgrade DastAutomation with WAF bypasses, SSRF encodings, dev-browser

Replace Playwright MCP with dev-browser CLI throughout. Add WAF-specific
XSS bypass payloads (6 providers), SSRF IP encoding permutation engine
(8 variants), LFI PHP wrapper chain (14 techniques), 403/429 bypass
techniques, single-packet race condition testing."
```

---

### Task 4: Upgrade ApiSecurity Skill

**Files:**
- Modify: `~/.claude/skills/ApiSecurity/SKILL.md` (647 lines)

**Step 1: Read the current SKILL.md**

```bash
cat ~/.claude/skills/ApiSecurity/SKILL.md
```

**Step 2: Expand JWT attack section**

Current JWT section likely covers basic attacks. Add:
- **JWK injection:** Embed attacker's public key in JWT header, sign with attacker's private key
- **kid path traversal:** `"kid": "../../dev/null"` → sign with empty string
- **JKU/X5U injection:** Point `jku`/`x5u` header to attacker-controlled server hosting rogue keys
- **Algorithm confusion:** Server expects RS256, attacker sends HS256 signed with server's RSA public key as HMAC secret
- **None algorithm variants:** `"alg": "none"`, `"alg": "None"`, `"alg": "NONE"`, `"alg": "nOnE"`
- **Weak secret brute-force:** Common secrets list, hashcat/john patterns
- Include tool commands: `jwt_tool -t TARGET_URL -rc "COOKIE" -M at` (all tests)

**Step 3: Add parameter mining section**

New section "Parameter Discovery" after API endpoint discovery:
- For each discovered endpoint, run parameter brute-force
- Arjun approach: send requests with batches of parameter names, detect response differences
- Common hidden params to check: `debug`, `test`, `admin`, `internal`, `verbose`, `trace`, `_method`, `callback`, `format`, `fields`, `include`, `expand`
- curl-based approach for environments without Arjun:
  ```bash
  # Add each param to URL and check for response diff
  for param in debug test admin verbose trace format; do
    curl -s "https://target.com/api/endpoint?$param=true" | md5sum
  done
  ```

**Step 4: Add GraphQL field-level authorization testing**

Expand GraphQL section beyond introspection:
- After getting schema via introspection, test access to every field
- Identify fields that should be role-restricted (email, phone, address, payment, admin flags)
- Test with different auth levels (unauthenticated, low-priv user, admin)
- Test alias-based batching to bypass rate limits on auth checks
- Test nested queries for authorization bypass (authorized on parent, check children)

**Step 5: Add API version downgrade attacks**

New section:
- For each endpoint, try version downgrade: `/v3/users/123` → `/v2/users/123` → `/v1/users/123`
- Older API versions often lack authorization middleware added in newer versions
- Also try: remove version prefix entirely, try `/api/users/123` vs `/api/v2/users/123`
- Check for different response schemas that leak additional data in older versions

**Step 6: Add mass assignment detection**

New section:
- For each POST/PUT/PATCH endpoint, add extra fields from the GET response
- Compare: does adding `"role": "admin"` or `"is_admin": true` to a user update request work?
- Technique: GET /api/user/me → note all fields → PUT /api/user/me with additional fields
- Check for: role escalation, permission changes, account status changes, plan/tier changes
- Detect via response diff: did the added field appear in the response?

**Step 7: Verify and commit**

```bash
cd ~/.claude
git add skills/ApiSecurity/
git commit -m "feat: upgrade ApiSecurity with JWT attacks, param mining, GraphQL auth, mass assignment

Expand JWT section (JWK injection, kid traversal, JKU/X5U, algorithm
confusion). Add parameter mining via brute-force. Add GraphQL field-level
authorization testing. Add API version downgrade attacks. Add mass
assignment detection via response diff analysis."
```

---

### Task 5: Upgrade IdorPentest Skill

**Files:**
- Modify: `~/.claude/skills/IdorPentest/SKILL.md` (81 lines)
- Modify: `~/.claude/skills/IdorPentest/AttackLayers.md` (if needed)
- Create: `~/.claude/skills/IdorPentest/Workflows/ImpactValidation.md`
- Create: `~/.claude/skills/IdorPentest/Workflows/ChainExploitation.md`

**Step 1: Read the current SKILL.md and AttackLayers.md**

```bash
cat ~/.claude/skills/IdorPentest/SKILL.md
cat ~/.claude/skills/IdorPentest/AttackLayers.md
```

**Step 2: Create Impact Validation workflow**

Create `Workflows/ImpactValidation.md`:
- After finding an IDOR, don't just report it — assess the impact:
  1. What data is exposed? (PII, financial, credentials, health, private messages)
  2. How many records are accessible? (enumerate a range to estimate total)
  3. What actions can be performed? (read-only vs write/delete)
  4. Is there cross-tenant data exposure?
  5. Can the attacker modify another user's data?
- Data sensitivity classification:
  - Critical: passwords, payment info, SSN, health records → P1
  - High: email, phone, address, private messages → P2
  - Medium: username, profile data, preferences → P3
  - Low: public data accessible via IDOR → P4/P5 (likely won't be accepted)

**Step 3: Create Chain Exploitation workflow**

Create `Workflows/ChainExploitation.md`:
- IDOR → Data Exfil: enumerate IDs to extract bulk data
- IDOR → Privilege Escalation: if IDOR exposes admin user data, extract admin tokens/sessions
- IDOR → Account Takeover: if IDOR allows email/password change on other accounts
- IDOR + Information Disclosure: leaked internal IDs from one IDOR feed into another
- IDOR + SSRF: manipulate object references to trigger server-side requests

**Step 4: Add blind IDOR detection to SKILL.md or AttackLayers.md**

Add techniques for detecting IDOR when there's no visible confirmation:
- Timing-based: compare response time for own ID vs other ID vs non-existent ID
- Error message analysis: different errors for "exists but forbidden" vs "not found"
- Side-channel: does accessing another user's resource trigger a notification to them?
- Mutation-based: POST/PUT to another user's resource, then verify via legitimate access

**Step 5: Add UUID prediction/leakage detection**

Add to the UUID/non-sequential layer:
- UUIDv1 contains timestamp + MAC address — predictable if you know creation time
- Check if UUIDs are leaked in: API responses, HTML source, JS files, error messages, email links
- Check for sequential UUIDv4 (some implementations aren't truly random)
- Technique: create 2 accounts, compare UUIDs for predictable patterns

**Step 6: Verify and commit**

```bash
cd ~/.claude
git add skills/IdorPentest/
git commit -m "feat: upgrade IdorPentest with impact validation, chaining, blind IDOR

Add ImpactValidation workflow (data sensitivity classification, exposure
scope assessment). Add ChainExploitation workflow (IDOR to ATO, priv esc,
data exfil chains). Add blind IDOR detection (timing, error analysis,
side-channel). Add UUID prediction/leakage detection techniques."
```

---

### Task 6: Upgrade Security/WebAssessment Skill

**Files:**
- Modify: `~/.claude/skills/Security/WebAssessment/SKILL.md` (206 lines)

**Step 1: Read the current SKILL.md**

```bash
cat ~/.claude/skills/Security/WebAssessment/SKILL.md
```

**Step 2: Add autonomous authentication directive**

Add a new section "Autonomous Behaviors" near the top of the skill:

```markdown
## Autonomous Behaviors (MANDATORY)

When credentials are provided for a target, the agent MUST:
1. Navigate to the login page using dev-browser
2. Fill credentials and submit the form
3. Extract all auth tokens (JWT, session cookies, CSRF tokens)
4. Store tokens in the shared state file
5. Auto-refresh tokens when they expire (detect 401 → re-authenticate)
6. Extract new CSRF tokens before each state-changing request

The agent MUST NOT:
- Stop to ask the user for tokens when credentials are provided
- Stop to ask about CSRF tokens (extract them from the page)
- Stop to ask about session management (handle it autonomously)
- Report "I need a token" — get it yourself
```

**Step 3: Add business logic test cases**

Add section "Business Logic Testing Checklist" with 9 categories from AllAboutBugBounty:

1. **Reviews/Ratings:** Submit reviews for products not purchased, manipulate rating values, bypass review limits
2. **Coupons/Discounts:** Apply same coupon multiple times (race condition), use expired coupons, stack incompatible discounts
3. **Delivery Charges:** Manipulate delivery fee parameters, change delivery address after payment, bypass minimum order
4. **Currency:** Change currency code while keeping price value, exploit rounding differences between currencies
5. **Premium Features:** Access premium endpoints without subscription, manipulate subscription tier parameter, bypass trial expiration
6. **Refunds:** Request refund while keeping service, double refund via race condition, manipulate refund amount
7. **Cart/Checkout:** Negative quantity, price tampering in cart, add items after payment calculation
8. **Comments/Posts:** Bypass character limits, inject into notification emails, manipulate timestamps
9. **Parameter Tampering:** Change `user_id`, `role`, `is_admin`, `plan_type` in requests

**Step 4: Add OWASP WSTG v4.2 reference taxonomy**

Add section referencing WSTG test case IDs the agent should walk through:
- WSTG-INFO: Information gathering (fingerprinting, discovery, error handling)
- WSTG-CONF: Configuration management (HTTP methods, file extensions, admin interfaces)
- WSTG-IDNT: Identity management (role definitions, registration, provisioning)
- WSTG-ATHN: Authentication (credentials, lockout, bypass, MFA)
- WSTG-ATHZ: Authorization (path traversal, priv esc, IDOR)
- WSTG-SESS: Session management (cookies, fixation, CSRF, timeout)
- WSTG-INPV: Input validation (XSS, SQLi, SSTI, LFI, command injection)
- WSTG-ERRH: Error handling (stack traces, error codes)
- WSTG-CRYP: Cryptography (TLS, padding oracle, sensitive data)
- WSTG-BUSL: Business logic (workflow, integrity, timing, limits)
- WSTG-CLNT: Client-side (DOM XSS, JS execution, clickjacking, WebSocket)

**Step 5: Update to reference dev-browser instead of Playwright MCP**

Replace any Playwright MCP references with dev-browser patterns.

**Step 6: Verify and commit**

```bash
cd ~/.claude
git add skills/Security/WebAssessment/
git commit -m "feat: upgrade WebAssessment with autonomous auth, business logic, WSTG taxonomy

Add mandatory autonomous authentication directive (no stopping for tokens).
Add 9-category business logic testing checklist from AllAboutBugBounty.
Add OWASP WSTG v4.2 test case taxonomy reference. Replace Playwright
MCP with dev-browser CLI."
```

---

### Task 7: Impact Validator Module

**Files:**
- Create: `~/.claude/skills/Security/ImpactValidator/SKILL.md`
- Create: `~/.claude/skills/Security/ImpactValidator/ChainPatterns.md`
- Create: `~/.claude/skills/Security/ImpactValidator/SeverityMatrix.md`
- Create: `~/.claude/skills/Security/ImpactValidator/BountyFilter.md`
- Create: `~/.claude/skills/Security/ImpactValidator/ReportTemplate.md`

**Step 1: Create ImpactValidator directory**

```bash
mkdir -p ~/.claude/skills/Security/ImpactValidator
```

**Step 2: Create SKILL.md — the main validator skill**

```markdown
---
name: ImpactValidator
description: Validates pentest findings for exploitability, chains vulnerabilities for maximum impact, classifies severity, and generates bug bounty reports. Use after attack agents complete testing.
---

## Purpose

Every finding from attack agents passes through this validator before reporting.
The validator answers three questions:
1. Is this actually exploitable? (not theoretical, not a false positive)
2. Can this be chained with other findings for higher impact?
3. Is this worth submitting to a bug bounty program?

## Workflow

1. Read all findings from shared state
2. For each finding:
   a. Attempt to reproduce the exploit
   b. Verify the impact is real (data actually exposed, action actually performed)
   c. Capture PoC evidence (curl commands, screenshots, response bodies)
3. Check all findings against chain patterns
4. Classify severity using the matrix
5. Filter through bounty-worthiness criteria
6. Generate reports for validated findings only

## Key Rules

- NEVER report a finding you haven't verified yourself
- A finding without a working PoC is not a finding
- Always attempt chaining before finalizing severity
- If a P4 can be chained to P2, report the chain as P2
- Drop anything the program explicitly excludes
```

**Step 3: Create ChainPatterns.md**

Document all known vulnerability chains with step-by-step exploitation:
- XSS → ATO: steal session cookie, impersonate admin
- XSS → CSRF → ATO: change victim's email via stored XSS, then password reset
- SSRF → Cloud Metadata → Credential Theft: access IMDSv1, extract IAM creds
- SSRF → Internal Admin → RCE: access internal admin panel, upload web shell
- IDOR → Data Exfil → Privilege Escalation: extract admin data, use admin tokens
- Open Redirect → OAuth Token Theft → ATO: redirect OAuth callback to attacker
- Information Disclosure → API Key → Further Access: leaked key opens new attack surface
- Race Condition → Financial Impact: double-spend, coupon reuse, balance manipulation

Each chain includes: preconditions, step-by-step, PoC template, expected severity.

**Step 4: Create SeverityMatrix.md**

Detailed classification matrix:
- P1 (Critical, $10K-$250K): RCE, full ATO on any user, payment manipulation with financial impact, mass PII breach, authentication bypass to admin
- P2 (High, $2K-$50K): IDOR exposing PII, privilege escalation, significant data exposure, stored XSS on sensitive pages with demonstrated impact
- P3 (Medium, $500-$5K): Stored XSS without ATO chain, CSRF on sensitive actions, information disclosure of credentials/tokens, blind SSRF without metadata access
- P4 (Low, $100-$1K): Reflected XSS, CSRF on non-sensitive actions, verbose errors exposing stack traces, open redirect without chain
- P5 (Informational, $0-$100): Missing headers, theoretical issues, self-XSS, clickjacking on non-sensitive pages

**Step 5: Create BountyFilter.md**

List of findings that programs commonly reject:
- Self-XSS (unless chained)
- Missing security headers without demonstrated exploitation
- Clickjacking on non-sensitive pages
- CSRF on logout/non-state-changing actions
- Rate limiting issues without demonstrated abuse
- Content spoofing without user impact
- SPF/DKIM/DMARC misconfiguration (usually excluded)
- Software version disclosure without known CVE
- Theoretical attacks without PoC
- Issues requiring physical device access
- Social engineering reliance

**Step 6: Create ReportTemplate.md**

HackerOne/Bugcrowd-optimized report template with:
- Descriptive title (what + where + impact in one line)
- Severity with CVSS score and CWE ID
- Summary (2-3 sentences: what, where, impact)
- Steps to reproduce (numbered, exact URLs, payloads, curl commands)
- Impact (business terms: users affected, data exposed, financial risk)
- PoC (curl commands, dev-browser scripts, screenshots)
- Remediation recommendation
- Bounty estimate range

**Step 7: Verify and commit**

```bash
cd ~/.claude
git add skills/Security/ImpactValidator/
git commit -m "feat: add ImpactValidator module for finding validation and severity classification

New skill with chain detection (8 vulnerability chains), severity matrix
(P1-P5 with payout ranges), bounty-worthiness filter, and HackerOne/
Bugcrowd report template. Every finding must pass validation before
reporting."
```

---

### Task 8: BugBountyHunter Orchestrator Skill

**Files:**
- Create: `~/.claude/skills/BugBountyHunter/SKILL.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/recon-r1.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/recon-r2.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/recon-r3.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-auth.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-idor.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-injection.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-ssrf.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-business-logic.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-api.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-file-upload.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/attack-websocket.md`
- Create: `~/.claude/skills/BugBountyHunter/AgentPrompts/validator.md`

This is the largest task — the master orchestrator that ties everything together.

**Step 1: Create directory structure**

```bash
mkdir -p ~/.claude/skills/BugBountyHunter/AgentPrompts
```

**Step 2: Create SKILL.md — the master orchestrator**

This is the core skill file. It must include:

**Frontmatter:**
```markdown
---
name: BugBountyHunter
description: Autonomous bug bounty pentesting orchestrator. Reads program rules, spawns parallel agents for recon and attack, validates findings, generates bounty-ready reports. Use when pentesting a target for bug bounty.
---
```

**Input Parsing:**
- Parse target URL, scope wildcards, credentials, program URL
- Accept formats:
  - `pentest target.com` (minimal)
  - `pentest target.com scope=*.target.com creds=user:pass@https://target.com/login program=https://hackerone.com/target`
  - `bug bounty target.com` (synonym trigger)

**Phase 0 — Scope Compliance:**
- Use WebFetch to fetch the program page
- Parse scope from program page (or accept user-provided scope)
- Generate `/tmp/pentest-<id>/scope.yaml`
- Generate `/tmp/pentest-<id>/state.json` with initial structure
- Display scope summary to user for confirmation before proceeding

**Phase 1 — Recon (3 parallel agents):**
- Read agent prompt templates from `AgentPrompts/recon-r1.md`, `recon-r2.md`, `recon-r3.md`
- Inject scope.yaml contents and target info into each prompt
- Spawn 3 parallel agents using the Agent tool with `subagent_type: "Pentester"`
- Each agent writes discoveries to state.json
- Wait for all 3 to complete
- Merge recon results and display summary

**Phase 2 — Authentication:**
- Use dev-browser to authenticate with provided credentials
- Store auth state in state.json
- If no credentials provided, skip to unauthenticated testing

**Phase 2b — Attack (8 parallel agents):**
- Read agent prompt templates from `AgentPrompts/attack-*.md`
- Inject scope, auth tokens, discovered endpoints, tech stack into each prompt
- Spawn 8 parallel agents using the Agent tool with `subagent_type: "Pentester"`
- Each agent tests its attack surface and writes findings to state.json
- Wait for all 8 to complete

**Phase 3 — Validation:**
- Read validator prompt from `AgentPrompts/validator.md`
- Inject all findings from state.json
- Spawn validator agent
- Validator reproduces, chains, classifies, and filters findings

**Phase 4 — Reporting:**
- Read validated findings from validator output
- Generate markdown report using ImpactValidator/ReportTemplate.md format
- Save report to `/tmp/pentest-<id>/report.md`
- Display summary to user with finding count and severity breakdown

**Behavioral rules (embedded in SKILL.md):**
All 8 behavioral rules from the design doc, prominently placed.

**Step 3: Create agent prompt templates**

Each file in `AgentPrompts/` is a complete prompt for one parallel agent. The orchestrator reads it, injects context (scope, auth, endpoints), and passes it to the Agent tool.

Example structure for `attack-idor.md`:
```markdown
# Agent B: Access Control / IDOR Testing

## Context (injected by orchestrator)
- Target: {{TARGET}}
- Scope: {{SCOPE_YAML}}
- Auth tokens: {{AUTH_STATE}}
- Discovered endpoints: {{ENDPOINTS}}
- Tech stack: {{TECH_STACK}}

## Your Mission
Test every discovered endpoint for IDOR and broken access control vulnerabilities.

## Behavioral Rules
1. Never stop to ask for tokens — use the auth state provided
2. Check scope before every request
3. Validate every finding — confirm the data is actually from another user
4. Attempt to chain findings for higher severity

## Methodology
Use the IdorPentest skill's 16-layer attack matrix.
For each discovered endpoint with an ID parameter:
[... full methodology ...]

## Output Format
Write findings to: /tmp/pentest-{{ENGAGEMENT_ID}}/state.json
Each finding: { id, class, severity, validated, endpoint, poc, impact }
```

Create all 12 agent prompt files (3 recon + 8 attack + 1 validator) following this pattern, each referencing the appropriate existing skill methodology.

**Step 4: Verify skill loads correctly**

Test that the skill triggers on appropriate keywords:
- "pentest target.com"
- "bug bounty target.com"
- "run a pentest on target.com"

**Step 5: Commit**

```bash
cd ~/.claude
git add skills/BugBountyHunter/
git commit -m "feat: add BugBountyHunter orchestrator skill

Master orchestrator with 4-phase pipeline: scope compliance (Phase 0),
parallel recon with 3 agents (Phase 1), parallel attack with 8 agents
(Phase 2), impact validation and chaining (Phase 3), report generation
(Phase 4). Uses dev-browser for auth, shared state for cross-agent
discovery, and payload databases for real-world techniques."
```

---

### Task 9: Fresh Technique Fetcher

**Files:**
- Create: `~/.claude/skills/Security/TechniqueFetcher/SKILL.md`

**Step 1: Create directory**

```bash
mkdir -p ~/.claude/skills/Security/TechniqueFetcher
```

**Step 2: Create SKILL.md**

A skill that, given a target's tech stack, fetches the latest relevant attack intelligence:

1. **Nuclei template updates:** Check for latest nuclei templates matching the tech stack
   ```bash
   nuclei -update-templates
   nuclei -tl -tags django | head -20  # List templates for detected framework
   ```

2. **HackerOne disclosed reports:** Search for disclosed reports on the target program
   - WebSearch for `site:hackerone.com/reports "target-name" disclosed`
   - Extract vulnerability patterns and techniques used

3. **CVE lookup:** For each identified software version
   - WebSearch for `CVE <software> <version> exploit`
   - Check if nuclei has templates for discovered CVEs

4. **Recent bypass techniques:** Search for latest WAF bypass, auth bypass, or framework-specific techniques
   - WebSearch for `<framework> <version> security bypass 2026`
   - WebSearch for `<WAF> bypass XSS 2026`

Output: structured list of relevant techniques, CVEs, and nuclei templates to prioritize during testing.

**Step 3: Commit**

```bash
cd ~/.claude
git add skills/Security/TechniqueFetcher/
git commit -m "feat: add TechniqueFetcher for pulling fresh CVEs, templates, and techniques

Fetches latest nuclei templates, disclosed HackerOne reports, CVEs for
identified software, and recent bypass techniques before each engagement."
```

---

### Task 10: Tool Installation Check

**Files:**
- Create: `~/.claude/skills/BugBountyHunter/check-tools.sh`

**Step 1: Create tool check script**

```bash
#!/bin/bash
# check-tools.sh — Verify all required tools are installed

REQUIRED=(dev-browser subfinder httpx nuclei katana ffuf nmap curl)
RECOMMENDED=(sqlmap interactsh-client arjun gau dalfox)
MISSING_REQ=()
MISSING_REC=()

for tool in "${REQUIRED[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_REQ+=("$tool")
  fi
done

for tool in "${RECOMMENDED[@]}"; do
  if ! command -v "$tool" &>/dev/null; then
    MISSING_REC+=("$tool")
  fi
done

echo "=== Bug Bounty Hunter Tool Check ==="
if [ ${#MISSING_REQ[@]} -eq 0 ]; then
  echo "✅ All required tools installed"
else
  echo "❌ Missing required tools: ${MISSING_REQ[*]}"
  echo "Install with:"
  for tool in "${MISSING_REQ[@]}"; do
    case "$tool" in
      subfinder) echo "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
      httpx) echo "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
      nuclei) echo "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" ;;
      katana) echo "  go install github.com/projectdiscovery/katana/cmd/katana@latest" ;;
      ffuf) echo "  go install github.com/ffuf/ffuf/v2@latest" ;;
      *) echo "  Install $tool via your package manager" ;;
    esac
  done
fi

if [ ${#MISSING_REC[@]} -gt 0 ]; then
  echo "⚠️  Missing recommended tools: ${MISSING_REC[*]}"
fi
```

**Step 2: Make executable and test**

```bash
chmod +x ~/.claude/skills/BugBountyHunter/check-tools.sh
~/.claude/skills/BugBountyHunter/check-tools.sh
```

**Step 3: Install any missing required tools**

Based on output, install missing tools.

**Step 4: Commit**

```bash
cd ~/.claude
git add skills/BugBountyHunter/check-tools.sh
git commit -m "feat: add tool installation check script for BugBountyHunter"
```

---

### Task 11: Integration Test

**Step 1: Run tool check**

```bash
~/.claude/skills/BugBountyHunter/check-tools.sh
```

**Step 2: Test skill triggers**

Verify the BugBountyHunter skill loads when saying:
- "pentest example.com"
- "bug bounty example.com"
- "run security assessment on example.com"

**Step 3: Test against a safe target**

Use a deliberately vulnerable application for testing:
- OWASP Juice Shop (if running locally)
- PortSwigger Web Security Academy labs
- Or a personal test application

Run the full pipeline and verify:
- [ ] Phase 0 generates scope.yaml
- [ ] Phase 1 recon agents run in parallel
- [ ] Phase 2 auth works autonomously
- [ ] Phase 2b attack agents run in parallel
- [ ] Phase 3 validator chains and classifies findings
- [ ] Phase 4 report is generated in proper format
- [ ] No out-of-scope requests were made
- [ ] All findings have working PoCs

**Step 4: Document any issues and iterate**

Fix any issues discovered during integration testing. Commit fixes.

---

## Parallelizable Tasks

Tasks 2-6 (skill upgrades) are independent and can be executed in parallel by separate agents. Task 1 (Payload Database) must complete first since skills reference payloads. Tasks 7-8 require all skill upgrades to be done. Tasks 9-11 are sequential after 8.

```
Task 1 (Payload DB)
    ├── Task 2 (Recon) ─────────┐
    ├── Task 3 (DAST) ──────────┤
    ├── Task 4 (API) ───────────┤── All parallel
    ├── Task 5 (IDOR) ──────────┤
    └── Task 6 (WebAssessment) ─┘
                                 ├── Task 7 (Impact Validator)
                                 └── Task 8 (Orchestrator)
                                      ├── Task 9 (Technique Fetcher)
                                      ├── Task 10 (Tool Check)
                                      └── Task 11 (Integration Test)
```
