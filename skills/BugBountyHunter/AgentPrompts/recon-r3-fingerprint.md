# Agent R3: Tech Fingerprinting & Vulnerability Scanning

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
5. Write findings to /tmp/pentest-{{ID}}/agents/r3-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json
8. Do NOT exploit vulnerabilities — identify and record only
9. **Scope enforcement function:** Before EVERY HTTP request, validate the target domain:
   ```bash
   check_scope() {
     local url="$1"
     local domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
     if ! grep -xqF "$domain" /tmp/pentest-{{ID}}/scope-allowlist.txt 2>/dev/null; then
       echo "[SCOPE BLOCKED] $domain is NOT in scope — request skipped"
       return 1
     fi
   }
   ```
   Call `check_scope "$URL" || continue` before every curl, dev-browser navigation, or tool command that hits an external URL. If scope check fails, do NOT send the request.

## Mission

Fingerprint the entire technology stack, detect WAF presence, identify known CVEs via nuclei scanning, generate search dorks, and take visual evidence with screenshots.

## Methodology

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (DorkGeneration workflow), `~/.claude/skills/DastAutomation/SKILL.md`

### Step 1: HTTP Technology Detection

```bash
# Comprehensive tech fingerprinting with httpx
httpx -u https://{{TARGET}} -tech-detect -status-code -title -server \
  -content-type -cdn -ip -cname -tls-grab -tls-probe \
  -json -o /tmp/pentest-{{ID}}/httpx-fingerprint.json

# If subdomains already in state.json, fingerprint all live hosts
httpx -l /tmp/pentest-{{ID}}/all-subs.txt -tech-detect -status-code -title -server \
  -json -o /tmp/pentest-{{ID}}/httpx-all.json 2>/dev/null
```

### Step 2: WAF Detection

```bash
# Detect WAF via response headers and behavior
# Send a benign request and an obviously malicious one, compare responses
CLEAN=$(curl -s -o /dev/null -w "%{http_code}" "https://{{TARGET}}/")
DIRTY=$(curl -s -o /dev/null -w "%{http_code}" "https://{{TARGET}}/?id=1' OR 1=1--")

# Check common WAF headers
curl -s -D- "https://{{TARGET}}/" | grep -iE '(cf-ray|x-sucuri|x-cdn|server: cloudflare|server: AkamaiGHost|x-amz-cf|x-ms-waf|x-fw-protection)'

# Nuclei WAF detection templates
nuclei -u "https://{{TARGET}}" -tags waf -silent -o /tmp/pentest-{{ID}}/waf-detect.txt
```

Record WAF in state.json tech_stack.waf — this is critical for attack agents to select WAF-specific bypass payloads from `~/.claude/skills/Security/Payloads/`.

### Step 3: Nuclei Vulnerability Scanning

```bash
# Run nuclei with standard templates — CVEs, exposures, misconfigurations
nuclei -u "https://{{TARGET}}" \
  -severity critical,high,medium \
  -type http \
  -concurrency 10 \
  -rate-limit 10 \
  -json -o /tmp/pentest-{{ID}}/nuclei-results.json

# Targeted scans based on detected tech stack
# If WordPress detected:
nuclei -u "https://{{TARGET}}" -tags wordpress -json -o /tmp/pentest-{{ID}}/nuclei-wp.json 2>/dev/null

# If Apache/Nginx detected:
nuclei -u "https://{{TARGET}}" -tags apache,nginx -json -o /tmp/pentest-{{ID}}/nuclei-server.json 2>/dev/null

# Exposure checks (sensitive files, debug endpoints, default creds)
nuclei -u "https://{{TARGET}}" -tags exposure,default-login,config -json -o /tmp/pentest-{{ID}}/nuclei-exposure.json
```

### Step 4: SSL/TLS Analysis

```bash
# Check SSL configuration
curl -s -v "https://{{TARGET}}/" 2>&1 | grep -E '(SSL connection|subject|issuer|expire|TLSv)'

# Check for weak ciphers and protocols
nmap --script ssl-enum-ciphers -p 443 {{TARGET}} -oN /tmp/pentest-{{ID}}/ssl-ciphers.txt 2>/dev/null
```

### Step 5: Dork Generation

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (DorkGeneration workflow)

Generate targeted search dorks for manual investigation:

```
# Google Dorks
site:{{TARGET}} filetype:pdf OR filetype:doc OR filetype:xls
site:{{TARGET}} inurl:admin OR inurl:login OR inurl:dashboard
site:{{TARGET}} intitle:"index of" OR intitle:"directory listing"
site:{{TARGET}} ext:env OR ext:log OR ext:conf OR ext:bak
site:{{TARGET}} intext:"error" OR intext:"warning" OR intext:"exception"
site:{{TARGET}} inurl:api OR inurl:graphql OR inurl:swagger

# GitHub Dorks
org:{{TARGET}} password OR secret OR token OR api_key
"{{TARGET}}" filename:.env OR filename:config.json OR filename:credentials
"{{TARGET}}" extension:pem OR extension:key OR extension:p12

# Shodan Dorks
ssl.cert.subject.cn:"{{TARGET}}"
hostname:"{{TARGET}}"
http.title:"{{TARGET}}"
```

Save dorks to /tmp/pentest-{{ID}}/dorks.txt for manual follow-up.

### Step 6: Visual Evidence Screenshots

```bash
# Take screenshots of key pages for the report
dev-browser <<'EOF'
const page = await browser.getPage("screenshot");
await page.goto("https://{{TARGET}}");
await page.waitForLoadState("networkidle");
await page.saveScreenshot("/tmp/pentest-{{ID}}/screenshot-home.png");

// Screenshot any admin/login pages found
const pages_to_screenshot = ["login", "admin", "dashboard", "api/docs"];
for (const path of pages_to_screenshot) {
  try {
    await page.goto(`https://{{TARGET}}/${path}`, { timeout: 10000 });
    await page.saveScreenshot(`/tmp/pentest-{{ID}}/screenshot-${path.replace(/\//g, '-')}.png`);
  } catch (e) { /* path may not exist */ }
}
EOF
```

### Step 7: Security Header Analysis

```bash
# Check security headers
HEADERS=$(curl -s -D- -o /dev/null "https://{{TARGET}}/")
echo "$HEADERS" | grep -iE '(strict-transport|content-security-policy|x-frame-options|x-content-type|x-xss-protection|referrer-policy|permissions-policy|cross-origin)'

# Missing security headers are informational but useful for report
```

### Step 8: Write Results to Output File

Write discoveries to your dedicated output file (`/tmp/pentest-{{ID}}/agents/r3-results.json`) with:
- `tech_stack`: server, framework, language, CDN, WAF, CMS, versions
- Any nuclei findings as preliminary findings (to be validated in Phase 3)
The orchestrator will merge these into state.json.

## Tools
- httpx — technology detection, HTTP probing, CDN/WAF detection
- nuclei — vulnerability scanning with community templates
- nmap — SSL/TLS cipher analysis, port scanning
- curl — header analysis, WAF fingerprinting
- dev-browser — screenshots for visual evidence

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/r3-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "R3",
  "class": "vulnerability_scan",
  "severity_estimate": "P1-P5",
  "validated": false,
  "endpoint": "[URL where vuln was detected]",
  "method": "GET",
  "payload": "[nuclei template ID or detection method]",
  "response_summary": "[CVE ID, exposure type, or misconfiguration detail]",
  "poc_curl": "[curl command to verify]",
  "impact": "[what an attacker gains — RCE, info disclosure, etc.]",
  "chain_potential": "[how this combines with other findings]"
}
```

Report critical findings immediately:
- Known CVEs with public exploits (especially RCE)
- Default credentials on admin panels
- Exposed debug endpoints (.env, phpinfo, stack traces)
- Weak SSL/TLS allowing downgrade attacks
- WAF type identified (critical for attack agent payload selection)
