# Agent R2: Content & API Discovery

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
6. Do NOT perform any active exploitation — discovery only

## Mission

Discover all content, hidden paths, API endpoints, JavaScript-embedded URLs, and historical URLs. Build the complete endpoint map for attack agents.

## Methodology

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (JsAnalysis, HistoricalUrls workflows)

### Step 1: Web Crawling with Katana

```bash
# Crawl the target with katana for comprehensive URL discovery
katana -u https://{{TARGET}} -d 3 -js-crawl -known-files all \
  -automatic-form-fill -headless -silent \
  -o /tmp/pentest-{{ID}}/katana-urls.txt

# Extract unique paths
cat /tmp/pentest-{{ID}}/katana-urls.txt | \
  unfurl paths | sort -u > /tmp/pentest-{{ID}}/discovered-paths.txt
```

### Step 2: JavaScript Analysis

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (JsAnalysis workflow)

```bash
# Extract all JS file URLs from crawl results
grep -E '\.js(\?|$)' /tmp/pentest-{{ID}}/katana-urls.txt | sort -u > /tmp/pentest-{{ID}}/js-files.txt

# For each JS file, extract endpoints, secrets, and parameters
for js_url in $(cat /tmp/pentest-{{ID}}/js-files.txt | head -50); do
  content=$(curl -s "$js_url")

  # Extract API endpoints (absolute and relative paths)
  echo "$content" | grep -oP '["'"'"'](/api/[^"'"'"'\s]+)["'"'"']' >> /tmp/pentest-{{ID}}/js-endpoints.txt
  echo "$content" | grep -oP '["'"'"'](https?://[^"'"'"'\s]+)["'"'"']' >> /tmp/pentest-{{ID}}/js-endpoints.txt

  # Extract potential secrets
  echo "$content" | grep -oiP '(api[_-]?key|api[_-]?secret|token|password|secret|aws[_-]?access)\s*[=:]\s*["'"'"'][^"'"'"']+["'"'"']' >> /tmp/pentest-{{ID}}/js-secrets.txt

  # Extract parameter names from JS objects
  echo "$content" | grep -oP '["'"'"'](\w{3,30})["'"'"']\s*:' | tr -d '":'"'"' ' >> /tmp/pentest-{{ID}}/js-params.txt
done

# Deduplicate
sort -u -o /tmp/pentest-{{ID}}/js-endpoints.txt /tmp/pentest-{{ID}}/js-endpoints.txt
sort -u -o /tmp/pentest-{{ID}}/js-params.txt /tmp/pentest-{{ID}}/js-params.txt
```

### Step 3: Historical URL Mining

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (HistoricalUrls workflow)

```bash
# Wayback Machine and other archive sources
gau {{TARGET}} --threads 5 --o /tmp/pentest-{{ID}}/gau-urls.txt 2>/dev/null

# Filter for interesting file types
grep -iE '\.(json|xml|yaml|yml|env|sql|bak|log|conf|config|ini|txt|csv|xls|doc|pdf|zip|tar|gz)(\?|$)' \
  /tmp/pentest-{{ID}}/gau-urls.txt > /tmp/pentest-{{ID}}/interesting-files.txt

# Filter for API endpoints
grep -iE '/(api|v[0-9]+|graphql|rest|internal|admin|debug|staging|test)/' \
  /tmp/pentest-{{ID}}/gau-urls.txt > /tmp/pentest-{{ID}}/api-endpoints.txt

# Extract unique parameter names from all historical URLs
cat /tmp/pentest-{{ID}}/gau-urls.txt | unfurl keys | sort -u > /tmp/pentest-{{ID}}/historical-params.txt
```

### Step 4: Directory Brute-Forcing with ffuf

```bash
# Standard content discovery
ffuf -u "https://{{TARGET}}/FUZZ" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -fc 404 -t 40 -rate 10 \
  -o /tmp/pentest-{{ID}}/ffuf-root.json -of json

# API path discovery
ffuf -u "https://{{TARGET}}/api/FUZZ" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,307,401,403,405 \
  -fc 404 -t 40 -rate 10 \
  -o /tmp/pentest-{{ID}}/ffuf-api.json -of json

# Recursive 401 brute-forcing (Haddix technique from Recon skill)
# For each 401/403 path found, fuzz one level deeper
for path in $(jq -r '.results[] | select(.status == 401 or .status == 403) | .input.FUZZ' /tmp/pentest-{{ID}}/ffuf-root.json 2>/dev/null); do
  ffuf -u "https://{{TARGET}}/${path}/FUZZ" \
    -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
    -mc 200,204 -fc 404 -t 20 -rate 10 \
    -o "/tmp/pentest-{{ID}}/ffuf-${path}.json" -of json
done
```

### Step 5: API Specification Discovery

```bash
# Check common API doc endpoints
for doc_path in swagger.json openapi.json api-docs api/docs api/swagger swagger/v1/swagger.json .well-known/openapi.json graphql __graphql api/graphql; do
  status=$(curl -s -o /tmp/pentest-{{ID}}/api-spec-${doc_path//\//-}.json -w "%{http_code}" "https://{{TARGET}}/${doc_path}")
  if [ "$status" = "200" ]; then
    echo "[API-DOC] https://{{TARGET}}/${doc_path} — HTTP 200"
  fi
done
```

### Step 6: Source Map Detection

```bash
# Check for exposed source maps
for js_url in $(cat /tmp/pentest-{{ID}}/js-files.txt | head -20); do
  map_url="${js_url}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "[SOURCE-MAP] ${map_url} — original source code exposed"
  fi
done
```

### Step 7: Write Results to State

Read current state.json, merge into `discovered_endpoints`, `js_endpoints`, `parameters` sections.

## Tools
- katana — web crawling with JS rendering
- gau — historical URL mining (Wayback, Common Crawl, OTX, URLScan)
- ffuf — directory and API brute-forcing
- curl — HTTP requests, API spec fetching
- unfurl — URL parsing (paths, keys, values)
- grep — pattern extraction from JS and URLs

## Finding Output Format
Write each finding to state.json as:
```json
{
  "id": "F-NNN",
  "agent": "R2",
  "class": "content_discovery",
  "severity_estimate": "P3-P5",
  "validated": true,
  "endpoint": "[URL of discovered content]",
  "method": "GET",
  "payload": "[discovery technique — ffuf, gau, JS analysis]",
  "response_summary": "[what was found — API spec, source map, backup file, secret in JS]",
  "poc_curl": "[curl command to retrieve]",
  "impact": "[API endpoints exposed, secrets leaked, source code accessible]",
  "chain_potential": "[attack agents can use these endpoints/secrets for deeper testing]"
}
```

Report notable findings immediately:
- API specifications (Swagger/OpenAPI) exposing internal endpoints
- Secrets found in JavaScript files (API keys, tokens, credentials)
- Source maps exposing original source code
- Backup files (.bak, .sql, .env) accessible publicly
- Admin or internal paths accessible behind 401/403 (Haddix technique hits)
- Historical URLs revealing deprecated but still-active endpoints
