# Agent R1: Subdomain & Asset Discovery

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
5. Write findings to /tmp/pentest-{{ID}}/agents/r1-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json
8. Do NOT perform any active exploitation — recon only
9. **Scope enforcement function:** Before EVERY HTTP request, validate the target domain:
   ```bash
   check_scope() {
     local url="$1"
     local domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | cut -d: -f1)
     if ! grep -qF "$domain" /tmp/pentest-{{ID}}/scope-allowlist.txt 2>/dev/null; then
       echo "[SCOPE BLOCKED] $domain is NOT in scope — request skipped"
       return 1
     fi
   }
   ```
   Call `check_scope "$URL" || continue` before every curl, dev-browser navigation, or tool command that hits an external URL. If scope check fails, do NOT send the request.

## Mission

Discover all subdomains, IP addresses, cloud assets, and related infrastructure for the target domain. Build the complete asset inventory that attack agents will use.

## Methodology

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (DomainRecon, CloudAssetDiscovery, NetblockRecon workflows)

### Step 1: Passive Subdomain Enumeration

```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.{{TARGET}}&output=json" | jq -r '.[].name_value' | sort -u > /tmp/pentest-{{ID}}/crt-subs.txt

# subfinder for multi-source passive enumeration
subfinder -d {{TARGET}} -silent -all -o /tmp/pentest-{{ID}}/subfinder-subs.txt

# Merge and deduplicate
cat /tmp/pentest-{{ID}}/crt-subs.txt /tmp/pentest-{{ID}}/subfinder-subs.txt | sort -u > /tmp/pentest-{{ID}}/all-subs.txt
```

### Step 2: DNS Resolution & Live Host Detection

```bash
# Resolve all subdomains and check which are alive
httpx -l /tmp/pentest-{{ID}}/all-subs.txt -silent -status-code -title -tech-detect -o /tmp/pentest-{{ID}}/live-hosts.txt

# Extract IPs from resolved hosts
httpx -l /tmp/pentest-{{ID}}/all-subs.txt -silent -ip -o /tmp/pentest-{{ID}}/resolved-ips.txt
```

### Step 3: Cloud Asset Enumeration

Reference: `~/.claude/skills/Security/Recon/SKILL.md` (CloudAssetDiscovery workflow)

For each cloud provider, check common bucket/storage naming patterns:

```bash
# AWS S3 — check common patterns
for pattern in {{TARGET}} {{TARGET}}-assets {{TARGET}}-backup {{TARGET}}-dev {{TARGET}}-staging {{TARGET}}-prod {{TARGET}}-uploads {{TARGET}}-static {{TARGET}}-media; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${pattern}.s3.amazonaws.com/")
  if [ "$status" != "404" ]; then
    echo "[S3] ${pattern}.s3.amazonaws.com — HTTP ${status}"
  fi
done

# Azure Blob
for pattern in {{TARGET}} {{TARGET}}assets {{TARGET}}backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://${pattern}.blob.core.windows.net/")
  if [ "$status" != "404" ]; then
    echo "[Azure] ${pattern}.blob.core.windows.net — HTTP ${status}"
  fi
done

# GCP Storage
for pattern in {{TARGET}} {{TARGET}}-assets {{TARGET}}-backup; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${pattern}/")
  if [ "$status" != "404" ]; then
    echo "[GCP] storage.googleapis.com/${pattern} — HTTP ${status}"
  fi
done
```

### Step 4: Reverse DNS & ASN Mapping

```bash
# WHOIS on primary domain for registrar and org info
whois {{TARGET}} > /tmp/pentest-{{ID}}/whois.txt

# Extract ASN for the primary IP
PRIMARY_IP=$(dig +short {{TARGET}} | head -1)
curl -s "https://ipinfo.io/${PRIMARY_IP}/json" > /tmp/pentest-{{ID}}/ipinfo.txt
```

### Step 5: Subdomain Takeover Check

For each subdomain with CNAME pointing to external service:
```bash
# Check for dangling CNAMEs (potential subdomain takeover)
for sub in $(cat /tmp/pentest-{{ID}}/all-subs.txt); do
  cname=$(dig +short CNAME "$sub")
  if [ -n "$cname" ]; then
    # Check if CNAME target is unregistered or returns error
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://${sub}" 2>/dev/null)
    if [ "$status" = "404" ] || [ "$status" = "000" ]; then
      echo "[TAKEOVER?] ${sub} → ${cname} — HTTP ${status}"
    fi
  fi
done
```

### Step 6: Write Results to Output File

Write discoveries to your dedicated output file (`/tmp/pentest-{{ID}}/agents/r1-results.json`) with `subdomains`, `cloud_assets`, `tech_stack`, and `findings` sections. The orchestrator will merge these into state.json.

## Tools
- subfinder — multi-source subdomain enumeration
- httpx — HTTP probing, tech detection, live host verification
- curl — API calls, cloud asset checks, HTTP requests
- dig — DNS resolution, CNAME checks
- whois — domain registration info

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/r1-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "R1",
  "class": "asset_discovery",
  "severity_estimate": "P3-P5",
  "validated": true,
  "endpoint": "[URL of discovered asset]",
  "method": "GET",
  "payload": "[discovery technique used]",
  "response_summary": "[what was found — open bucket, admin panel, etc.]",
  "poc_curl": "[curl command to verify]",
  "impact": "[exposure level — public read, public write, sensitive data]",
  "chain_potential": "[what attack agents could do with this — SSRF target, data exfil, etc.]"
}
```

Report notable findings immediately:
- Open S3 buckets / cloud storage with public read/write
- Subdomain takeover candidates
- Admin panels accessible without auth
- Development/staging environments exposed to internet
- Internal hostnames leaked in DNS
