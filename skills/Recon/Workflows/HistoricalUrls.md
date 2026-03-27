# Historical URLs Workflow

**Purpose:** Mine archived and historical URLs from Wayback Machine, Common Crawl, and other sources to discover forgotten endpoints, old API versions, backup files, and sensitive paths.

**Input:** Target domain
**Output:** Categorized, deduplicated, and probed URL list for shared state
**Authorization:** Passive — uses only public archive data. Probing live URLs requires authorization.

---

## Step 1: Collect Historical URLs

### Run gau (GetAllUrls)

```bash
echo TARGET | gau --threads 5 --o gau_urls.txt
```

**gau sources:** Wayback Machine, Common Crawl, OTX (AlienVault), URLScan

### Run waybackurls

```bash
echo TARGET | waybackurls > wayback_urls.txt
```

### Combine and deduplicate

```bash
cat gau_urls.txt wayback_urls.txt | sort -u > all_historical_urls.txt
wc -l all_historical_urls.txt
```

---

## Step 2: Filter by Interesting Extensions

Extract URLs with extensions that commonly expose sensitive data or misconfigurations:

### Configuration and Environment Files

```bash
grep -Ei '\.(json|xml|yaml|yml|toml|ini|conf|config|cfg|env|properties)(\?|$)' all_historical_urls.txt | sort -u > urls_config.txt
```

### Database and Backup Files

```bash
grep -Ei '\.(sql|db|sqlite|sqlite3|dump|bak|old|backup|orig|copy|swp|sav|save)(\?|$)' all_historical_urls.txt | sort -u > urls_backup.txt
```

### Log Files

```bash
grep -Ei '\.(log|logs|out|err|error|debug|trace)(\?|$)' all_historical_urls.txt | sort -u > urls_logs.txt
```

### Source Code and Archives

```bash
grep -Ei '\.(zip|tar|tar\.gz|tgz|rar|7z|gz|bz2|war|jar|git|svn)(\?|$)' all_historical_urls.txt | sort -u > urls_archives.txt
```

### Sensitive Documents

```bash
grep -Ei '\.(xls|xlsx|csv|doc|docx|pdf|ppt|pptx|txt|md)(\?|$)' all_historical_urls.txt | sort -u > urls_documents.txt
```

### PHP / Server-Side Files (potential info disclosure)

```bash
grep -Ei '\.(php|asp|aspx|jsp|cgi|pl)(\?|$)' all_historical_urls.txt | sort -u > urls_serverside.txt
```

---

## Step 3: Filter by API Endpoints

Extract URLs that indicate API surfaces:

```bash
grep -Ei '/(api|v[0-9]+|graphql|rest|ws|websocket|rpc|soap|json-rpc)/' all_historical_urls.txt | sort -u > urls_api.txt
```

### Extract specific API versions (useful for finding deprecated versions)

```bash
grep -Ei '/v[0-9]+/' all_historical_urls.txt | sed 's|.*\(/v[0-9]\+/\).*|\1|' | sort -u > api_versions_found.txt
echo "API versions found:"
cat api_versions_found.txt
```

### GraphQL endpoints

```bash
grep -Ei 'graphql|/gql' all_historical_urls.txt | sort -u > urls_graphql.txt
```

---

## Step 4: Filter Admin/Internal Paths

Extract URLs suggesting internal or administrative functionality:

```bash
grep -Ei '/(admin|debug|internal|staging|test|dev|manage|dashboard|console|monitor|control|panel|portal|cms|backend|staff|operator|super|root|system|maintenance|setup|install|config|phpinfo|server-status|server-info|elmah|trace\.axd|__debug__|_debug_toolbar)' all_historical_urls.txt | sort -u > urls_admin_internal.txt
```

### Authentication-related paths

```bash
grep -Ei '/(login|logout|signin|signup|register|auth|oauth|sso|saml|forgot|reset|password|2fa|mfa|verify|activate|confirm|token|session|jwt)' all_historical_urls.txt | sort -u > urls_auth.txt
```

### File upload/download paths

```bash
grep -Ei '/(upload|download|file|attach|media|asset|static|resource|content|export|import|backup|restore)' all_historical_urls.txt | sort -u > urls_file_ops.txt
```

---

## Step 5: Deduplicate and Clean

### Remove duplicate query string variations (keep unique paths)

```bash
cat all_historical_urls.txt | sed 's/\?.*//' | sort -u > unique_paths.txt
wc -l unique_paths.txt
```

### Remove common static assets from the full list

```bash
grep -Evi '\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|webp|webm|avif)(\?|$)' all_historical_urls.txt | sort -u > urls_non_static.txt
```

---

## Step 6: Probe Live URLs

**Requires authorization for active probing.**

### Probe with httpx (status code + content length)

```bash
cat urls_non_static.txt | httpx -silent -sc -cl -o probed_urls.txt
```

### Filter by interesting status codes

```bash
# 200 OK — live and accessible
grep '\[200\]' probed_urls.txt > urls_200.txt

# 301/302 — redirects (may reveal internal routing)
grep -E '\[30[12]\]' probed_urls.txt > urls_redirects.txt

# 401/403 — protected but existing (high-value targets)
grep -E '\[40[13]\]' probed_urls.txt > urls_protected.txt

# 500 — server errors (potential for exploitation)
grep '\[500\]' probed_urls.txt > urls_errors.txt
```

### Probe only the high-value filtered URLs for faster results

```bash
cat urls_config.txt urls_backup.txt urls_logs.txt urls_admin_internal.txt urls_api.txt | sort -u | httpx -silent -sc -cl -o high_value_probed.txt
```

---

## Step 7: Parameter Mining

Extract unique parameter names from historical URLs:

```bash
cat all_historical_urls.txt | grep '?' | sed 's/.*?//' | tr '&' '\n' | sed 's/=.*//' | sort -u > historical_params.txt
wc -l historical_params.txt
echo "--- Top 30 most common parameters ---"
cat all_historical_urls.txt | grep '?' | sed 's/.*?//' | tr '&' '\n' | sed 's/=.*//' | sort | uniq -c | sort -rn | head -30
```

---

## Output Format (Shared State)

```json
{
  "historical_urls": {
    "target": "TARGET",
    "total_urls_found": 12847,
    "unique_paths": 3421,
    "categories": {
      "config_files": {"count": 23, "file": "urls_config.txt"},
      "backup_files": {"count": 8, "file": "urls_backup.txt"},
      "log_files": {"count": 5, "file": "urls_logs.txt"},
      "archives": {"count": 3, "file": "urls_archives.txt"},
      "api_endpoints": {"count": 156, "file": "urls_api.txt"},
      "admin_internal": {"count": 34, "file": "urls_admin_internal.txt"},
      "auth_paths": {"count": 18, "file": "urls_auth.txt"},
      "file_operations": {"count": 12, "file": "urls_file_ops.txt"}
    },
    "probing": {
      "live_200": {"count": 891, "file": "urls_200.txt"},
      "protected_401_403": {"count": 47, "file": "urls_protected.txt"},
      "errors_500": {"count": 12, "file": "urls_errors.txt"},
      "redirects": {"count": 234, "file": "urls_redirects.txt"}
    },
    "parameters_discovered": 287,
    "api_versions_found": ["v1", "v2", "v3"]
  }
}
```

Save to: `~/.claude/MEMORY/WORK/{current_work}/recon/historical_urls.json`

---

## Integration Notes

- **Protected paths (401/403)** are prime candidates for the Haddix recursive 401 technique — brute-force deeper paths under each 401 directory
- **Old API versions** (e.g., /v1/ when /v3/ is current) often lack security controls added in later versions
- **Backup/config files** should be checked immediately for sensitive data exposure
- **Historical parameters** feed into parameter fuzzing tools (Arjun, param-miner) for current endpoints
- **Server errors (500)** suggest fragile endpoints worth investigating for injection vulnerabilities
- Feed all discovered endpoints into the JS Analysis workflow if they serve JavaScript
