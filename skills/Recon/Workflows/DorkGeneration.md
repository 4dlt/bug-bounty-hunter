# Dork Generation Workflow

**Purpose:** Generate and execute targeted search dorks across Google, GitHub, and Shodan to discover exposed assets, leaked secrets, misconfigurations, and shadow IT for the target.

**Input:** Target domain and/or organization name
**Output:** Categorized dork lists with results for shared state
**Authorization:** Passive — uses only public search engines and indexed data

---

## Step 1: Google Dorks

### File Discovery Dorks

```
site:TARGET filetype:pdf
site:TARGET filetype:xls OR filetype:xlsx OR filetype:csv
site:TARGET filetype:doc OR filetype:docx
site:TARGET filetype:ppt OR filetype:pptx
site:TARGET filetype:sql
site:TARGET filetype:xml
site:TARGET filetype:json
site:TARGET filetype:conf OR filetype:cfg OR filetype:ini
site:TARGET filetype:log
site:TARGET filetype:bak OR filetype:old OR filetype:backup
site:TARGET filetype:env
site:TARGET filetype:key OR filetype:pem
```

### Sensitive Information Dorks

```
site:TARGET inurl:admin
site:TARGET inurl:login
site:TARGET inurl:dashboard
site:TARGET inurl:config
site:TARGET inurl:setup
site:TARGET inurl:debug
site:TARGET inurl:test
site:TARGET inurl:staging
site:TARGET intitle:"index of"
site:TARGET intitle:"directory listing"
site:TARGET inurl:wp-admin OR inurl:wp-login
site:TARGET inurl:phpinfo
```

### Error and Information Disclosure Dorks

```
site:TARGET "error" "warning" "mysql"
site:TARGET "Fatal error" "on line"
site:TARGET "sql syntax" OR "mysql_fetch"
site:TARGET "ORA-" "error"
site:TARGET "Server Error in" "Application"
site:TARGET "not for distribution" OR "confidential" OR "internal only"
site:TARGET "password" filetype:log
site:TARGET "username" "password" filetype:txt
```

### API and Developer Dorks

```
site:TARGET inurl:api
site:TARGET inurl:graphql
site:TARGET inurl:swagger OR inurl:api-docs OR inurl:openapi
site:TARGET "api_key" OR "apikey" OR "api-key"
site:TARGET inurl:token
site:TARGET inurl:oauth
```

### Cloud and Infrastructure Dorks

```
site:TARGET "s3.amazonaws.com"
site:TARGET "blob.core.windows.net"
site:TARGET "storage.googleapis.com"
site:TARGET inurl:jenkins
site:TARGET inurl:jira
site:TARGET inurl:confluence
```

### Third-Party Indexed Content

```
site:pastebin.com "TARGET"
site:trello.com "TARGET"
site:codepad.co "TARGET"
site:scribd.com "TARGET"
site:npmjs.com "TARGET"
site:stackoverflow.com "TARGET" "password" OR "api_key"
site:gist.github.com "TARGET"
```

### Execution

For automated Google dorking, use a tool or manual browser search. Rate-limit to avoid CAPTCHAs.

```bash
# Generate dork list file
cat << 'DORKEOF' > google_dorks.txt
site:TARGET filetype:pdf
site:TARGET filetype:xls OR filetype:xlsx
site:TARGET filetype:sql
site:TARGET filetype:xml
site:TARGET filetype:json
site:TARGET filetype:conf OR filetype:cfg
site:TARGET filetype:log
site:TARGET filetype:bak OR filetype:old
site:TARGET filetype:env
site:TARGET inurl:admin
site:TARGET inurl:login
site:TARGET inurl:config
site:TARGET inurl:debug
site:TARGET inurl:staging
site:TARGET intitle:"index of"
site:TARGET inurl:phpinfo
site:TARGET inurl:swagger OR inurl:api-docs
site:TARGET "api_key" OR "apikey"
site:TARGET "s3.amazonaws.com"
site:TARGET inurl:jenkins OR inurl:jira
DORKEOF

# Replace TARGET with actual domain
sed -i "s/TARGET/ACTUAL_DOMAIN/g" google_dorks.txt
```

---

## Step 2: GitHub Dorks

### Secret and Credential Searches

```
org:TARGET_ORG password
org:TARGET_ORG secret
org:TARGET_ORG api_key OR apikey OR api-key
org:TARGET_ORG token
org:TARGET_ORG AWS_ACCESS_KEY_ID OR AWS_SECRET_ACCESS_KEY
org:TARGET_ORG PRIVATE KEY
org:TARGET_ORG "jdbc:" OR "mysql://" OR "postgresql://"
org:TARGET_ORG "BEGIN RSA PRIVATE KEY"
org:TARGET_ORG "sk_live" OR "pk_live"
org:TARGET_ORG "AKIA"
```

### Configuration and Environment Files

```
org:TARGET_ORG filename:.env
org:TARGET_ORG filename:.env.production
org:TARGET_ORG filename:credentials
org:TARGET_ORG filename:config.json
org:TARGET_ORG filename:settings.py password
org:TARGET_ORG filename:wp-config.php
org:TARGET_ORG filename:database.yml
org:TARGET_ORG filename:.htpasswd
org:TARGET_ORG filename:id_rsa
org:TARGET_ORG filename:.npmrc _auth
```

### Domain-Specific Searches (use when org is unknown)

```
"TARGET_DOMAIN" password
"TARGET_DOMAIN" api_key
"TARGET_DOMAIN" secret
"TARGET_DOMAIN" token
"TARGET_DOMAIN" filename:.env
"TARGET_DOMAIN" "internal" OR "staging"
"TARGET_DOMAIN" "BEGIN RSA PRIVATE KEY"
"TARGET_DOMAIN" AWS_SECRET_ACCESS_KEY
"TARGET_DOMAIN" AKIA
"TARGET_DOMAIN" "jdbc:" OR "mysql://"
```

### Execution

```bash
# Using GitHub CLI (gh) for searching
gh search code "org:TARGET_ORG password" --limit 50
gh search code "org:TARGET_ORG api_key OR apikey" --limit 50
gh search code "org:TARGET_ORG filename:.env" --limit 50
gh search code "org:TARGET_ORG AWS_ACCESS_KEY_ID" --limit 50
gh search code "org:TARGET_ORG PRIVATE KEY" --limit 50

# Using GitHub web search URL format for manual review
echo "https://github.com/search?q=org%3ATARGET_ORG+password&type=code"
echo "https://github.com/search?q=org%3ATARGET_ORG+api_key&type=code"
echo "https://github.com/search?q=%22TARGET_DOMAIN%22+secret&type=code"
```

---

## Step 3: Shodan Dorks

### SSL Certificate Searches

```
ssl.cert.subject.cn:"TARGET_DOMAIN"
ssl.cert.subject.cn:"*.TARGET_DOMAIN"
ssl:"TARGET_ORG"
```

### Hostname Searches

```
hostname:"TARGET_DOMAIN"
hostname:"*.TARGET_DOMAIN"
```

### Organization Searches

```
org:"TARGET_ORG"
org:"TARGET_ORG" port:22
org:"TARGET_ORG" port:3389
org:"TARGET_ORG" port:8080 OR port:8443
org:"TARGET_ORG" "Server: Apache" OR "Server: nginx"
```

### Specific Service Searches

```
org:"TARGET_ORG" product:"elastic"
org:"TARGET_ORG" product:"mongodb"
org:"TARGET_ORG" product:"redis"
org:"TARGET_ORG" product:"jenkins"
org:"TARGET_ORG" "X-Jenkins"
org:"TARGET_ORG" http.title:"Dashboard"
```

### Execution

```bash
# Using Shodan CLI (requires API key)
shodan search "ssl.cert.subject.cn:TARGET_DOMAIN" --fields ip_str,port,org,hostnames
shodan search "hostname:TARGET_DOMAIN" --fields ip_str,port,org,hostnames
shodan search "org:TARGET_ORG" --fields ip_str,port,org,hostnames
shodan search "org:TARGET_ORG port:8080" --fields ip_str,port,http.title,http.server

# Count results first
shodan count "ssl.cert.subject.cn:TARGET_DOMAIN"
shodan count "org:TARGET_ORG"

# Download all results for offline analysis
shodan download target_results "ssl.cert.subject.cn:TARGET_DOMAIN"
shodan parse target_results.json.gz --fields ip_str,port,org,hostnames -o target_parsed.csv
```

---

## Step 4: Bonus Dork Sources

### Censys Dorks

```
services.tls.certificates.leaf.names: TARGET_DOMAIN
autonomous_system.name: "TARGET_ORG"
services.http.response.headers.server: * AND services.tls.certificates.leaf.names: TARGET_DOMAIN
```

### FOFA Dorks

```
domain="TARGET_DOMAIN"
cert="TARGET_ORG"
header="TARGET_DOMAIN"
```

### ZoomEye Dorks

```
site:TARGET_DOMAIN
ssl:"TARGET_DOMAIN"
organization:"TARGET_ORG"
```

---

## Step 5: Result Aggregation

Compile all findings into categorized output:

```bash
mkdir -p dork_results

# Save each category
# Google: manual or automated results
# GitHub: save gh search output
# Shodan: save parsed results

# Create summary
cat << 'EOF' > dork_results/summary.md
# Dork Results Summary — TARGET

## Google Dorks
- Total dorks run: X
- Interesting results: Y
- Notable findings: [list]

## GitHub Dorks
- Repositories with potential secrets: X
- Files with credentials: Y
- Notable findings: [list]

## Shodan Dorks
- Total hosts found: X
- Open management ports: Y
- Exposed databases: Z
- Notable findings: [list]

## Priority Follow-ups
1. [highest priority finding]
2. [second priority]
3. [third priority]
EOF
```

---

## Output Format (Shared State)

```json
{
  "dork_generation": {
    "target": "TARGET",
    "target_org": "TARGET_ORG",
    "google": {
      "dorks_run": 20,
      "results": {
        "exposed_files": [],
        "admin_panels": [],
        "api_docs": [],
        "info_disclosure": [],
        "third_party_leaks": []
      }
    },
    "github": {
      "dorks_run": 10,
      "results": {
        "credentials_found": [],
        "env_files": [],
        "config_files": [],
        "private_keys": []
      }
    },
    "shodan": {
      "dorks_run": 10,
      "results": {
        "hosts": [],
        "exposed_services": [],
        "management_ports": [],
        "databases": []
      }
    }
  }
}
```

Save to: `~/.claude/MEMORY/WORK/{current_work}/recon/dork_results.json`

---

## Integration Notes

- **Exposed API docs** (Swagger/OpenAPI) feed directly into API endpoint testing
- **GitHub secrets** should be verified for current validity immediately
- **Shodan-discovered hosts** feed into the NetblockRecon and IpRecon workflows
- **Admin panels** are high-priority targets for authentication testing
- **Indexed backup/config files** may contain database credentials, API keys, or internal architecture details
- Rate-limit all searches to avoid being blocked by search engines
- Google dorking is most effective when combined with historical URL mining (HistoricalUrls workflow)
