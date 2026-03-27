# JS Analysis Workflow

**Purpose:** Extract endpoints, secrets, and hidden parameters from JavaScript files discovered on the target.

**Input:** Target domain or list of URLs
**Output:** Categorized lists of endpoints, secrets, and parameters for shared state
**Authorization:** Passive analysis of publicly served JS files; no active exploitation

---

## Step 1: Crawl Target for JS Files

Use katana to spider the target and extract all JavaScript file URLs:

```bash
katana -u https://TARGET -jc -d 3 -ef css,png,jpg,gif,svg,woff,woff2,ttf,eot,ico -o js_urls_raw.txt
```

**Flags:**
- `-jc` — Enable JavaScript crawling (headless browser parsing)
- `-d 3` — Crawl depth of 3 levels
- `-ef` — Exclude non-JS static file extensions to reduce noise

Filter to only `.js` files:

```bash
grep '\.js$\|\.js?' js_urls_raw.txt | sort -u > js_urls.txt
```

**Alternative: Manual discovery with waybackurls + gau:**

```bash
echo TARGET | gau --threads 5 | grep '\.js$\|\.js?' | sort -u >> js_urls.txt
echo TARGET | waybackurls | grep '\.js$\|\.js?' | sort -u >> js_urls.txt
sort -u -o js_urls.txt js_urls.txt
```

**Alternative: Using httpx to probe and filter:**

```bash
cat js_urls.txt | httpx -silent -sc -mc 200 -o js_urls_live.txt
```

---

## Step 2: Download JS Files

```bash
mkdir -p js_files
while IFS= read -r url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sL "$url" -o "js_files/$filename"
  echo "$url -> $filename" >> js_file_map.txt
done < js_urls.txt
```

For large-scale downloads:

```bash
cat js_urls.txt | xargs -P 10 -I {} sh -c 'curl -sL "{}" -o "js_files/$(echo "{}" | md5sum | cut -d" " -f1).js"'
```

---

## Step 3: Extract Endpoints

### 3a: Absolute URLs

Pattern: `/(https?:\/\/[^\s"'<>]+)/g`

```bash
grep -rEoh 'https?://[^"'"'"' <>\\]+' js_files/ | sort -u > endpoints_absolute.txt
```

### 3b: Relative Paths

Pattern: `/["'](\/[a-zA-Z0-9_\-\/\.]+)["']/g`

```bash
grep -rEoh '["'"'"'](/[a-zA-Z0-9_\-/\.]+)["'"'"']' js_files/ | sed "s/[\"']//g" | sort -u > endpoints_relative.txt
```

### 3c: API Paths

Pattern: matches paths containing `/api/`, `/v1/`, `/v2/`, `/v3/`, `/graphql`, `/rest/`, `/ws/`

```bash
grep -rEoh '["'"'"'](/[^"'"'"']*(?:api|v[0-9]+|graphql|rest|ws)[^"'"'"']*)["'"'"']' js_files/ | sed "s/[\"']//g" | sort -u > endpoints_api.txt
```

**Alternative combined extraction with broader regex:**

```bash
grep -rEoh '["'"'"'][a-zA-Z0-9]*://[^"'"'"' <>]+["'"'"']' js_files/ | sed "s/[\"']//g" | sort -u >> endpoints_absolute.txt
grep -rEoh '["'"'"']/[a-zA-Z0-9_/\.\-]+["'"'"']' js_files/ | sed "s/[\"']//g" | sort -u >> endpoints_relative.txt
```

---

## Step 4: Extract Secrets

Run these regex patterns against all downloaded JS files:

### Google API Key
Pattern: `/['"](AIza[0-9A-Za-z\-_]{35})['"]/`

```bash
grep -rEoh "AIza[0-9A-Za-z\-_]{35}" js_files/ | sort -u > secrets_google_api.txt
```

### AWS Access Key
Pattern: `/['"](AKIA[0-9A-Z]{16})['"]/`

```bash
grep -rEoh "AKIA[0-9A-Z]{16}" js_files/ | sort -u > secrets_aws_key.txt
```

### AWS Secret Key (often near access key)
```bash
grep -rEoh "['\"][0-9a-zA-Z/+]{40}['\"]" js_files/ | sort -u > secrets_aws_secret_candidates.txt
```

### Passwords
Pattern: `/password\s*[:=]\s*['"]([^'"]+)['"]/i`

```bash
grep -rEioh "password\s*[:=]\s*['\"][^'\"]+['\"]" js_files/ | sort -u > secrets_passwords.txt
```

### Generic API Keys
Pattern: `/api[_-]?key\s*[:=]\s*['"]([^'"]+)['"]/i`

```bash
grep -rEioh "api[_\-]?key\s*[:=]\s*['\"][^'\"]+['\"]" js_files/ | sort -u > secrets_api_keys.txt
```

### Bearer Tokens / Authorization Headers
```bash
grep -rEioh "bearer\s+[a-zA-Z0-9\-_\.]+|authorization\s*[:=]\s*['\"][^'\"]+['\"]" js_files/ | sort -u > secrets_tokens.txt
```

### Private Keys
```bash
grep -rl "BEGIN.*PRIVATE KEY" js_files/ > secrets_private_keys_files.txt
```

### Slack Tokens
```bash
grep -rEoh "xox[baprs]-[0-9a-zA-Z\-]+" js_files/ | sort -u > secrets_slack.txt
```

### GitHub Tokens
```bash
grep -rEoh "gh[pousr]_[A-Za-z0-9_]{36,}" js_files/ | sort -u > secrets_github.txt
```

### Stripe Keys
```bash
grep -rEoh "sk_live_[0-9a-zA-Z]{24,}" js_files/ | sort -u > secrets_stripe.txt
```

### JWT Tokens
```bash
grep -rEoh "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_\-]+" js_files/ | sort -u > secrets_jwt.txt
```

### Combined secrets scan:

```bash
cat secrets_*.txt | sort -u > all_secrets.txt
wc -l all_secrets.txt
```

---

## Step 5: Extract Hidden Parameters

### Variable assignments that suggest parameter names:

```bash
grep -rEoh "['\"]([a-zA-Z_][a-zA-Z0-9_]*)['\"]:\s*['\"]" js_files/ | sed "s/['\"]//g;s/://g" | sort -u > params_from_objects.txt
```

### URL query parameters:

```bash
grep -rEoh '[?&]([a-zA-Z_][a-zA-Z0-9_]*)=' js_files/ | sed 's/[?&]//;s/=//' | sort -u > params_from_urls.txt
```

### Form field names:

```bash
grep -rEioh 'name\s*=\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]' js_files/ | sed "s/name\s*=\s*//i;s/[\"']//g" | sort -u > params_from_forms.txt
```

### Fetch/XMLHttpRequest bodies:

```bash
grep -rEioh "\"(id|user_id|token|auth|session|key|secret|password|email|username|admin|role|type|status|action|callback|redirect|url|path|file|upload|download|search|query|filter|sort|page|limit|offset)[\"']" js_files/ | sed "s/[\"']//g" | sort -u > params_interesting.txt
```

### Combine all parameters:

```bash
cat params_*.txt | sort -u > all_parameters.txt
wc -l all_parameters.txt
```

---

## Step 6: Identify Internal/Debug Endpoints

Look for paths that suggest internal or debug functionality:

```bash
grep -rEioh '["'"'"'](/[^"'"'"']*(?:admin|debug|internal|staging|test|dev|config|manage|dashboard|console|monitor|health|status|metrics|trace|log|backup|dump|export|import)[^"'"'"']*)["'"'"']' js_files/ | sed "s/[\"']//g" | sort -u > endpoints_internal.txt
```

---

## Step 7: Source Map Detection

Check for source maps that may expose original source code:

```bash
grep -roh '//# sourceMappingURL=.*' js_files/ | sort -u > sourcemaps.txt
```

For each source map URL found, attempt retrieval:

```bash
while IFS= read -r line; do
  map_url=$(echo "$line" | sed 's/.*sourceMappingURL=//')
  echo "Checking: $map_url"
  curl -sI "$map_url" | head -5
done < sourcemaps.txt
```

---

## Output Format (Shared State)

Produce a consolidated JSON summary for injection into shared state:

```json
{
  "js_analysis": {
    "target": "TARGET",
    "js_files_found": 42,
    "endpoints": {
      "absolute": ["https://api.target.com/v2/users", "..."],
      "relative": ["/api/v1/auth", "/internal/config", "..."],
      "api": ["/graphql", "/api/v2/payments", "..."],
      "internal": ["/admin/dashboard", "/debug/trace", "..."]
    },
    "secrets": {
      "google_api_keys": [],
      "aws_keys": [],
      "passwords": [],
      "api_keys": [],
      "tokens": [],
      "jwt": [],
      "other": []
    },
    "parameters": {
      "from_objects": ["user_id", "token", "..."],
      "from_urls": ["page", "limit", "search", "..."],
      "interesting": ["admin", "role", "redirect", "..."]
    },
    "source_maps": ["https://target.com/app.js.map"]
  }
}
```

Save to: `~/.claude/MEMORY/WORK/{current_work}/recon/js_analysis.json`

---

## Integration Notes

- **Feed endpoints into ffuf** for path brute-forcing (especially relative paths and API endpoints)
- **Feed parameters into Arjun/param-miner** for hidden parameter discovery on live endpoints
- **Feed secrets into manual verification** — validate each secret for active use
- **Source maps** can be unpacked with `source-map-explorer` or manually to recover original source code
- **Internal endpoints** are high-priority targets for the attack phase
