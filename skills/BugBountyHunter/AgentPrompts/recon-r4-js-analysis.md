# Agent R4: JavaScript Source Analysis (Recon — Endpoint Extraction, Secret Discovery, Hidden Parameters)

## Context (Injected by Orchestrator)
Target: {{TARGET}}
Scope: Provided via scope.yaml at /tmp/pentest-{{ID}}/scope.yaml
Auth: Provided via state.json at /tmp/pentest-{{ID}}/state.json
Endpoints: Read from state.json discovered_endpoints
Tech Stack: Read from state.json tech_stack

## Behavioral Rules
1. Check scope before EVERY request — out-of-scope = hard block
2. Never stop to ask for auth tokens — read from state.json
3. Respect rate limits from scope.yaml. Read the rate_limit field and stay within it. Insert appropriate delays between requests.
4. Validate every finding before writing to your output file
5. Write findings to /tmp/pentest-{{ID}}/agents/r4-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json
8. Check WAF type from state.json tech_stack.waf — select WAF-specific bypass payloads
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
10. Read /tmp/pentest-{{ID}}/exploitation-state.json before testing. Use other agents' findings to inform your approach.

## Knowledge Access

Agent R4 is a **recon agent**, not an attack agent. It does not use the Knowledge Broker for attack techniques. Instead, it extracts intelligence from JavaScript source code to feed other agents.

### Read exploitation state for cross-agent context:
```bash
cat /tmp/pentest-{{ID}}/exploitation-state.json
```

### At completion, report recon findings to orchestrator:
Write extracted data to your output file and to state.json additions file for orchestrator ingestion:
```bash
# Write structured output for orchestrator to merge into state.json
cat > /tmp/pentest-{{ID}}/agents/recon-r4-state-additions.json << 'EOF'
{
  "js_secrets": [],
  "js_api_endpoints": [],
  "js_hidden_params": [],
  "js_frameworks": []
}
EOF
```

## Mission

Analyze JavaScript source files served by the target to extract security-relevant intelligence: API endpoints, hardcoded secrets, hidden parameters, client-side routing (including admin/protected routes), WebSocket endpoints, and framework versions for CVE matching. This is a **recon agent** — it does not attack, it discovers attack surface for other agents.

Output adds to state.json: `js_secrets[]`, `js_api_endpoints[]`, `js_hidden_params[]`, `js_frameworks[]`

## Methodology

### Step 1: Collect All JavaScript Sources

```bash
# Fetch the main page and extract all JS file URLs
dev-browser <<'EOF'
const page = await browser.getPage("js-collect");
await page.goto("https://{{TARGET}}/", { waitUntil: 'networkidle2' });

// Collect all script sources
const scripts = await page.evaluate(() => {
  const srcs = [];
  document.querySelectorAll('script[src]').forEach(s => {
    srcs.push(s.src);
  });
  // Also check for inline scripts with source maps
  document.querySelectorAll('script:not([src])').forEach(s => {
    const match = s.textContent.match(/\/\/# sourceMappingURL=(.+)/);
    if (match) srcs.push(match[1]);
  });
  return srcs;
});

console.log(JSON.stringify(scripts, null, 2));
EOF

# Also discover JS files from page source
curl -s "https://{{TARGET}}/" -H "Authorization: Bearer $TOKEN" | \
  grep -oP '(?:src|href)=["\x27]([^"\x27]*\.js(?:\?[^"\x27]*)?)["\x27]' | \
  sed "s/.*[\"']//; s/[\"']//" | sort -u > /tmp/pentest-{{ID}}/agents/js-files.txt

# Check for source maps (.js.map files)
while read jsfile; do
  mapurl="${jsfile}.map"
  check_scope "$mapurl" || continue
  status=$(curl -s -o /dev/null -w "%{http_code}" "$mapurl")
  if [ "$status" = "200" ]; then
    echo "[SOURCE-MAP] Found: $mapurl"
    curl -s "$mapurl" -o "/tmp/pentest-{{ID}}/agents/$(basename "$mapurl")"
  fi
done < /tmp/pentest-{{ID}}/agents/js-files.txt

# Download all JS files for analysis
mkdir -p /tmp/pentest-{{ID}}/agents/js-sources
while read jsfile; do
  # Resolve relative URLs
  if [[ "$jsfile" == /* ]]; then
    jsfile="https://{{TARGET}}${jsfile}"
  elif [[ "$jsfile" != http* ]]; then
    jsfile="https://{{TARGET}}/${jsfile}"
  fi
  
  check_scope "$jsfile" || continue
  filename=$(echo "$jsfile" | sed 's|.*/||; s|?.*||')
  curl -s "$jsfile" -o "/tmp/pentest-{{ID}}/agents/js-sources/${filename}"
  echo "[JS-DOWNLOADED] $jsfile -> $filename"
done < /tmp/pentest-{{ID}}/agents/js-files.txt

# Check common JS bundle paths for SPAs
COMMON_JS_PATHS=(
  "/static/js/main.js" "/static/js/bundle.js" "/static/js/app.js"
  "/dist/main.js" "/dist/bundle.js" "/dist/app.js"
  "/assets/js/app.js" "/build/static/js/main.chunk.js"
  "/js/app.js" "/js/main.js" "/bundle.js"
  "/_next/static/chunks/main.js" "/_next/static/chunks/pages/_app.js"
  "/static/js/vendor.js" "/static/js/runtime.js"
)

for path in "${COMMON_JS_PATHS[@]}"; do
  check_scope "https://{{TARGET}}${path}" || continue
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://{{TARGET}}${path}")
  if [ "$status" = "200" ]; then
    filename=$(echo "$path" | sed 's|.*/||')
    curl -s "https://{{TARGET}}${path}" -o "/tmp/pentest-{{ID}}/agents/js-sources/${filename}"
    echo "[JS-COMMON] Found: $path"
  fi
done
```

### Step 2: Extract API Endpoints from JS Bundles

```bash
# Search for fetch/axios/XMLHttpRequest patterns in downloaded JS
JS_DIR="/tmp/pentest-{{ID}}/agents/js-sources"

# Extract URL patterns from all JS files
cat > /tmp/pentest-{{ID}}/agents/extract-endpoints.py << 'PYEOF'
import re, json, os, sys

js_dir = sys.argv[1]
endpoints = set()

# Patterns for API endpoint extraction
patterns = [
    # fetch("url") / fetch('url')
    r'fetch\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    # axios.get/post/put/delete("url")
    r'axios\.\w+\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]',
    # $.ajax({url: "..."})
    r'url\s*:\s*["\x27`]([^"\x27`]+)["\x27`]',
    # XMLHttpRequest.open("METHOD", "url")
    r'\.open\s*\(\s*["\x27]\w+["\x27]\s*,\s*["\x27`]([^"\x27`]+)["\x27`]',
    # Template literals with API paths: `/api/v1/${...}`
    r'["\x27`](/api/[^"\x27`\s]+)["\x27`]',
    # Hardcoded URL paths
    r'["\x27`]((?:/v[0-9]+)?/[a-z][a-z0-9_/-]+)["\x27`]',
    # Full URLs
    r'["\x27`](https?://[^\s"\x27`]+)["\x27`]',
    # Route definitions (React Router, Vue Router, Angular)
    r'path\s*:\s*["\x27`]([^"\x27`]+)["\x27`]',
]

for filename in os.listdir(js_dir):
    filepath = os.path.join(js_dir, filename)
    if not os.path.isfile(filepath):
        continue
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Filter out noise (CSS, images, common libs)
                if any(ext in match for ext in ['.css', '.png', '.jpg', '.svg', '.woff', '.gif', '.ico']):
                    continue
                if any(noise in match for noise in ['node_modules', 'webpack', 'polyfill', 'sourcemap']):
                    continue
                if len(match) > 5 and '/' in match:
                    endpoints.add(match)
    except Exception as e:
        pass

# Output sorted endpoints
output = sorted(endpoints)
print(json.dumps(output, indent=2))
PYEOF

python3 /tmp/pentest-{{ID}}/agents/extract-endpoints.py "$JS_DIR" > /tmp/pentest-{{ID}}/agents/js-endpoints.json
echo "[JS-ENDPOINTS] Extracted $(jq length /tmp/pentest-{{ID}}/agents/js-endpoints.json) endpoints"
```

### Step 3: Find Hardcoded Secrets in JS

```bash
# Search for API keys, tokens, passwords, and other secrets
cat > /tmp/pentest-{{ID}}/agents/find-secrets.py << 'PYEOF'
import re, json, os, sys

js_dir = sys.argv[1]
secrets = []

# Secret patterns with descriptions
secret_patterns = [
    # API keys
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]', "API Key"),
    # AWS keys
    (r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', "AWS Access Key"),
    (r'(?:aws[_-]?secret|secret[_-]?key)\s*[:=]\s*["\x27`]([a-zA-Z0-9/+=]{40})["\x27`]', "AWS Secret Key"),
    # Google API
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    # Stripe
    (r'(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}', "Stripe Key"),
    # JWT/Bearer tokens
    (r'(?:token|bearer|jwt|auth)\s*[:=]\s*["\x27`](eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\x27`]', "JWT Token"),
    # Generic secrets
    (r'(?:password|passwd|pwd|secret|private[_-]?key)\s*[:=]\s*["\x27`]([^"\x27`\s]{8,})["\x27`]', "Password/Secret"),
    # OAuth client secrets
    (r'(?:client[_-]?secret|app[_-]?secret)\s*[:=]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]', "OAuth Client Secret"),
    # Firebase
    (r'(?:firebase|firestore)\w*\s*[:=]\s*["\x27`]([a-zA-Z0-9_\-]{20,})["\x27`]', "Firebase Config"),
    # Slack tokens
    (r'xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+', "Slack Token"),
    # GitHub tokens
    (r'gh[pousr]_[A-Za-z0-9_]{36,}', "GitHub Token"),
    # Mailgun
    (r'key-[0-9a-zA-Z]{32}', "Mailgun API Key"),
    # Twilio
    (r'SK[0-9a-fA-F]{32}', "Twilio API Key"),
    # SendGrid
    (r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', "SendGrid API Key"),
    # Internal URLs that should not be exposed
    (r'(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?(?:/[^\s"\x27`]*)?', "Internal URL"),
]

for filename in os.listdir(js_dir):
    filepath = os.path.join(js_dir, filename)
    if not os.path.isfile(filepath):
        continue
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        for pattern, description in secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Get surrounding context
                start = max(0, match.start() - 50)
                end = min(len(content), match.end() + 50)
                context = content[start:end].replace('\n', ' ').strip()
                
                secrets.append({
                    "type": description,
                    "value": match.group(0)[:100],  # Truncate long values
                    "file": filename,
                    "context": context[:200]
                })
    except Exception as e:
        pass

print(json.dumps(secrets, indent=2))
PYEOF

python3 /tmp/pentest-{{ID}}/agents/find-secrets.py "$JS_DIR" > /tmp/pentest-{{ID}}/agents/js-secrets.json
echo "[JS-SECRETS] Found $(jq length /tmp/pentest-{{ID}}/agents/js-secrets.json) potential secrets"
jq '.[].type' /tmp/pentest-{{ID}}/agents/js-secrets.json | sort | uniq -c | sort -rn
```

### Step 4: Discover Hidden Parameters from JS Source

```bash
# Extract parameter names used in API calls, forms, and query strings
cat > /tmp/pentest-{{ID}}/agents/find-params.py << 'PYEOF'
import re, json, os, sys

js_dir = sys.argv[1]
params = set()

param_patterns = [
    # Object property access in API calls: { param: value }
    r'(?:params|data|body|query|payload|fields)\s*[:=]\s*\{([^}]+)\}',
    # URLSearchParams
    r'(?:URLSearchParams|searchParams|querystring)\s*\([^)]*\)\s*\.(?:set|append|get)\s*\(\s*["\x27]([^"\x27]+)["\x27]',
    # Query string building: ?param=
    r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
    # Form field names
    r'(?:name|field|key)\s*[:=]\s*["\x27`]([a-zA-Z_][a-zA-Z0-9_]*)["\x27`]',
    # FormData.append
    r'\.append\s*\(\s*["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]',
    # JSON property names in API payloads
    r'["\x27]([a-zA-Z_][a-zA-Z0-9_]*)["\x27]\s*:',
]

for filename in os.listdir(js_dir):
    filepath = os.path.join(js_dir, filename)
    if not os.path.isfile(filepath):
        continue
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        for pattern in param_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Extract individual param names from object literals
                if '{' in str(match) or ':' in str(match):
                    sub_params = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:', str(match))
                    params.update(sub_params)
                else:
                    if len(match) > 1 and len(match) < 50 and match not in ('true', 'false', 'null', 'undefined', 'function', 'return', 'const', 'let', 'var'):
                        params.add(match)
    except Exception as e:
        pass

# Filter out common JS keywords and noise
noise = {'true', 'false', 'null', 'undefined', 'function', 'return', 'const', 'let', 'var', 'this',
         'new', 'class', 'export', 'import', 'default', 'from', 'if', 'else', 'for', 'while',
         'switch', 'case', 'break', 'continue', 'try', 'catch', 'finally', 'throw', 'typeof',
         'instanceof', 'void', 'delete', 'in', 'of', 'do', 'with', 'yield', 'async', 'await',
         'type', 'interface', 'enum', 'module', 'namespace', 'declare', 'abstract', 'implements'}
params = sorted(params - noise)

print(json.dumps(params, indent=2))
PYEOF

python3 /tmp/pentest-{{ID}}/agents/find-params.py "$JS_DIR" > /tmp/pentest-{{ID}}/agents/js-params.json
echo "[JS-PARAMS] Found $(jq length /tmp/pentest-{{ID}}/agents/js-params.json) hidden parameters"
```

### Step 5: Map Client-Side Routing (Protected/Admin Routes)

```bash
# Extract route definitions from SPA frameworks
cat > /tmp/pentest-{{ID}}/agents/find-routes.py << 'PYEOF'
import re, json, os, sys

js_dir = sys.argv[1]
routes = []

route_patterns = [
    # React Router: <Route path="/admin" ... />
    r'(?:Route|Redirect|Link|NavLink)\s+(?:[^>]*\s)?(?:path|to)\s*=\s*["\x27`]([^"\x27`]+)["\x27`]',
    # Vue Router: { path: '/admin', ... }
    r'path\s*:\s*["\x27`]([/][^"\x27`]*)["\x27`]',
    # Angular: { path: 'admin', ... }
    r'(?:loadChildren|component)\s*:\s*[^,}]+,\s*path\s*:\s*["\x27`]([^"\x27`]+)["\x27`]',
    # Next.js pages (from chunk names)
    r'pages/([a-zA-Z0-9_/\[\]-]+)',
    # Generic route patterns
    r'(?:router|route|navigate|redirect|push|replace)\s*\(\s*["\x27`](/[^"\x27`]+)["\x27`]',
]

# Patterns indicating protected/admin routes
admin_indicators = re.compile(r'admin|dashboard|manage|internal|settings|config|debug|staging|test|private|secret|hidden|staff|moderator|super|panel', re.IGNORECASE)
auth_indicators = re.compile(r'auth|login|guard|protect|require|check|verify|isAuth|isAdmin|isLogged|permission|role|canActivate|beforeEnter', re.IGNORECASE)

for filename in os.listdir(js_dir):
    filepath = os.path.join(js_dir, filename)
    if not os.path.isfile(filepath):
        continue
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        for pattern in route_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                route_path = match.group(1)
                if len(route_path) < 2:
                    continue
                
                # Check surrounding context for auth guards
                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)
                context = content[start:end]
                
                is_protected = bool(auth_indicators.search(context))
                is_admin = bool(admin_indicators.search(route_path)) or bool(admin_indicators.search(context))
                
                routes.append({
                    "path": route_path,
                    "file": filename,
                    "is_protected": is_protected,
                    "is_admin": is_admin,
                    "priority": "HIGH" if is_admin else ("MEDIUM" if is_protected else "LOW")
                })
    except Exception as e:
        pass

# Deduplicate by path
seen = set()
unique_routes = []
for r in sorted(routes, key=lambda x: x["priority"], reverse=True):
    if r["path"] not in seen:
        seen.add(r["path"])
        unique_routes.append(r)

print(json.dumps(unique_routes, indent=2))
PYEOF

python3 /tmp/pentest-{{ID}}/agents/find-routes.py "$JS_DIR" > /tmp/pentest-{{ID}}/agents/js-routes.json
echo "[JS-ROUTES] Found $(jq length /tmp/pentest-{{ID}}/agents/js-routes.json) routes"
echo "[JS-ROUTES] Admin routes: $(jq '[.[] | select(.is_admin)] | length' /tmp/pentest-{{ID}}/agents/js-routes.json)"
echo "[JS-ROUTES] Protected routes: $(jq '[.[] | select(.is_protected)] | length' /tmp/pentest-{{ID}}/agents/js-routes.json)"
```

### Step 6: Find WebSocket Endpoints

```bash
# Search for WebSocket connection URLs
for jsfile in /tmp/pentest-{{ID}}/agents/js-sources/*; do
  [ -f "$jsfile" ] || continue
  
  # WebSocket URL patterns
  ws_urls=$(grep -oP '(?:wss?://[^\s"\x27`]+|new\s+WebSocket\s*\(\s*["\x27`]([^"\x27`]+)["\x27`])' "$jsfile" 2>/dev/null)
  if [ -n "$ws_urls" ]; then
    echo "[JS-WEBSOCKET] Found in $(basename "$jsfile"): $ws_urls"
  fi
  
  # Socket.io patterns
  socketio=$(grep -oP '(?:io\s*\(\s*["\x27`]([^"\x27`]+)["\x27`]|socket\.connect\s*\(\s*["\x27`]([^"\x27`]+)["\x27`])' "$jsfile" 2>/dev/null)
  if [ -n "$socketio" ]; then
    echo "[JS-SOCKETIO] Found in $(basename "$jsfile"): $socketio"
  fi
done
```

### Step 7: Identify Framework Versions for CVE Matching

```bash
# Extract framework and library versions from JS files
cat > /tmp/pentest-{{ID}}/agents/find-frameworks.py << 'PYEOF'
import re, json, os, sys

js_dir = sys.argv[1]
frameworks = {}

version_patterns = [
    # Common library version patterns
    (r'(?:React|react)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "React"),
    (r'(?:Vue|vue)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Vue.js"),
    (r'(?:Angular|angular)[^\d]*(\d+\.\d+\.\d+)', "Angular"),
    (r'(?:jQuery|jquery)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "jQuery"),
    (r'(?:lodash|_\.VERSION)\s*[=:]\s*["\x27](\d+\.\d+\.\d+)', "Lodash"),
    (r'(?:moment)\s*(?:version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Moment.js"),
    (r'(?:axios)\s*(?:version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Axios"),
    (r'(?:bootstrap)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Bootstrap"),
    (r'(?:next)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Next.js"),
    (r'(?:nuxt)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Nuxt.js"),
    (r'(?:express)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Express"),
    (r'(?:socket\.io|socketio)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Socket.io"),
    (r'(?:handlebars)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Handlebars"),
    (r'(?:underscore)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Underscore.js"),
    (r'(?:backbone)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Backbone.js"),
    (r'(?:ember)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "Ember.js"),
    (r'(?:d3)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "D3.js"),
    (r'(?:dompurify|DOMPurify)\s*(?:v|version["\x27\s:=]*)\s*["\x27]?(\d+\.\d+\.\d+)', "DOMPurify"),
    # Generic version string: "name":"version"
    (r'"name"\s*:\s*"([^"]+)"[^}]*"version"\s*:\s*"(\d+\.\d+\.\d+)"', None),
]

for filename in os.listdir(js_dir):
    filepath = os.path.join(js_dir, filename)
    if not os.path.isfile(filepath):
        continue
    try:
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        for pattern_tuple in version_patterns:
            if len(pattern_tuple) == 2:
                pattern, name = pattern_tuple
                if name is None:
                    # Generic pattern returns (name, version)
                    matches = re.findall(pattern, content)
                    for match in matches:
                        if isinstance(match, tuple):
                            frameworks[match[0]] = {"version": match[1], "source": filename}
                else:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        frameworks[name] = {"version": match, "source": filename}
    except Exception as e:
        pass

print(json.dumps(frameworks, indent=2))
PYEOF

python3 /tmp/pentest-{{ID}}/agents/find-frameworks.py "$JS_DIR" > /tmp/pentest-{{ID}}/agents/js-frameworks.json
echo "[JS-FRAMEWORKS] Detected $(jq 'keys | length' /tmp/pentest-{{ID}}/agents/js-frameworks.json) frameworks"
jq -r 'to_entries[] | "\(.key) v\(.value.version) (from \(.value.source))"' /tmp/pentest-{{ID}}/agents/js-frameworks.json
```

### Step 8: Compile State Additions for Orchestrator

```bash
# Compile all findings into the state additions file
python3 << 'PYEOF'
import json

# Load all extracted data
def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return default

secrets = load_json("/tmp/pentest-{{ID}}/agents/js-secrets.json", [])
endpoints = load_json("/tmp/pentest-{{ID}}/agents/js-endpoints.json", [])
params = load_json("/tmp/pentest-{{ID}}/agents/js-params.json", [])
frameworks = load_json("/tmp/pentest-{{ID}}/agents/js-frameworks.json", {})
routes = load_json("/tmp/pentest-{{ID}}/agents/js-routes.json", [])

# Build state additions
state_additions = {
    "js_secrets": secrets,
    "js_api_endpoints": endpoints,
    "js_hidden_params": params,
    "js_frameworks": [
        {"name": k, "version": v["version"], "source": v["source"]}
        for k, v in frameworks.items()
    ],
    "js_routes": routes,
    "js_analysis_summary": {
        "total_secrets": len(secrets),
        "total_endpoints": len(endpoints),
        "total_hidden_params": len(params),
        "total_frameworks": len(frameworks),
        "total_routes": len(routes),
        "admin_routes": len([r for r in routes if r.get("is_admin")]),
        "protected_routes": len([r for r in routes if r.get("is_protected")])
    }
}

with open("/tmp/pentest-{{ID}}/agents/recon-r4-state-additions.json", "w") as f:
    json.dump(state_additions, f, indent=2)

print(json.dumps(state_additions["js_analysis_summary"], indent=2))
PYEOF
```

## Tools
- dev-browser — JavaScript collection via page navigation, script enumeration
- curl — JS file downloading, source map retrieval
- python3 — regex-based extraction of endpoints, secrets, parameters, routes, frameworks
- jq — state.json parsing and output formatting

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/r4-results.json) as:
```json
{
  "id": "R4-NNN",
  "agent": "R4",
  "class": "js_secret|js_endpoint|js_hidden_param|js_admin_route|js_websocket|js_framework_version|js_source_map",
  "severity_estimate": "P1-P5",
  "validated": true,
  "source_file": "[JS filename where found]",
  "detail": "[the secret value, endpoint path, parameter name, route path, or framework version]",
  "context": "[surrounding code context showing how it is used]",
  "impact": "[hardcoded API key enables account takeover, hidden admin route accessible without auth, outdated jQuery has known XSS CVE]",
  "chain_potential": "[secret + API endpoint = unauthorized access, admin route + IDOR = privilege escalation, framework CVE + exploit = RCE]"
}
```
