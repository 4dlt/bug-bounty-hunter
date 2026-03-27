# Security Payloads Database

Structured YAML payload database for bug bounty pentesting. Foundation referenced by all PAI attack skills.

## Structure

```
Payloads/
  README.md              # This file
  xss.yaml               # Cross-Site Scripting (26+ techniques, WAF bypasses)
  ssrf.yaml              # Server-Side Request Forgery (IP encodings, cloud metadata)
  sqli.yaml              # SQL Injection (per-database, 6 attack types)
  idor.yaml              # Insecure Direct Object Reference (16 bypass techniques)
  lfi.yaml               # Local File Inclusion (14 techniques, PHP wrappers)
  auth-bypass.yaml       # Authentication bypass (JWT, MFA, OAuth, sessions)
  business-logic.yaml    # Business logic flaws (9 categories)
  403-bypass.yaml        # 403 Forbidden bypass (headers, paths, methods)
  rate-limit-bypass.yaml # Rate limiting bypass (headers, IPs, paths)
  ssti.yaml              # Server-Side Template Injection (10 engines)
```

## YAML Format

Every file follows this structure:

```yaml
metadata:
  version: "1.0"
  sources:
    - "AllAboutBugBounty/daffainfo"
  last_updated: "2026-03-27"

category_name:
  - name: descriptive_name
    payload: "the actual payload"
    context: "where to use it"
    notes: "why this works"
```

## Usage

Load payloads programmatically:

```python
import yaml
with open("xss.yaml") as f:
    data = yaml.safe_load(f)
for p in data["html_body"]:
    print(p["payload"])
```

## WAF Coverage

XSS and SQLi files include provider-specific WAF bypasses for:
- Cloudflare
- Imperva / Incapsula
- AWS WAF
- CloudFront
- ModSecurity / OWASP CRS
- Akamai Kona

## Database Coverage

SQLi file includes per-database payloads for:
- MySQL / MariaDB
- PostgreSQL
- Microsoft SQL Server
- Oracle
- SQLite

## SSTI Engine Coverage

SSTI file includes detection and RCE payloads for:
- Jinja2 (Python)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- Smarty (PHP)
- Mako (Python)
- Pug/Jade (Node.js)
- ERB (Ruby)
- Handlebars (Node.js)
- Tornado (Python)
