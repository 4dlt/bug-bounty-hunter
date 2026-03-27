---
name: TechniqueFetcher
description: Pulls fresh attack intelligence before a pentest engagement — latest nuclei templates, disclosed HackerOne/Bugcrowd reports, CVEs for identified software, and recent bypass techniques. Called by BugBountyHunter orchestrator before Phase 2 attack agents launch.
---

## Purpose

Static skills miss new vulnerabilities. This module fetches the latest attack intelligence for a specific target's tech stack before testing begins. It bridges the gap between "what the skills know" and "what's been discovered this week."

## When to Use

- Before launching attack agents in BugBountyHunter Phase 2
- When you know the target's tech stack (framework, server, WAF, CMS)
- When you have a specific program name on HackerOne/Bugcrowd

## Workflow

### Step 1: Update Nuclei Templates

```bash
# Update to latest templates
nuclei -update-templates

# List templates matching detected tech stack
nuclei -tl -tags {{FRAMEWORK}} | head -30
nuclei -tl -tags {{SERVER}} | head -30
nuclei -tl -tags {{CMS}} | head -30

# Check for new templates added in last 30 days
nuclei -tl -tags cve | grep 2026 | head -20
```

### Step 2: Search Disclosed Reports for Target Program

Use WebSearch to find disclosed vulnerability reports:

```
Search: site:hackerone.com/reports "{{PROGRAM_NAME}}" disclosed
Search: site:bugcrowd.com "{{TARGET_DOMAIN}}" vulnerability
Search: "{{TARGET_DOMAIN}}" vulnerability disclosure bounty
```

Extract from disclosed reports:
- What vulnerability types were found before
- Which endpoints were vulnerable
- What techniques/payloads worked
- What the program considers high-severity

### Step 3: CVE Lookup for Identified Software

For each identified software version from recon:

```
Search: CVE {{SOFTWARE}} {{VERSION}} exploit 2025 OR 2026
Search: {{SOFTWARE}} {{VERSION}} security advisory
Search: {{SOFTWARE}} {{VERSION}} nuclei template
```

Check if nuclei has templates:
```bash
nuclei -tl -tags {{SOFTWARE}} | grep -i "{{VERSION_MAJOR}}"
```

### Step 4: Fresh Bypass Techniques

Search for latest bypass techniques relevant to detected WAF and framework:

```
Search: {{WAF}} bypass XSS 2025 OR 2026
Search: {{FRAMEWORK}} authentication bypass 2025 OR 2026
Search: {{FRAMEWORK}} SSTI payload 2026
Search: {{WAF}} WAF bypass techniques latest
```

### Step 5: Check Recent Security Research

```
Search: site:portswigger.net/research 2026
Search: site:labs.detectify.com 2026
Search: "bug bounty" "new technique" 2026
```

## Output Format

Return structured intelligence to the orchestrator:

```json
{
  "nuclei_templates": {
    "total_matching": 45,
    "high_priority": ["CVE-2026-XXXX", "CVE-2025-YYYY"],
    "tags_to_run": ["django", "nginx", "cloudflare"]
  },
  "disclosed_reports": [
    {
      "url": "https://hackerone.com/reports/XXXXXX",
      "vuln_type": "SSRF",
      "endpoint": "/api/webhook",
      "technique": "DNS rebinding",
      "severity": "critical",
      "bounty": "$15,000"
    }
  ],
  "cves": [
    {
      "id": "CVE-2026-XXXX",
      "software": "Django 4.2",
      "description": "...",
      "nuclei_template": true,
      "exploit_available": true
    }
  ],
  "fresh_techniques": [
    {
      "technique": "Cloudflare XSS bypass via mutation XSS",
      "source": "PortSwigger Research",
      "applicable_to": "cloudflare WAF",
      "payload": "..."
    }
  ]
}
```

## Integration with BugBountyHunter

The orchestrator calls this module after Phase 1 recon completes (tech stack known) and before Phase 2 attack agents launch. The output is injected into attack agent prompts so they test the most relevant and current attack vectors.

## Key Principle

Fresh intelligence > stale methodology. A CVE from last week that matches the target's exact software version is worth more than 100 generic test cases.
