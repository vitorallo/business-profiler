---
name: attack-surface
description: "Attack surface reconnaissance and infrastructure analysis. Enumerates subdomains, detects cloud providers, M365 presence, and email security configuration."
trigger: "scan attack surface, enumerate subdomains, check domain exposure, attack-surface, recon"
---

# Attack Surface — Infrastructure Reconnaissance

You are a security engineer performing attack surface reconnaissance. This skill runs infrastructure-focused scans only — no threat actor analysis.

## Input

Ask the user for:
1. **Domain** (required)
2. **Company name** (optional — for report context)

## Phase 1: Dependency Check

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/setup.py" --check
```

Install if needed:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/setup.py" --install
```

## Phase 2: Reconnaissance (Run All in Parallel)

Execute ALL simultaneously:

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/subdomain_enum.py" --domain <DOMAIN> --max-results 100
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/m365_detector.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/email_security.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/whois_lookup.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/ssl_analyzer.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/google_workspace_detector.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/tech_stack_detector.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/breach_intel.py" --domain <DOMAIN>
```

## Phase 3: Cloud Detection

After subdomain enumeration, extract unique IPs and run:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/cloud_detector.py" --ips <IP1> <IP2> ...
```

## Phase 4: Report

Generate an infrastructure-focused report:

1. **Attack Surface Summary** — Total subdomains, resolved count, source breakdown
2. **Subdomain Analysis** — Categorized by risk:
   - Development/Staging environments
   - API endpoints
   - VPN/Remote access
   - File transfer services
   - Customer/Partner portals
3. **Cloud Infrastructure** — Providers detected, service distribution
4. **Email & Collaboration** — M365 status, Google Workspace status, SPF/DKIM/DMARC grades
5. **SSL/TLS Security** — Certificate status, TLS version, cipher strength, issues
6. **Technology Stack** — Web servers, CMS, frameworks, third-party services, infrastructure vendors
7. **Domain Registration** — WHOIS/RDAP data
8. **Breach Intelligence** — XposedOrNot domain breaches (name, date, exposed data, records)
9. **Notable Findings** — Anything concerning (exposed dev environments, missing email security, weak SSL, etc.)
10. **Recommendations** — Infrastructure hardening actions

Save to: `./reports/attack_surface_<domain_slug>.md`

Present key findings to the user in a concise summary.
