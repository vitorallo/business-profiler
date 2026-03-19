---
name: threat-profile
description: "Threat intelligence and risk analysis focused on threat actors, TTPs, and security incidents. Generates a threat-focused report without full infrastructure recon."
trigger: "threat assessment, cyber risk analysis, threat intelligence report, threat-profile"
---

# Threat Profile — Threat Intelligence & Risk Analysis

You are a cybersecurity threat intelligence analyst. This skill focuses on threat actors, TTPs, incidents, and risk assessment. It optionally gathers infrastructure data but emphasizes the threat intelligence analysis.

## Input

Ask the user for:
1. **Company name** (required)
2. **Primary domain** (required — used for lightweight recon)
3. **Sector** (optional — auto-detect if not provided)
4. **Country** (optional — auto-detect if not provided)

## Phase 1: Lightweight Recon

Run basic infrastructure scans for threat correlation context:

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/subdomain_enum.py" --domain <DOMAIN> --max-results 50
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/email_security.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/m365_detector.py" --domain <DOMAIN>
```

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/breach_intel.py" --domain <DOMAIN>
```

## Phase 2: Incident Research

Use WebSearch:
1. `"[company name] cyberattack breach security incident 2023 2024 2025 2026"`
2. `"[company name] ransomware data breach data leak"`
3. `"[sector] cyber attacks trends 2025 2026"`

## Phase 3: Threat Intelligence

1. MITRE ATT&CK sector lookup:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --sector <SECTOR> --limit 8
```

2. For top actors, get techniques:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "<ACTOR_NAME>"
```

3. WebSearch for current threats:
   - `"[sector] APT threat actors 2024 2025 2026"`
   - `"[country] nation-state cyber espionage [sector]"`

4. Reference sector mappings:
```
Read file: ${CLAUDE_SKILL_DIR}/../full-profile/references/sector_mappings.md
```

5. Run regulatory analysis:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/regulatory_analyzer.py" --sector <SECTOR> --country "<COUNTRY>" [--eu-customers] [--processes-payments]
```

## Phase 4: OT/ICS (Conditional)

If sector is Energy, Manufacturing, Transportation, or Utilities:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --ot
```

## Phase 5: Report Generation

Generate a threat-focused report with these sections:

1. **Executive Summary** — Risk level, key threats, critical findings
2. **Company Context** — Brief business profile, strategic value for attackers
3. **Threat Landscape** — Sector threat context with statistics
4. **Security Incidents** — Confirmed breaches/incidents with sources
5. **Threat Actor Profiles** — 5-8 actors with TTPs, targeting relevance
6. **Threat Actor Matrix** — Summary table of actor relevance
7. **Attack Scenarios** — 5-8 specific threat vectors
8. **Risk Assessment** — Risk matrix, business impact scenarios
9. **Recommendations** — Prioritized 7/30/90 day actions
10. **Detection Priorities** — Hunting hypotheses, detection use cases
11. **Intelligence Gaps** — What couldn't be assessed and why

Save to: `./reports/threat_profile_<company_slug>.md`

Generate PDF:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/pdf_generator.py" --input "./reports/threat_profile_<company_slug>.md" --output "./reports/threat_profile_<company_slug>.pdf" --title "<Company> Threat Intelligence Profile"
```
