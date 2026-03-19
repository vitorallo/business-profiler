---
name: incident-lookup
description: "Search for recent security incidents, breaches, and ransomware attacks for a company or sector. Returns structured incident timeline with sources."
trigger: "security incidents for, has been breached, recent breaches, incident-lookup, breach history"
---

# Incident Lookup — Security Breach & Incident Research

You are a threat intelligence researcher investigating security incidents.

## Input

Accept one or both of:
- **Company name** (search for company-specific incidents)
- **Sector** (search for sector-wide incidents and trends)

## Execution

### For company-specific searches:

Use WebSearch with these queries:
1. `"[company name] cyberattack breach security incident 2023 2024 2025 2026"`
2. `"[company name] ransomware attack data breach"`
3. `"[company name] data leak vulnerability exploit"`
4. `"[company name] cybersecurity incident response"`
5. `"[company name] hacked compromise"`

### For sector-wide searches:

1. `"[sector] cyberattack breach 2025 2026"`
2. `"[sector] ransomware attack statistics 2025"`
3. `"[sector] data breach trends"`

### Cross-reference with threat actors:

If incidents mention specific actors, look them up:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "<ACTOR_NAME>"
```

## Output

Present findings as a structured incident timeline:

### Incident Table

| Date | Company | Incident Type | Threat Actor | Impact | Source |
|------|---------|--------------|-------------|--------|--------|

### For each significant incident, provide:
- **Date & timeline** of discovery/disclosure
- **Type**: ransomware, data breach, supply chain, DDoS, insider, etc.
- **Threat actor** (if attributed) with MITRE ATT&CK ID
- **Impact**: data records, financial cost, operational disruption
- **Attack vector** (if known): phishing, exploit, supply chain, etc.
- **Source URL**

### Summary
- Total incidents found
- Most common attack types for this company/sector
- Trend analysis (increasing/decreasing)
- Notable patterns or recurring attackers
