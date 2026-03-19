---
name: ot-ics-assessment
description: "OT/ICS/SCADA focused threat assessment for industrial environments. Analyzes ICS exposure, OT-specific threat actors, and industrial protocol risks."
trigger: "OT security assessment, ICS threat analysis, SCADA exposure, industrial control systems, ot-ics-assessment"
---

# OT/ICS Assessment — Industrial Control Systems Threat Analysis

You are an OT/ICS cybersecurity specialist performing an industrial threat assessment.

## Input

Ask the user for:
1. **Company name** (required)
2. **Domain** (required)
3. **Sector** (optional — defaults to Manufacturing/Energy context)

## Phase 1: ICS Infrastructure Discovery

1. Run subdomain enumeration:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/subdomain_enum.py" --domain <DOMAIN> --max-results 100
```

2. Search subdomain results for ICS patterns: `scada`, `plc`, `hmi`, `ics`, `modbus`, `opc`, `dcs`, `rtu`, `historian`, `pi`, `factory`, `plant`, `production`, `mfg`, `ot-`, `ot.`

3. Reference OT protocol information:
```
Read file: ${CLAUDE_SKILL_DIR}/references/ot_protocols.md
```

## Phase 2: ICS Threat Intelligence

1. Get ICS-specific threat actors:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --ot
```

2. Get techniques for key ICS actors:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "Sandworm Team"
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "Dragonfly"
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "TEMP.Veles"
```

3. WebSearch for OT-specific intelligence:
   - `"[company] OT ICS SCADA security incident"`
   - `"Dragos [sector] ICS threat groups 2025 2026"`
   - `"ICS SCADA vulnerability [sector] 2025 2026"`
   - `"PIPEDREAM INCONTROLLER FrostyGoop ICS malware"`

## Phase 3: Report Generation

Generate an OT-focused report:

1. **Executive Summary** — OT risk level, key findings
2. **OT/ICS Attack Surface** — Discovered ICS subdomains, naming patterns, risk assessment
3. **ICS Protocol Exposure** — Map findings to Purdue model levels
4. **ICS Threat Actors** — Profiles of relevant OT threat groups:
   - Sandworm Team / ELECTRUM
   - Dragonfly / DYMALLOY
   - TEMP.Veles / XENOTIME
   - CHERNOVITE
   - KAMACITE
   - VOLTZITE
   - Volt Typhoon
5. **ICS Malware Intelligence** — Relevant malware families (TRITON, PIPEDREAM, FrostyGoop, etc.)
6. **MITRE ATT&CK for ICS Mapping** — Relevant ICS tactics and techniques
7. **OT Risk Assessment** — Risk matrix specific to OT environment
8. **Recommendations** — OT-specific mitigations (7/30/90 day)
9. **Detection Priorities** — OT-specific detection use cases
10. **FOFA Queries** — Pre-built queries for future ICS protocol scanning (if FOFA is configured)

Save to: `./reports/ot_threat_intelligence_<company_slug>.md`

Generate PDF:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/pdf_generator.py" --input "./reports/ot_threat_intelligence_<company_slug>.md" --output "./reports/ot_threat_intelligence_<company_slug>.pdf" --title "<Company> OT/ICS Threat Intelligence"
```
