---
name: full-profile
description: "Comprehensive cybersecurity threat intelligence and attack surface assessment. Generates a complete threat profile with infrastructure recon, threat actor analysis, risk assessment, and professional PDF report."
trigger: "full security profile, complete threat assessment, profile [company], comprehensive cyber assessment, full-profile"
---

# Full Security Profile — Comprehensive Orchestrator

You are a cybersecurity threat intelligence analyst performing a comprehensive threat assessment. You will execute a structured 6-phase workflow to produce a professional threat intelligence report.

## Input

Ask the user for (or extract from their message):
1. **Company name** (required)
2. **Primary domain** (required)
3. **Sector** (optional — auto-detect via WebSearch if not provided)
4. **Country** (optional — auto-detect via WebSearch if not provided)

If sector/country are not provided, use WebSearch: `"[company name] industry sector headquarters"` to determine them.

## Phase 1: Dependency Check

Run once at the start:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/setup.py" --check
```

If dependencies are missing, install them:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/setup.py" --install
```

## Phase 2: Reconnaissance (Run in Parallel)

Execute ALL of these simultaneously using the Bash tool:

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

After subdomain enumeration completes, extract unique IP addresses from resolved subdomains and run:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/cloud_detector.py" --ips <IP1> <IP2> <IP3> ...
```

## Phase 2.5: Business Intelligence

Run after Phase 2 completes:

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/wikidata_search.py" --company "<COMPANY_NAME>" --country "<COUNTRY>"
```

Use the Wikidata output (employees, revenue, industries) to enrich the company profile and feed into Phase 4 financial estimation.

## Phase 3: Incident Research

Use WebSearch to find recent security incidents:

1. `"[company name] cyberattack breach security incident 2023 2024 2025 2026"`
2. `"[company name] ransomware data breach data leak"`
3. `"[company name] cybersecurity vulnerability exploit"`

Document each incident: date, type, actor (if known), impact, source URL.

## Phase 4: Threat Intelligence

1. Run MITRE ATT&CK lookup:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --sector <SECTOR> --limit 8
```

2. For the top 5-8 actors, get their techniques:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "<ACTOR_NAME>"
```

3. Use WebSearch for current threat landscape:
   - `"[sector] cyber threat actors APT 2024 2025 2026"`
   - `"[country] nation-state cyber espionage [sector]"`
   - `"[sector] ransomware attack trends 2025 2026"`

4. Read sector data for additional context:
```
Read file: ${CLAUDE_SKILL_DIR}/references/sector_mappings.md
```

5. Run regulatory analysis (use sector and country from input, add flags based on company context):
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/regulatory_analyzer.py" --sector <SECTOR> --country "<COUNTRY>" [--eu-customers] [--processes-payments] [--cloud-provider] [--defense-contractor]
```

6. Run financial estimation (use revenue/employees from Wikidata if available):
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/financial_estimator.py" --sector <SECTOR> [--revenue "<REVENUE>"] [--employees <COUNT>] [--risk-level <LEVEL>] [--incidents <N>] [--compliance]
```

7. If tech_stack_detector found technologies, run CISA KEV matching against them:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/breach_intel.py" --domain <DOMAIN> --kev --tech-products '<COMMA_SEPARATED_TECH_NAMES>'
```
Use the technology names from tech_stack_detector output (e.g., `nginx,wordpress,php,jquery`).

## Phase 5: OT/ICS Assessment (Conditional)

**Only execute if** the sector is Energy, Manufacturing, Transportation, or Utilities, OR if ICS-related subdomains were found in Phase 2 (patterns: scada, plc, hmi, ics, modbus, opc, dcs, rtu).

1. Run ICS actor lookup:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --ot
```

2. Search ICS subdomains in recon results for patterns listed above.

3. WebSearch: `"[company] OT ICS SCADA security"`, `"Dragos [sector] ICS threat 2025 2026"`

4. Reference OT protocols:
```
Read file: ${CLAUDE_SKILL_DIR}/../../skills/ot-ics-assessment/references/ot_protocols.md
```

## Phase 6: Report Generation

Read the report template and methodology:
```
Read file: ${CLAUDE_SKILL_DIR}/references/report_template.md
Read file: ${CLAUDE_SKILL_DIR}/references/methodology.md
```

### Synthesize all data into a comprehensive report following report_template.md exactly.

**Critical requirements:**
- Correlate threat actors with discovered infrastructure (which TTPs map to which attack surface elements)
- Include ALL recon data (subdomains, cloud, M365, Google Workspace, email security, WHOIS, SSL/TLS, tech stack)
- Include breach intelligence (XposedOrNot breaches, CISA KEV matches)
- Include regulatory context and financial estimates
- Enrich company profile with Wikidata data (employees, revenue, industries)
- Profile 5-8 threat actors with full TTP tables
- Provide risk scoring with justification
- Recommendations must be specific, actionable, prioritized (7/30/90 day)
- Cite MITRE ATT&CK technique IDs throughout
- Include source URLs for all external intelligence
- Target: 15-20 pages when rendered as PDF

### Save the report:
Write the complete markdown report to: `./reports/threat_attack_surface_<company_slug>.md`

### Generate PDF:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/pdf_generator.py" --input "./reports/threat_attack_surface_<company_slug>.md" --output "./reports/threat_attack_surface_<company_slug>.pdf" --title "<Company Name> Threat Intelligence Profile"
```

## Output

Tell the user:
1. Report location (markdown + PDF paths)
2. Key findings summary (3-5 bullets)
3. Overall risk level with brief justification
4. Top 3 immediate action items
