# Threat & Attack Surface Assessment Methodology

## Overview

This methodology produces a comprehensive threat intelligence and attack surface assessment. The workflow has 6 phases executed in order, with parallel execution within phases where possible.

---

## Phase 1: Input & Validation

Gather and validate:
- **Company name** (legal entity name)
- **Primary domain** (e.g., shell.com)
- **Sector** (auto-detect via WebSearch if not provided)
- **Country** (headquarters location)
- **OT/ICS relevance** (auto-detect from sector: Energy, Manufacturing, Transportation, Utilities)

---

## Phase 2: Reconnaissance (Parallel Execution)

Run ALL of these in parallel using Bash tool:

1. **Subdomain Enumeration** — `python scripts/subdomain_enum.py --domain <domain>`
   - Sources: crt.sh, HackerTarget, AlienVault OTX
   - Identifies: dev/test environments, API endpoints, VPN gateways, portals

2. **Cloud Detection** — `python scripts/cloud_detector.py --ips <ip1> <ip2> ...`
   - Extract unique IPs from subdomain results
   - Identifies: AWS, Azure, GCP, Cloudflare, Akamai, etc.

3. **M365 Detection** — `python scripts/m365_detector.py --domain <domain>`
   - Methods: MX records, GetCredentialType API, OpenID config
   - Identifies: tenant ID, federation status

4. **Email Security** — `python scripts/email_security.py --domain <domain>`
   - Checks: SPF, DKIM, DMARC records
   - Grades each mechanism

5. **WHOIS** — `python scripts/whois_lookup.py --domain <domain>`
   - Via RDAP protocol (free)
   - Identifies: registrar, dates, nameservers

---

## Phase 3: Incident Research

Use WebSearch to find:
- `"[company] cyberattack breach security incident 2023 2024 2025 2026"`
- `"[company] ransomware data breach data leak"`
- `"[company] cybersecurity vulnerability exploit"`

Document each incident with: date, type, actor (if known), impact, source URL.

---

## Phase 4: Threat Intelligence

1. **MITRE ATT&CK Lookup** — `python scripts/mitre_client.py --sector <sector>`
   - Get threat actors targeting the sector
   - For each actor: `python scripts/mitre_client.py --actor <name>` for TTPs

2. **WebSearch for Current Threats**:
   - `"[sector] cyber threat actors APT 2024 2025 2026"`
   - `"[country] nation-state cyber espionage [sector]"`
   - `"[sector] ransomware trends 2025 2026"`

3. **Threat Actor Selection Criteria**:
   - Nation-state actors: match by target country AND sector
   - eCrime/ransomware: match by sector targeting patterns
   - Include 5-8 actors minimum for comprehensive coverage

---

## Phase 5: OT/ICS Assessment (Conditional)

Trigger: sector is Energy, Manufacturing, Transportation, Utilities, or ICS-related subdomains detected.

1. **ICS Subdomain Patterns** — search recon results for: scada, plc, hmi, ics, modbus, opc, dcs, rtu
2. **ICS Threat Actors** — `python scripts/mitre_client.py --ot`
3. **WebSearch**: `"[company] OT ICS SCADA security"`, `"Dragos [sector] ICS threat groups 2025"`
4. **Protocol Exposure** — reference ot_protocols.md for port/protocol mapping

---

## Phase 6: Analysis & Report Generation

Claude synthesizes all gathered data into the report following report_template.md:

### Risk Scoring Criteria

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Active nation-state targeting + Confirmed breaches + Critical infrastructure |
| **HIGH** | Nation-state interest + Large attack surface + Sector under active targeting |
| **MEDIUM** | Standard threat landscape + Moderate attack surface + No confirmed incidents |
| **LOW** | Limited exposure + Strong security posture + Low strategic value |

### Analysis Requirements
- Correlate threat actors with discovered infrastructure (which TTPs apply to which attack surface elements)
- Map attack scenarios to specific subdomains/services found
- Provide actionable recommendations with priority and timeline
- Include MITRE ATT&CK technique IDs throughout
- Cite all sources with URLs

### Quality Checklist
- [ ] All recon data incorporated (subdomains, cloud, M365, email security, WHOIS)
- [ ] 5-8 threat actors profiled with TTPs
- [ ] Security incidents documented with sources
- [ ] Risk levels justified with evidence
- [ ] Recommendations are specific, actionable, and prioritized (7/30/90 day)
- [ ] MITRE ATT&CK techniques cited throughout
- [ ] No placeholder text remains
- [ ] Report is 15-20 pages when rendered as PDF
