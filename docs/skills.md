# Skills Guide

Each skill is a slash command that tells Claude which scripts to run and how to assemble the output. The logic lives in SKILL.md files.

## full-profile

**Command:** `/business-profiler:full-profile <company> <domain> [sector] [country]`

The full pipeline. Runs all 6 phases:

1. **Dependency check** — ensures all Python packages are installed
2. **Reconnaissance** (parallel) — subdomains, M365, Google Workspace, email security, WHOIS, SSL/TLS, tech stack, breach intel
3. **Business intelligence** — Wikidata company data (employees, revenue, industries)
4. **Cloud detection** — ASN-based cloud provider identification from subdomain IPs
5. **Threat intelligence** — MITRE ATT&CK actors + techniques, regulatory analysis, financial estimation, CISA KEV matching, WebSearch for incidents and trends
6. **OT/ICS assessment** (conditional) — only if sector is Energy, Manufacturing, Transportation, or Utilities
7. **Report generation** — full Markdown report following the template, plus PDF

**Output:** `./reports/threat_attack_surface_<company>.md` + `.pdf` (15-20 pages)

**Example:**
```
/business-profiler:full-profile Shell shell.com Energy Netherlands
```

## threat-profile

**Command:** `/business-profiler:threat-profile <company> <domain> [sector] [country]`

Threat intelligence focused. Lightweight recon (50 subdomains max) combined with deep threat actor analysis, breach intelligence, incident research, and regulatory context.

**Phases:**
1. Lightweight recon (subdomains, email security, M365, breach intel)
2. Incident research via WebSearch
3. Threat intelligence (MITRE, regulatory analysis, WebSearch)
4. OT/ICS (conditional)
5. Report generation + PDF

**Output:** `./reports/threat_profile_<company>.md` + `.pdf`

## attack-surface

**Command:** `/business-profiler:attack-surface <domain> [company]`

Infrastructure-only reconnaissance. No threat actor analysis.

**Phases:**
1. Full recon (subdomains, M365, Google Workspace, email security, WHOIS, SSL/TLS, tech stack, breach intel)
2. Cloud detection
3. Infrastructure report (attack surface summary, subdomains by risk category, cloud, email, SSL, tech stack, breaches)

**Output:** `./reports/attack_surface_<domain>.md`

## threat-actors

**Command:** `/business-profiler:threat-actors <sector|actor_name|country>`

Quick MITRE ATT&CK lookup. Returns actor profiles, TTPs, and targeting relevance.

**Examples:**
```
/business-profiler:threat-actors Energy
/business-profiler:threat-actors "Sandworm Team"
/business-profiler:threat-actors Russia
```

## ot-ics-assessment

**Command:** `/business-profiler:ot-ics-assessment <company> <domain> [sector] [country]`

Specialized assessment for industrial control systems. Includes ICS-specific subdomain pattern matching (scada, plc, hmi, modbus, opc, dcs, rtu), OT threat actors, Purdue model mapping, and ICS malware intelligence.

**Output:** `./reports/ot_threat_intelligence_<company>.md`

## incident-lookup

**Command:** `/business-profiler:incident-lookup <company|sector>`

WebSearch-based breach and incident research. Returns a timeline of incidents with dates, types, actors, impact, and source URLs.

## sales-targeting

**Command:** `/business-profiler:sales-targeting <company> <domain> [sector] [country]`

Takes the same recon and threat data from `full-profile` and turns it into a sales report. Instead of "here are your vulnerabilities", the output is "here's why this company will buy from you, how much they can spend, and who to call first."

### Phases

1. **Input & data ingestion** — dependency check, auto-detect sector/country if not provided. Optionally ingest an existing threat report or client profile to skip redundant work.
2. **Threat & infrastructure intelligence** — full recon pipeline (same 8 parallel scripts as `full-profile`) + MITRE ATT&CK + incident research. **Skipped entirely** if an existing threat report path is provided.
3. **Business & financial intelligence** (parallel) — `wikidata_search.py`, `financial_estimator.py`, `regulatory_analyzer.py`, plus 5 WebSearch queries for financials, contacts, buyer intent, and regulatory posture.
4. **Enhanced contact intelligence** (optional) — LinkedIn, Sales Navigator, Crunchbase via browser automation tools. Skipped if no browser tools detected; WebSearch data used instead. See [Enhanced Mode](enhanced-mode.md).
5. **Analysis & scoring** — scores the account across 5 dimensions using the methodology reference, maps pain points to the 38-service catalog, calculates 3-year revenue opportunity, classifies the account.
6. **Report generation** — 6-part report following the template reference, plus PDF.

### Report Structure

The output is a 6-part Strategic Account Targeting Report:

| Part | Title | Content |
|------|-------|---------|
| Executive Summary | — | Account classification, 3-year opportunity, Perfect Storm convergence table |
| I | **The Opportunity** | Financial intelligence, market position, investment capacity |
| II | **The Pain** | Security incidents, attack surface exposure, threat actor targeting |
| III | **The Deadline** | Regulatory pressure, compliance timeline, urgency drivers |
| IV | **The Approach** | Key stakeholders, value propositions per persona, service opportunity matrix |
| V | **The Campaign** | Week-by-week engagement sequence, competitive positioning, risks |
| VI | **Action Plan** | Immediate actions (7 days), quarterly milestones, revenue targets |

Plus appendices: intelligence sources, key dates, estimated org chart, attack surface summary.

### Scoring & Classification

The skill scores the account on 5 dimensions:

| Dimension | Scores | Data Sources |
|-----------|--------|-------------|
| Financial Capacity | Unlimited / Substantial / Moderate / Budget-conscious | Wikidata, financial_estimator, WebSearch, Crunchbase (enhanced) |
| Threat Severity | CRITICAL / HIGH / MEDIUM | Recon scripts, MITRE, breach_intel, incident research |
| Regulatory Pressure | IMMEDIATE / HIGH / MEDIUM / LOW | regulatory_analyzer, WebSearch |
| Engagement Path | Direct / Networked / Cold | WebSearch contacts, LinkedIn (enhanced), Sales Navigator (enhanced) |
| Buyer Intent | HIGH / MEDIUM / LOW | WebSearch signals, Sales Navigator badges (enhanced) |

Account classification based on 3-year revenue opportunity:
- **STRATEGIC PARTNER** (> 2M) — enterprise, multiple service lines, strategic partnership
- **KEY ACCOUNT** (500K - 2M) — mid-to-large, 3+ service opportunities
- **TARGET ACCOUNT** (< 500K) — focused engagement, 1-2 service lines

### Service Catalog

Pain points from the recon get matched to a catalog of 38 services across 6 categories:

| Category | Services | Examples |
|----------|----------|---------|
| Assessment & Advisory | 8 | Pentests, red team, cloud assessment, OT/ICS, vCISO |
| Integration & Implementation | 8 | EDR/XDR, SIEM/SOAR, IAM/PAM, backup & DR, zero trust |
| Managed Services | 7 | SOC-as-a-Service, MDR, managed SIEM, managed ASM |
| GRC & Compliance | 7 | ISO 27001, NIS2/DORA, CRA, risk assessment, TPRM |
| Incident Response & Recovery | 4 | IR retainer, breach response, forensics, BC/DR |
| Training & Awareness | 4 | Awareness platform, phishing simulation, tabletop exercises |

Pricing adjusts to the target's size (Enterprise > 1B, Mid-Market 100M-1B, SMB < 100M). You can edit service names and pricing in `references/service_opportunity_mapping.md`.

### Accepts Existing Data

You can feed it existing reports so it doesn't redo work:

- **Existing threat report** (e.g., from `full-profile` or `threat-profile`) → Phase 2 is skipped entirely. Attack surface stats, incidents, threat actors, and breach intel are extracted from the report.
- **Existing client profile** → contacts, pain points, and previous recommendations are extracted and used in scoring.

Typical flow: run `full-profile` first, then pass that report into `sales-targeting`.

### Enhanced Mode

If browser automation tools (Playwright MCP, Chrome MCP, or similar) are available, Phase 3.5 activates:

| Source | What it adds |
|--------|-------------|
| LinkedIn | Contact names, titles, tenure, background, mutual connections |
| Sales Navigator | Buyer intent badges, company followers, TeamLink connections |
| Crunchbase | IT spend, growth score, heat score, funding history |

Without browser tools, WebSearch provides fallback contact/financial data. The report notes the limitation in the intelligence gaps section. See [Enhanced Mode docs](enhanced-mode.md) for setup.

### Output

`./reports/strategic_targeting_<company>.md` + `.pdf`

Final output summary includes:
- Account classification with justification
- 3-year revenue opportunity (year-by-year)
- Top 3 immediate actions
- Intelligence gaps and follow-up priorities

### Examples

```
# Full pipeline
/business-profiler:sales-targeting Shell shell.com Energy Netherlands

# With existing threat report (skips recon)
/business-profiler:sales-targeting Shell shell.com Energy Netherlands
> Use existing report at ./reports/threat_attack_surface_shell.md

# Auto-detect sector and country
/business-profiler:sales-targeting ASML asml.com
```
