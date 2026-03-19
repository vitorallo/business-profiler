# Nexagen GmbH — Strategic Account Targeting Report

**Classification:** Confidential — Sales Enablement
**Document Type:** Executive Account Strategy
**Version:** 1.0
**Created:** 2026-03-15
**Research Approach:** Agentic CTI + Financial + Business Profiler + EASM/OSINT

> This is a sample report based on a fictional company. All data, findings, financials, contacts, and recommendations are fabricated for demonstration purposes. No real organization was assessed.

---

## Executive Summary

**Account Status:** KEY ACCOUNT | **Risk Assessment:** HIGH
**Estimated 3-Year Revenue Opportunity:** EUR 620K — EUR 1.1M
**Urgency:** HIGH — NIS2 enforcement active + CRA deadline approaching + confirmed vendor breach

Nexagen GmbH is a strong account opportunity driven by three converging pressures: a recent vendor portal breach exposing gaps in third-party risk management, imminent CRA compliance obligations for their PLC products, and active nation-state targeting of German manufacturers by APT28 and Sandworm Team. With EUR 380M revenue and an estimated IT budget of EUR 15-19M, Nexagen has the capacity for a multi-year engagement but will require clear ROI justification typical of Mittelstand companies.

The confirmed February 2025 breach, 187 discovered subdomains including OT-adjacent systems, and unenforced DMARC create a compelling "why now" that the CISO can take to the board.

### The Perfect Storm

| Factor | Status | Implication |
|--------|--------|-------------|
| **Financial Capacity** | Moderate — EUR 380M revenue, EUR 15-19M IT spend | Budget-conscious but can fund targeted engagements with clear ROI |
| **Threat Level** | HIGH — APT28/Sandworm targeting, 1 confirmed breach, OT exposure | Urgent need for OT assessment, vendor risk management, email security |
| **Regulatory Deadline** | HIGH — NIS2 active, CRA reporting Sep 2026 | Mandatory spend on compliance; PLC products likely in CRA scope |
| **Buyer Intent** | MEDIUM — Post-breach; CISO hired 2024; security budget increasing | Active investment cycle triggered by Feb 2025 incident |
| **Access Path** | Networked — CISO spoke at German Manufacturing Security Forum 2025 | Industry event connection possible; mutual contacts in DACH security community |

---

## PART I: THE OPPORTUNITY

### 1.1 Financial Intelligence

| Metric | Value | Source |
|--------|-------|--------|
| Annual Revenue | EUR 380M (2025 est.) | WebSearch / Industry databases |
| Net Profit | EUR 28M (7.4% margin) | Industry benchmark estimate |
| Employees | ~2,400 | Wikidata |
| IT Spend (est.) | EUR 15M — 19M | 4-5% of revenue (manufacturing benchmark) |
| Security Budget (est.) | EUR 1.5M — 2.8M | 10-15% of IT budget (post-breach adjustment) |
| Recent Funding | None (privately held, family ownership) | WebSearch |

**Financial Capacity Score: MODERATE**

Nexagen is a profitable Mittelstand company with healthy margins. Security budget decisions require board-level justification. The Feb 2025 breach likely increased the security budget allocation for 2026. Engagement pricing should be competitive and demonstrate measurable risk reduction.

### 1.2 Market Position

Nexagen is a mid-tier German industrial automation manufacturer specializing in PLCs and SCADA interface modules. They supply components to automotive OEMs and chemical plants across the DACH region. The company is privately held (family-owned since 1997) with conservative spending patterns but growing awareness of cybersecurity risk.

Their PLC products sit in the OT supply chain — a breach or firmware compromise at Nexagen could cascade to their customers' production environments, making them both a target and a liability.

---

## PART II: THE PAIN

### 2.1 Security Incident History

| Date | Incident | Type | Impact |
|------|----------|------|--------|
| Feb 2025 | partners.nexagen.de credential stuffing | Unauthorized access | 340 vendor accounts compromised; documents accessed |

**Pattern Analysis:**

| Incident Pattern | Weakness Indicated | Service Opportunity |
|-----------------|-------------------|-------------------|
| Vendor portal compromise | No MFA, weak credential policies | #30 Third-Party Risk Management |
| Credential stuffing success | Password reuse, no breach monitoring | #11 IAM/PAM, #35 Security Awareness |
| Post-breach uncertainty | No forensic investigation conducted | #33 Digital Forensics |

### 2.2 Attack Surface Analysis

| Category | Count/Details | Risk Level |
|----------|--------------|------------|
| Subdomains | 187 (64 resolved) | HIGH |
| Cloud | AWS eu-central-1 (8 IPs), Hetzner (14 IPs) | MODERATE |
| Email Security | SPF pass, DMARC none, DKIM partial | HIGH |
| Staging/Dev exposed | 12 subdomains | HIGH |
| OT-adjacent | scada-gw, plc-update, edge-mgmt | HIGH |
| CISA KEV matches | 7 (nginx, PHP, WordPress) | HIGH |

### 2.3 Threat Actor Targeting

| Actor | Attribution | Relevance |
|-------|------------|-----------|
| APT28 (Fancy Bear) | Russia GRU | HIGH — targeting German manufacturing |
| Sandworm Team | Russia GRU | HIGH — ICS/OT sabotage capability |
| ALPHV/BlackCat | eCrime | HIGH — manufacturing is #2 ransomware target |

---

## PART III: THE DEADLINE

### 3.1 Regulatory Pressure

| Regulation | Deadline | Penalty | Status |
|-----------|----------|---------|--------|
| NIS2 | Active Jan 2025 | EUR 7.6M (2% of turnover) | Enforcement phase — must demonstrate compliance program |
| CRA | Reporting Sep 2026 | EUR 9.5M (2.5% of turnover) | 6 months to reporting deadline — PLC products likely in scope |
| GDPR | Active | EUR 15.2M (4% of turnover) | Ongoing — vendor breach may trigger notification obligations |
| Machinery Regulation | 2027 | Product market access | Connected PLC products will need cybersecurity certification |

**Regulatory Pressure Score: HIGH**

The CRA deadline in 6 months is the strongest urgency driver. Nexagen's PLC products almost certainly qualify as "products with digital elements" requiring SBOMs and vulnerability handling processes. This is new territory for most manufacturers — they need help.

---

## PART IV: THE APPROACH

### 4.1 Key Stakeholders

| Name | Title | Background | Access Path |
|------|-------|------------|-------------|
| Klaus Brenner | CISO (hired Q2 2024) | Former security lead at a German automotive supplier; hired post-breach preparation | Spoke at German Manufacturing Security Forum 2025; reachable via industry events |
| Petra Hoffmann | CIO | 15+ years at Nexagen; oversees IT and OT convergence project | Through CISO or via DACH CIO network |
| Michael Nexagen Jr. | CEO / Family owner | Second generation; cautious but increasingly security-aware after Feb breach | Through CISO with board-ready business case |

**Note:** Contact intelligence is limited to public web sources. For detailed profiles, configure Chrome MCP for LinkedIn enrichment.

### 4.2 Value Proposition

**For the CISO (Klaus Brenner):**
> "Your vendor portal breach in February exposed gaps that NIS2 auditors will ask about. We help you close the third-party risk gap, assess your OT/IT boundary, and build the compliance evidence trail — before the regulator comes knocking."

**For the CIO (Petra Hoffmann):**
> "With 187 subdomains including OT-adjacent systems and 12 exposed staging environments, your attack surface is bigger than your team can monitor manually. Our managed ASM gives you continuous visibility without adding headcount."

**For the CEO:**
> "CRA reporting starts in September. Your PLCs are almost certainly in scope. The penalty is EUR 9.5M. Getting ahead of this costs less than 3% of that exposure and protects your market access."

### 4.3 Service Opportunity Matrix

| # | Service | Pain Point | Est. Value (EUR) | Timeline | Priority |
|---|---------|-----------|-----------------|----------|----------|
| 30 | Third-Party Risk Management | Vendor portal breach | 20K — 40K | Year 1 | P1 |
| 7 | OT/ICS Security Assessment | SCADA gateway + PLC exposure | 25K — 50K | Year 1 | P1 |
| 25 | NIS2 Compliance Program | Active enforcement | 25K — 60K | Year 1 | P1 |
| 26 | CRA Compliance Program | Sep 2026 deadline for PLC products | 30K — 70K | Year 1 | P1 |
| 1 | External Penetration Test | 187 subdomains, 12 staging envs | 10K — 20K | Year 1 | P2 |
| 31 | IR Retainer | Post-breach readiness | 20K — 50K/yr | Year 1 | P2 |
| 20 | Managed ASM | Continuous attack surface monitoring | 30K — 60K/yr | Year 2 | P2 |
| 35 | Security Awareness Training | Credential stuffing success indicates weak hygiene | 8K — 20K/yr | Year 2 | P3 |
| 37 | Tabletop Exercise | NIS2 requirement; test incident response | 5K — 15K | Year 2 | P3 |

**Revenue Opportunity:**

| Year | Focus | Estimated Revenue (EUR) |
|------|-------|------------------------|
| Year 1 | Assessments + compliance (OT, NIS2, CRA, TPRM, pentest, IR retainer) | 250K — 410K |
| Year 2 | Managed services + expansion (ASM, awareness, tabletop, follow-up assessments) | 200K — 350K |
| Year 3 | Recurring services + maturity reviews | 170K — 300K |
| **3-Year Total** | | **EUR 620K — 1.06M** |

**Account Classification: KEY ACCOUNT** (3-year opportunity 500K — 2M)

---

## PART V: THE CAMPAIGN

### 5.1 Engagement Sequence

| Week | Action | Channel | Objective |
|------|--------|---------|-----------|
| 1 | Research Klaus Brenner on LinkedIn; find mutual connections in DACH security community | LinkedIn | Map decision-making unit |
| 1 | Prepare Nexagen-specific threat briefing (APT28 + manufacturing + Feb breach context) | Internal | Value-first content |
| 2 | Send personalized outreach with attack surface snapshot (subdomain count, DMARC gap, staging exposure) | Email / LinkedIn | Establish credibility through specifics |
| 3 | Offer complimentary CRA scoping session for PLC product lines | Email follow-up | Create meeting opportunity |
| 3-4 | First meeting: present threat landscape briefing + CRA timeline | Video call | Demonstrate expertise; identify pain priorities |
| 4-6 | Submit proposal: OT assessment + NIS2 gap analysis + CRA scoping | Proposal | Convert to engagement |
| 6-8 | Deliver findings; present managed services roadmap | Workshop | Build trust; create expansion path |

### 5.2 Competitive Positioning

| Competitor | Their pitch | Our counter |
|-----------|------------|-------------|
| Big 4 consultancy | Scale, brand recognition | We're faster, more technical, and specialize in manufacturing OT. No 6-week staffing ramp-up. |
| Siemens/Rockwell (OT vendors) | Integrated OT security with their products | We're vendor-agnostic. We assess their controls objectively and cover IT-OT convergence. |
| Local German pentesting boutique | Regional trust, German-speaking team | We add CTI depth (MITRE-mapped actors), compliance integration, and managed services they can't offer. |

### 5.3 Risk Factors

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Mittelstand budget constraints | HIGH | MEDIUM | Start with focused assessments (EUR <30K) to prove value |
| Family ownership = slow decisions | MEDIUM | MEDIUM | Provide board-ready materials CISO can present directly |
| Internal team believes they can handle it | MEDIUM | HIGH | Lead with specialized OT/CRA expertise they don't have in-house |

---

## PART VI: ACTION PLAN

### Immediate (next 7 days)
1. Research Klaus Brenner's LinkedIn profile and speaking history
2. Draft personalized outreach email with Nexagen-specific findings
3. Prepare 1-page CRA impact brief for PLC manufacturers

### Q1/Q2 Milestones

| Milestone | Target | Success Criteria |
|-----------|--------|-----------------|
| First meeting | Week 4 | CISO agrees to threat briefing |
| Proposal submitted | Week 6 | OT assessment + NIS2 + CRA scoping |
| First engagement signed | Week 8 | EUR 50K+ initial project |
| Managed services discussion | Week 12 | ASM + IR retainer pipeline |

---

## Appendix A: Intelligence Sources

| Source | Type |
|--------|------|
| crt.sh, HackerTarget, AlienVault OTX | Subdomain enumeration |
| XposedOrNot | Breach intelligence |
| CISA KEV | Known exploited vulnerabilities |
| MITRE ATT&CK STIX | Threat actor TTPs |
| Wikidata | Company data |
| WebSearch | Incidents, financials, contacts |
| BSI Annual Report 2025 | German threat landscape |

---

*Made with love by an AI agent · a skill developed by PEACH STUDIO*
