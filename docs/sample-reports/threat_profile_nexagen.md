# Nexagen GmbH — Threat Intelligence Profile

**Classification:** CONFIDENTIAL — For Authorized Recipients Only
**Date:** 2026-03-15
**Report Type:** Threat Intelligence & Attack Surface Assessment
**Risk Level:** **HIGH**

> This is a sample report based on a fictional company. All data, findings, and recommendations are fabricated for demonstration purposes. No real organization was assessed.

---

## 1. Executive Summary

<p>Overall Risk Level: <span class="risk-badge risk-high">HIGH</span></p>

<div class="dashboard-row">
  <div class="metric-card">
    <p class="metric-value">187</p>
    <p class="metric-label">Subdomains Discovered</p>
  </div>
  <div class="metric-card">
    <p class="metric-value">2</p>
    <p class="metric-label">Cloud Providers</p>
  </div>
  <div class="metric-card">
    <p class="metric-value">1</p>
    <p class="metric-label">Confirmed Breaches</p>
  </div>
  <div class="metric-card">
    <p class="metric-value">7</p>
    <p class="metric-label">CISA KEV Matches</p>
  </div>
</div>

| Attribute | Assessment |
|-----------|------------|
| **Primary Threat** | State-sponsored espionage and ransomware targeting German manufacturing |
| **Secondary Threat** | Supply chain compromise via exposed vendor portals |
| **Email Security Posture** | **MODERATE — DMARC set to none (not enforced)** |
| **Attack Surface** | **ELEVATED — 187 subdomains, exposed staging environments, legacy ERP interfaces** |

Nexagen GmbH is a mid-size German industrial automation manufacturer with 2,400 employees and approximately EUR 380M annual revenue. The company designs and produces programmable logic controllers (PLCs) and SCADA interface modules for automotive and chemical plants across Europe.

**Critical Findings:**
- APT28 (Fancy Bear) and Sandworm Team are actively targeting German manufacturing firms with OT exposure
- Germany's BSI reported a 41% increase in attacks on Mittelstand manufacturers in 2025
- Nexagen's DMARC record is set to `p=none`, meaning spoofed emails pass without quarantine or rejection
- 12 staging/dev subdomains are publicly accessible (erp-test.nexagen.de, plc-dev.nexagen.de, etc.)
- A vendor collaboration portal (partners.nexagen.de) was breached in February 2025 via credential stuffing

**Immediate Actions Required (0-7 Days):**
1. Enforce DMARC policy to `p=reject` on nexagen.de
2. Restrict public access to staging/dev subdomains behind VPN
3. Force password reset on partners.nexagen.de and enable MFA

---

## 2. Company Context

### Business Profile

| Attribute | Detail |
|-----------|--------|
| **Company** | Nexagen GmbH |
| **Sector** | Manufacturing (Industrial Automation) |
| **Country** | Germany |
| **Headquarters** | Stuttgart, Baden-Württemberg |
| **Founded** | 1997 |
| **Employees** | ~2,400 |
| **Revenue** | EUR 380M (2025 est.) |
| **Primary Domain** | nexagen.de |
| **Products** | PLCs, SCADA interface modules, industrial edge gateways |
| **Key Markets** | Automotive OEMs, chemical plants, energy utilities (DACH region) |

### Strategic Value for Attackers

As a manufacturer of industrial control system components, Nexagen sits at a sensitive point in the OT supply chain:

1. **IP theft** — PLC firmware and SCADA protocols are high-value targets for state-sponsored actors seeking industrial espionage
2. **Supply chain pivot** — Compromising Nexagen's products could provide access to downstream customers (automotive plants, chemical facilities)
3. **Ransomware leverage** — Manufacturing downtime is extremely costly; firms often pay to restore operations quickly
4. **OT access** — Nexagen's own production floor runs the same PLCs they manufacture, creating an OT attack surface

---

## 3. Infrastructure Assessment

### Attack Surface Summary

| Category | Count/Details | Risk Level |
|----------|--------------|------------|
| **Subdomains** | 187 total (64 resolved to IPs) | HIGH |
| **Cloud Providers** | AWS (8 IPs, eu-central-1), Hetzner (14 IPs) | MODERATE |
| **Email Security** | SPF: pass (-all), DMARC: none, DKIM: 2 selectors | HIGH — DMARC not enforced |
| **SSL/TLS** | TLSv1.3 on main domain, TLSv1.2 on 3 subdomains | MODERATE |
| **M365 Tenant** | Confirmed, federated: Yes (ADFS) | INFO |
| **Tech Stack** | nginx 1.24, PHP 8.1, WordPress (corporate blog), SAP Gateway | MODERATE |
| **CISA KEV Matches** | 7 (nginx: 2, PHP: 3, WordPress: 2) | HIGH |

### Notable Subdomains

**Development/Staging (12 exposed):**
- erp-test.nexagen.de — SAP test instance (185.72.x.x, Hetzner)
- plc-dev.nexagen.de — PLC firmware development portal (185.72.x.x, Hetzner)
- staging.nexagen.de — WordPress staging with debug mode enabled
- api-sandbox.nexagen.de — REST API sandbox with test data, no auth required
- qa-erp.nexagen.de — SAP QA environment
- ci.nexagen.de — Jenkins CI (version 2.387, 3 CISA KEV matches)

**OT-Adjacent:**
- scada-gw.nexagen.de — SCADA gateway interface (Modbus TCP proxy, port 502 open)
- plc-update.nexagen.de — PLC firmware update server (unsigned firmware packages)
- edge-mgmt.nexagen.de — Industrial edge device management (default credentials documented in public manual)
- opc-bridge.nexagen.de — OPC-UA bridge between plant floor and corporate MES

**Vendor/Partner:**
- partners.nexagen.de — Vendor collaboration portal (breached Feb 2025)
- supplier-portal.nexagen.de — Supply chain document exchange (TLSv1.2, weak cipher suite)

**VPN/Remote Access:**
- vpn.nexagen.de — GlobalProtect VPN gateway
- remote.nexagen.de — Citrix StoreFront (version not determined)

### Email Security Detail

| Record | Value | Grade |
|--------|-------|-------|
| **SPF** | `v=spf1 include:spf.protection.outlook.com include:_spf.hetzner.com -all` | PASS |
| **DMARC** | `v=DMARC1; p=none; rua=mailto:dmarc@nexagen.de` | FAIL — policy not enforced |
| **DKIM** | Selector `s1` (Microsoft 365), `hetzner` (mail relay) | PARTIAL — no third-party signing |
| **MX** | nexagen-de.mail.protection.outlook.com (pri 10) | M365 confirmed |

The DMARC `p=none` policy means spoofed emails from @nexagen.de are delivered without quarantine or rejection. Combined with the SPF include for Hetzner (broad IP range), an attacker can spoof Nexagen emails to vendors and customers with high deliverability.

### CISA KEV Matches

| CVE | Product | Vulnerability | Date Added | Ransomware Use |
|-----|---------|--------------|------------|----------------|
| CVE-2024-7971 | nginx | HTTP/2 rapid reset DoS | 2024-08-15 | No |
| CVE-2023-44487 | nginx | HTTP/2 rapid reset | 2023-10-10 | No |
| CVE-2024-4577 | PHP 8.1 | CGI argument injection (RCE) | 2024-06-13 | Yes — TellYouThePass |
| CVE-2023-3824 | PHP 8.1 | Buffer overflow | 2023-09-20 | No |
| CVE-2024-2961 | PHP (glibc) | iconv buffer overflow | 2024-05-30 | No |
| CVE-2024-2194 | WordPress | Stored XSS via comments | 2024-04-10 | No |
| CVE-2023-2982 | WordPress | Auth bypass via social login plugin | 2023-08-15 | No |

CVE-2024-4577 (PHP CGI argument injection) is the most critical — it allows unauthenticated remote code execution and is actively used by the TellYouThePass ransomware family. Nexagen's staging environments running PHP 8.1 are directly exposed.

---

## 4. Threat Intelligence

### Breach Intelligence (XposedOrNot)

| Breach | Date | Exposed Data Types | Records |
|--------|------|--------------------|---------|
| Collection #1 (aggregated) | Jan 2019 | Email addresses, passwords | 12 nexagen.de accounts found |
| Cit0day dump | Nov 2020 | Email, plaintext passwords | 3 nexagen.de accounts found |

15 Nexagen employee email/password combinations appear in known credential dumps. These are the likely source material for the February 2025 credential stuffing attack on the partner portal.

### Confirmed Security Incidents

| Date | Incident | Type | Actor | Impact |
|------|----------|------|-------|--------|
| Feb 2025 | partners.nexagen.de credential stuffing | Unauthorized Access | Unknown | 340 vendor accounts compromised; NDA documents and technical drawings accessed |
| Nov 2024 | Spearphishing campaign targeting Nexagen procurement | Phishing | Unknown | 2 employees clicked; no confirmed compromise; reported to BSI |
| Aug 2023 | DDoS on nexagen.de during trade show | Disruption | Unknown | 4-hour outage of corporate website and customer portal |

### Threat Actor Profiles

#### APT28 (Fancy Bear)

| Attribute | Detail |
|-----------|--------|
| **Attribution** | Russia — GRU Unit 26165 |
| **Motivation** | Espionage, IP theft |
| **Relevance** | **HIGH** — Targeting German manufacturers for defense-adjacent IP |

**Key TTPs:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1566.001 | Spearphishing Attachment |
| Execution | T1059.001 | PowerShell |
| Persistence | T1547.001 | Registry Run Keys |
| Credential Access | T1003.001 | LSASS Memory |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares |

#### Sandworm Team (APT44)

| Attribute | Detail |
|-----------|--------|
| **Attribution** | Russia — GRU Unit 74455 |
| **Motivation** | Sabotage, destructive attacks on OT/ICS |
| **Relevance** | **HIGH** — Demonstrated ICS attack capability (Industroyer, CaddyWiper) |

**Key TTPs:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Execution | T1059.006 | Python |
| Impact | T1485 | Data Destruction |
| Impact | T1495 | Firmware Corruption |
| Lateral Movement | T1570 | Lateral Tool Transfer |

#### ALPHV/BlackCat Affiliates

| Attribute | Detail |
|-----------|--------|
| **Attribution** | eCrime — Ransomware-as-a-Service |
| **Motivation** | Financial (ransomware + data extortion) |
| **Relevance** | **HIGH** — Manufacturing is #2 most targeted sector for ransomware in 2025 |

**Key TTPs:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1078 | Valid Accounts |
| Execution | T1047 | Windows Management Instrumentation |
| Impact | T1486 | Data Encrypted for Impact |
| Exfiltration | T1567.002 | Exfiltration to Cloud Storage |
| Defense Evasion | T1562.001 | Disable or Modify Tools |

#### APT41 (Wicked Panda)

| Attribute | Detail |
|-----------|--------|
| **Attribution** | China — MSS-affiliated, dual espionage/cybercrime |
| **Motivation** | IP theft + financial gain |
| **Relevance** | **MEDIUM** — Expanded to European manufacturing in 2024-2025 |

**Key TTPs:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1195.002 | Compromise Software Supply Chain |
| Initial Access | T1190 | Exploit Public-Facing Application |
| Persistence | T1505.003 | Web Shell |
| Credential Access | T1003.001 | LSASS Memory |
| Exfiltration | T1041 | Exfiltration Over C2 Channel |

### Sector Threat Context: German Manufacturing (2025-2026)

German manufacturing (Mittelstand in particular) faces a difficult period. The BSI's 2025 annual report flagged a 41% YoY increase in attacks on mid-size manufacturers. Ransomware groups have shifted focus from healthcare to manufacturing, which is now the #2 most targeted sector globally. The convergence of IT and OT networks in Industry 4.0 adoption has expanded attack surfaces faster than security teams can keep up.

Three factors make Nexagen's position worse than the sector average: their products are embedded in customer OT environments (supply chain risk multiplier), their own production floor runs the PLCs they build (self-targeting), and the February 2025 breach suggests existing controls are inadequate.

### Threat Actor Targeting Matrix

| Actor | Attribution | Sector Match | Country Match | Relevance |
|-------|------------|-------------|---------------|-----------|
| APT28 | Russia GRU | Manufacturing | Germany | HIGH |
| Sandworm Team | Russia GRU | OT/ICS/Manufacturing | Europe | HIGH |
| ALPHV/BlackCat | eCrime | Manufacturing (#2 target) | Global | HIGH |
| Kimsuky | North Korea | Manufacturing/Defense | Germany | MEDIUM |
| APT41 | China MSS | Manufacturing | Europe | MEDIUM |

---

## 5. Regulatory Context

| Regulation | Deadline | Status | Penalty | Key Requirements |
|-----------|----------|--------|---------|-----------------|
| **NIS2** | Active Jan 2025 | Enforcement phase | EUR 10M or 2% turnover | Supply chain security, incident reporting (24h), regular testing |
| **CRA** | Reporting Sep 2026 | Preparation | EUR 15M or 2.5% turnover | SBOM for products with digital elements, vulnerability handling |
| **GDPR** | Active | Ongoing | EUR 20M or 4% turnover | Data protection, breach notification (72h) |
| **Machinery Regulation** | 2027 | Preparation | Product recall / market ban | Cybersecurity requirements for connected machinery |

**Compliance Pressure: HIGH** — NIS2 is already enforceable, CRA reporting deadline is 6 months away, and Nexagen's PLC products likely fall under both CRA and the new Machinery Regulation.

---

## 6. Risk Assessment

| Risk Factor | Likelihood (1-5) | Impact (1-5) | Risk Level |
|-------------|-------------------|--------------|------------|
| Ransomware attack on production | 4 | 5 | **CRITICAL** |
| State-sponsored IP theft (PLC firmware) | 3 | 5 | **HIGH** |
| Supply chain compromise via partner portal | 4 | 4 | **HIGH** |
| Spearphishing leading to AD compromise | 4 | 4 | **HIGH** |
| OT/ICS sabotage via SCADA gateway | 2 | 5 | **HIGH** |
| Regulatory penalty (NIS2 non-compliance) | 3 | 4 | **HIGH** |

**Overall Risk Level: HIGH**

Nexagen faces elevated risk from ransomware groups targeting manufacturing, state-sponsored actors seeking industrial IP, and regulatory pressure from NIS2 and CRA. The exposed development environments and unenforced DMARC create low-hanging-fruit entry points.

---

## 7. Recommendations

### Immediate (0-7 Days)
- **MIT-001:** Enforce DMARC to `p=reject` on nexagen.de — CRITICAL
- **MIT-002:** Restrict staging/dev subdomains behind VPN or IP allowlist — CRITICAL
- **MIT-003:** Force MFA on partners.nexagen.de, audit all vendor accounts from Feb breach — CRITICAL

### Short-term (7-30 Days)
- **MIT-004:** Patch 7 CISA KEV vulnerabilities matched in tech stack — HIGH
- **MIT-005:** Segment SCADA gateway (scada-gw.nexagen.de) from corporate network — HIGH
- **MIT-006:** Deploy EDR on OT-adjacent systems — HIGH

### Medium-term (30-90 Days)
- **MIT-007:** Engage third-party penetration test focused on OT/IT boundary — HIGH
- **MIT-008:** Implement supply chain security assessment for top 20 vendors — HIGH
- **MIT-009:** Begin NIS2 compliance gap analysis — HIGH
- **MIT-010:** Assess CRA applicability to PLC product lines — MEDIUM

---

## 8. Intelligence Gaps

| Gap | Impact | Recommended Action |
|-----|--------|-------------------|
| No internal network visibility | Cannot assess lateral movement paths | Request internal pentest or network diagram |
| PLC firmware security not assessed | Unknown supply chain risk to customers | Firmware security audit |
| Vendor breach scope unclear | Feb 2025 incident may have broader impact | Forensic investigation of partner portal |
| OT network architecture unknown | Cannot assess ICS segmentation | OT/ICS assessment with Purdue model mapping |

---

## Appendix: Intelligence Sources

| Source | Type | Date Accessed |
|--------|------|---------------|
| crt.sh | Subdomain enumeration | 2026-03-15 |
| HackerTarget | Subdomain enumeration | 2026-03-15 |
| AlienVault OTX | Subdomain enumeration | 2026-03-15 |
| XposedOrNot | Breach intelligence | 2026-03-15 |
| CISA KEV | Known exploited vulnerabilities | 2026-03-15 |
| MITRE ATT&CK STIX | Threat actor TTPs | 2026-03-15 |
| Wikipedia/Wikidata | Company data | 2026-03-15 |
| RDAP | Domain registration | 2026-03-15 |
| WebSearch | Incidents, trends, financial data | 2026-03-15 |
| BSI Annual Report 2025 | German threat landscape | 2026-03-15 |

---

*Made with love by an AI agent · a skill developed by [PEACH STUDIO](http://peachstudio.be)*
