# Report Template

Use this structure for the full threat intelligence report. Every section is required unless marked optional.

---

## Document Header

```
# Threat Intelligence & Attack Surface Assessment: [COMPANY NAME]

**Assessment Date:** [YYYY-MM-DD]
**Target Organization:** [Legal Name]
**Primary Domain:** [domain.com]
**Assessment Version:** 1.0
**Classification:** Confidential - Internal Use Only
**Risk Level:** **[CRITICAL/HIGH/MEDIUM/LOW]**
```

---

## Executive Summary

3-5 bullet points of the most critical findings. Include:
- Confirmed breaches/incidents
- Key threat actors targeting the organization
- Attack surface statistics (subdomain count, cloud exposure)
- Sector threat context (one line)
- Immediate actions required

End with: **Immediate Actions Required (0-7 Days):** numbered list of 3-5 urgent items.
End with: **Risk Justification:** one paragraph explaining the risk level.

---

## 1. Company Overview

### 1.1 Business Profile
Table with: Legal Name, Industry, Founded, Headquarters, Website, Employees (if known), Revenue (if known), CEO (if known).
Enrich with Wikidata data where available (source: Wikipedia/Wikidata).

### 1.2 Business Description
2-3 paragraphs: core business, strategic significance for threat targeting (why attackers care).
If financial estimates are available, include IT/cybersecurity spend estimations (clearly marked as estimates with methodology).

### 1.3 Global Operations
Geographic presence, subsidiaries, key operational locations.

---

## 2. Infrastructure Assessment

### 2.1 Attack Surface Summary
Table: Domain, Total Subdomains, Resolved, Unresolved, Key Findings.

### 2.2 Network Infrastructure
ASN info, IP ranges by region (from cloud detector output).

### 2.3 Cloud Infrastructure
Table: Provider, IPs Identified, Services Detected.

### 2.4 Email & Collaboration
- M365 detection results (tenant ID, federation)
- Email security grades: SPF, DKIM, DMARC with records and issues
- MX record analysis

### 2.5 Domain Registration
WHOIS/RDAP data: registrar, creation/expiration dates, nameservers.

### 2.6 SSL/TLS Security
Table: Domain, TLS Version, Cipher Suite, Cipher Bits, Certificate Issuer, Expiry Date, Risk Level.
List any security issues found (expired cert, outdated TLS, weak cipher, wildcard).

### 2.7 Technology Stack
Group by category:
- **Web Server**: e.g., nginx 1.18, Apache 2.4
- **Frameworks & Languages**: e.g., PHP, ASP.NET, React, Vue
- **CMS**: e.g., WordPress, Drupal
- **CDN/WAF**: e.g., Cloudflare, Akamai, Fastly
- **Third-Party Services**: table with Name, Category, Detection Method (e.g., Stripe/Payments, HubSpot/Marketing, Sentry/Monitoring)
- **Infrastructure Vendors**: e.g., Vercel, Netlify, AWS CloudFront

### 2.8 Notable Subdomains
Categorize discovered subdomains by risk:
- **Development/Staging**: api-dev, test, staging, preprod
- **File Transfer**: ftp, sftp, transfer
- **VPN/Remote Access**: vpn, remote, gateway
- **Customer/Partner Portals**: portal, partner, supplier
- **API Endpoints**: api, graphql, ws

---

## 3. Threat Intelligence

### 3.1 Sector Threat Context
2-3 paragraphs on the current threat landscape for this sector. Include statistics (ransomware trends, attack frequency).

### 3.2 Breach Intelligence
Table from XposedOrNot data: Breach Name, Date, Exposed Data Types, Records Affected.
If no breaches found, state that clearly.

### 3.3 CISA KEV Matches
If tech stack data was used for KEV matching, include table: CVE ID, Vendor, Product, Vulnerability Name, Date Added, Ransomware Campaign Use.
If no matches, state that clearly. If KEV matching was not performed (no tech stack data), note this as an intelligence gap.

### 3.4 Confirmed Security Incidents
Table for each incident (from WebSearch): Date, Type, Actor, Impact, Source URL.
If no incidents found, state that clearly.

### 3.5 Threat Actor Profiles
For each relevant actor (5-8), include:

#### [Actor Name] ([Attribution Country])
- **MITRE ID:** G####
- **Aliases:** list
- **Motivation:** Espionage / Financial / Destruction
- **Target Match:** why this actor is relevant (sector + country + strategic value)
- **Key TTPs Table:**

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1566.001 | Spearphishing Attachment |

### 3.6 Threat Actor Targeting Matrix
Summary table: Actor, Attribution, Sector Match, Country Match, Overall Relevance (HIGH/MEDIUM/LOW).

---

## 4. Regulatory Context

### 4.1 Applicable Regulations
Table: Regulation, Full Name, Deadline, Urgency, Penalties.
Include key requirements for each (top 3-5).

### 4.2 Compliance Pressure Summary
Overall urgency level, compliance drivers, estimated total compliance cost range.

---

## 5. Threat Vectors

Numbered list of 5-8 attack scenarios specific to this organization:
For each: description, risk factors (what makes this likely), attack chain (MITRE techniques), potential impact.

---

## 6. Risk Assessment

### 5.1 Risk Matrix
Table: Risk Factor, Likelihood (1-5), Impact (1-5), Risk Level.

### 5.2 Overall Risk Assessment
Paragraph with justification bullets.

### 5.3 Business Impact Scenarios
Table: Scenario, Impact Description, Estimated Impact, Likelihood.

---

## 7. Recommendations

### 6.1 Immediate Actions (0-7 Days)
Numbered list with: ID (MIT-001), action, priority (CRITICAL/HIGH), rationale.

### 6.2 Short-Term Actions (7-30 Days)
Same format.

### 6.3 Medium-Term Actions (30-90 Days)
Same format.

### 6.4 Strategic Recommendations
Longer-term security improvements.

---

## 8. Detection Priorities

### 7.1 High-Value Detection Use Cases
Table: Use Case, MITRE Technique, Data Source, Priority.

### 7.2 Threat Hunting Priorities
Numbered list of hunting hypotheses tied to threat actors identified.

---

## 9. Intelligence Gaps

Table: Gap, Impact on Assessment, Recommended Mitigation.

---

## 10. Appendices

### Appendix A: MITRE ATT&CK Heat Map
Table showing technique coverage across all identified actors.

### Appendix B: Full Subdomain List (Sample)
First 50 subdomains with resolution status.

### Appendix C: Intelligence Sources
All sources used with URLs and access dates.

---

*Made with love by an AI agent · a skill developed by PEACH STUDIO*
