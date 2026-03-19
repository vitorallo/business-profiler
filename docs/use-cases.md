# Use cases

This guide walks through the two main workflows: running a threat profile on a target company, and turning that into a sales targeting report. Both produce PDF output.

> Due to the sensitivity of real threat intelligence data, the sample reports in `docs/sample-reports/` use a completely fictional company. No real organizations were profiled.

Companies used here are mockup samples, non-existing entities.

---

## 1. Threat profiling a target company

**When to use:** You need a threat intelligence report on a company — their attack surface, who's targeting their sector, what breaches they've had, and what regulations apply. Useful for pre-engagement research, KYC, or internal threat assessments.

**Command:**
```
/business-profiler:full-profile Nexagen nexagen.de Manufacturing Germany
```

**What happens:**
1. Checks dependencies (installs if needed)
2. Runs 8 recon scripts in parallel — subdomains, email security (SPF/DKIM/DMARC), M365 detection, SSL/TLS, tech stack, WHOIS, breach history
3. Detects cloud providers from discovered IPs
4. Pulls company data from Wikidata (employees, revenue, industry)
5. Searches for recent security incidents via WebSearch
6. Looks up sector-specific threat actors from MITRE ATT&CK, gets their TTPs
7. Runs regulatory analysis (NIS2, DORA, CRA, etc. based on sector + country)
8. Estimates IT and security spend from industry benchmarks
9. Generates a 15-20 page report with all findings, risk scoring, and recommendations
10. Outputs both Markdown and PDF

**What you get:**
- Executive summary with overall risk level (CRITICAL/HIGH/MEDIUM/LOW)
- Full infrastructure map (subdomains, cloud, email, SSL, tech stack)
- Breach history from XposedOrNot + CISA KEV matches against their tech stack
- 5-8 threat actor profiles with MITRE ATT&CK TTP tables
- Regulatory exposure with deadlines and penalties
- Risk-scored recommendations on a 7/30/90 day timeline
- PDF with the Peach Studio theme

**Sample output:** See [docs/sample-reports/threat_profile_nexagen.md](sample-reports/threat_profile_nexagen.md)

### Lighter alternatives

Not every situation needs the full pipeline:

| Need | Skill | What it skips |
|------|-------|---------------|
| Just threat actors, no recon | `/business-profiler:threat-profile Nexagen nexagen.de Manufacturing Germany` | Lighter recon (50 subdomains max), no cloud detection |
| Just the attack surface | `/business-profiler:attack-surface nexagen.de` | No threat actors, no regulatory analysis |
| Just MITRE actors for a sector | `/business-profiler:threat-actors Manufacturing` | No recon at all, just MITRE lookup |
| Just recent breaches | `/business-profiler:incident-lookup Nexagen` | WebSearch only, no scripts |
| OT/ICS focused | `/business-profiler:ot-ics-assessment Nexagen nexagen.de Manufacturing Germany` | Adds ICS-specific analysis (Purdue model, ICS malware) |

---

## 2. Sales targeting from threat data

**When to use:** You're a cybersecurity sales team preparing to engage a prospect. You want to turn real threat data into an account strategy: what services to pitch, how much to quote, who to call, and why they should buy now.

**Command:**
```
/business-profiler:sales-targeting Nexagen nexagen.de Manufacturing Germany
```

**What happens:**
1. Runs the full recon + threat intel pipeline (same as full-profile)
2. Adds business intelligence: Wikidata company data, financial estimation, regulatory analysis
3. Runs 5 WebSearch queries for financials, contacts (CISO/CIO), buyer intent signals, and regulatory posture
4. Scores the account on 5 dimensions: financial capacity, threat severity, regulatory pressure, engagement path, buyer intent
5. Maps discovered pain points to a catalog of 38 cybersecurity services with pricing scaled to company size
6. Calculates a 3-year revenue opportunity
7. Classifies the account: STRATEGIC PARTNER / KEY ACCOUNT / TARGET ACCOUNT
8. Generates a 6-part report: Opportunity, Pain, Deadline, Approach, Campaign, Action Plan

**What you get:**
- "Perfect Storm" convergence table (finances + threats + regulation + access)
- Financial intelligence: revenue, IT spend estimate, security budget estimate
- Pain-to-service mapping: each finding linked to a specific service with pricing
- Key stakeholders with titles and engagement approach
- Week-by-week engagement sequence
- Competitive positioning against likely incumbents
- 3-year revenue target by service line
- PDF with the Peach Studio theme

**Sample output:** See [docs/sample-reports/strategic_targeting_nexagen.md](sample-reports/strategic_targeting_nexagen.md)

### Fast mode: reuse an existing threat report

If you already ran `full-profile` or `threat-profile`, don't redo the recon:

```
/business-profiler:sales-targeting Nexagen nexagen.de Manufacturing Germany
> Use existing report at ./reports/threat_attack_surface_nexagen.md
```

The skill reads the threat report, extracts all the data, skips Phase 2 entirely, and goes straight to business intelligence and scoring. Saves 5-10 minutes.

### Enhanced mode: LinkedIn and Crunchbase

If you run Claude Code with Chrome MCP (`claude --chrome`), the skill also pulls:
- LinkedIn: CISO/CIO names, tenure, background, mutual connections
- Sales Navigator: buyer intent signals
- Crunchbase: IT spend, growth score, funding history

Without it, contact data comes from WebSearch (less detailed but still functional). The report notes what's missing.

---

## 3. Typical workflow

Most users run two skills in sequence:

```
# Step 1: Technical assessment
/business-profiler:full-profile Nexagen nexagen.de Manufacturing Germany

# Step 2: Sales strategy (reuses the threat report)
/business-profiler:sales-targeting Nexagen nexagen.de Manufacturing Germany
> Use existing report at ./reports/threat_attack_surface_nexagen.md
```

Step 1 produces the threat intelligence for your security team. Step 2 turns it into something the account executive can act on. Both share the same data — no duplicate scanning.

---

## What the reports look like

Due to confidentiality, we can't share reports from real companies. The sample reports in `docs/sample-reports/` are based on a fictional company called **Nexagen GmbH** — a mid-size German manufacturer we invented. The structure, depth, and format match what you'd get from a real run, but all data is fabricated.
