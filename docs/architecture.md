# Architecture

## Plugin Structure

```
business-profiler/
├── .claude-plugin/
│   └── plugin.json              # Plugin manifest (name, version, skill list)
├── scripts/                     # Standalone CLI tools (Python, JSON output)
│   ├── setup.py                 # Dependency management
│   ├── config.py                # Optional API key loader
│   ├── subdomain_enum.py        # Subdomain enumeration (3 sources)
│   ├── m365_detector.py         # Microsoft 365 detection
│   ├── google_workspace_detector.py  # Google Workspace detection
│   ├── email_security.py        # SPF/DKIM/DMARC audit
│   ├── ssl_analyzer.py          # SSL/TLS certificate analysis
│   ├── tech_stack_detector.py   # Web technology fingerprinting
│   ├── whois_lookup.py          # RDAP domain lookup
│   ├── cloud_detector.py        # ASN-based cloud detection
│   ├── breach_intel.py          # XposedOrNot + CISA KEV
│   ├── wikidata_search.py       # Wikipedia/Wikidata company data
│   ├── mitre_client.py          # MITRE ATT&CK STIX client
│   ├── regulatory_analyzer.py   # Regulation/compliance analysis
│   ├── financial_estimator.py   # IT/cybersec spend estimation
│   └── pdf_generator.py         # Markdown to PDF
├── skills/                      # Skill definitions (SKILL.md files)
│   ├── full-profile/
│   │   ├── SKILL.md
│   │   └── references/
│   │       ├── report_template.md
│   │       ├── methodology.md
│   │       └── sector_mappings.md
│   ├── threat-profile/
│   ├── attack-surface/
│   ├── threat-actors/
│   ├── ot-ics-assessment/
│   ├── incident-lookup/
│   └── sales-targeting/
│       ├── SKILL.md
│       └── references/
│           ├── report_template.md
│           ├── service_opportunity_mapping.md
│           └── methodology.md
├── assets/
│   └── sector_threat_actors.json
├── docs/
└── README.md
```

## Design Principles

### Scripts are standalone

Every script in `scripts/` is a self-contained CLI tool:
- Takes arguments via `argparse`
- Outputs JSON to stdout
- Can be run independently outside of Claude
- No inter-script imports or shared state

### Skills are orchestrators

SKILL.md files instruct Claude which scripts to run, in what order, and how to synthesize the results. Claude executes the scripts via Bash, reads the JSON output, and generates the report.

### Free-first data sources

All core functionality uses free, keyless public APIs. Optional paid APIs (FOFA, SecurityTrails) extend coverage but are not required.

### Parallel execution

Skills run independent scripts simultaneously using parallel Bash tool calls. For example, Phase 2 of `full-profile` runs 8 scripts in parallel.

### Graceful degradation

Missing optional dependencies or API failures don't break the workflow. Scripts return empty results or error fields, and Claude adapts the report accordingly.

## Data Flow

```
User input (company, domain, sector, country)
    │
    ▼
Phase 1: setup.py --check
    │
    ▼
Phase 2: Parallel recon scripts ──────────────────────┐
    │ subdomain_enum    → subdomains, IPs             │
    │ m365_detector     → M365 tenant info            │
    │ google_workspace  → Google Workspace presence    │
    │ email_security    → SPF/DKIM/DMARC grades       │
    │ whois_lookup      → registration data            │
    │ ssl_analyzer      → cert + TLS security          │
    │ tech_stack        → technologies + vendors       │
    │ breach_intel      → domain breaches              │
    └──────────────────────────────────────────────────┘
    │
    ▼
Phase 2.5: wikidata_search → company profile (employees, revenue)
    │
    ▼
Phase 3: cloud_detector (using IPs from subdomain_enum)
    │
    ▼
Phase 4: Threat intelligence
    │ mitre_client         → actors + TTPs
    │ regulatory_analyzer  → applicable regulations
    │ financial_estimator  → IT/cybersec spend estimates
    │ breach_intel --kev   → CISA KEV matches (using tech_stack output)
    │ WebSearch            → incidents, trends
    │
    ▼
Phase 5: OT/ICS (conditional)
    │
    ▼
Phase 6: Claude synthesizes all data → Markdown report → PDF
```

### sales-targeting Data Flow

The `sales-targeting` skill extends the standard pipeline with business intelligence, contact research, and sales-specific analysis:

```
User input (company, domain, sector, country)
    │
    ▼
Phase 1: setup.py --check + ingest existing data (if provided)
    │
    ├── Existing threat report provided? ──YES──▶ Extract data, skip Phase 2
    │
    ▼ (NO)
Phase 2: Full recon pipeline (same as full-profile)
    │ 8 parallel recon scripts + cloud_detector
    │ mitre_client (sector actors + TTPs)
    │ breach_intel --kev (CISA KEV matching)
    │ WebSearch (incidents)
    │
    ▼
Phase 3: Business & financial intelligence (parallel)
    │ wikidata_search     → company profile
    │ financial_estimator → IT/security spend estimates
    │ regulatory_analyzer → applicable regulations + deadlines
    │ WebSearch × 5       → financials, contacts, buyer intent, regulatory posture
    │
    ├── Browser tools available? ──YES──▶ Phase 3.5: Enhanced mode
    │                                     │ LinkedIn    → contacts, tenure, mutual connections
    │                                     │ Sales Nav   → buyer intent signals
    │                                     │ Crunchbase  → IT spend, growth/heat scores
    │                                     ▼
    ▼
Phase 4: Analysis & scoring
    │ Read references/methodology.md
    │ Score: financial capacity, threat severity, regulatory pressure
    │ Read references/service_opportunity_mapping.md
    │ Map pain points → 38-service catalog (scaled to company size)
    │ Calculate 3-year revenue opportunity
    │ Classify account: STRATEGIC PARTNER / KEY ACCOUNT / TARGET ACCOUNT
    │
    ▼
Phase 5: Report generation
    │ Read references/report_template.md
    │ Generate 6-part Strategic Account Targeting Report
    │ Save markdown → pdf_generator.py → PDF
    │
    ▼
Phase 6: Quality checklist + intelligence gaps
```
