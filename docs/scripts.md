# Scripts Reference

All scripts are standalone CLI tools that output JSON to stdout. They can be used independently or orchestrated by the skills.

## Reconnaissance

### subdomain_enum.py

Enumerates subdomains from three free sources: crt.sh, HackerTarget, AlienVault OTX.

```bash
python3 scripts/subdomain_enum.py --domain shell.com --max-results 100
```

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | Yes | Target domain |
| `--max-results` | No | Max subdomains to return (default: 100) |

### ssl_analyzer.py

Analyzes SSL/TLS certificate and connection security. Uses Python stdlib only.

```bash
python3 scripts/ssl_analyzer.py --domain shell.com
python3 scripts/ssl_analyzer.py --domain shell.com --port 8443
```

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | Yes | Domain to analyze |
| `--port` | No | Port (default: 443) |

**Output fields:** certificate (subject, issuer, SANs, expiry), tls_version, cipher_suite, security_issues, risk_level (CRITICAL/HIGH/MEDIUM/LOW).

### tech_stack_detector.py

Fingerprints web technologies via HTTP headers and HTML content analysis. Detects web servers, CMS, JS frameworks, analytics, payment processors, CDN/WAF, and 90+ third-party services.

```bash
python3 scripts/tech_stack_detector.py --domain shell.com
```

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | Yes | Domain to analyze (auto-prepends `https://`) |

**Requires:** httpx, beautifulsoup4

### cloud_detector.py

Detects cloud providers by resolving subdomain IPs and looking up ASN ownership.

```bash
python3 scripts/cloud_detector.py --ips 104.18.12.33 104.18.13.33
```

| Flag | Required | Description |
|------|----------|-------------|
| `--ips` | Yes | Space-separated IP addresses |

### whois_lookup.py

WHOIS/RDAP domain registration lookup via the free rdap.org bootstrap service.

```bash
python3 scripts/whois_lookup.py --domain shell.com
```

## Email & Collaboration

### m365_detector.py

Detects Microsoft 365 tenants via MX records, GetCredentialType API, and OpenID configuration.

```bash
python3 scripts/m365_detector.py --domain shell.com
```

### google_workspace_detector.py

Detects Google Workspace via MX records, SPF includes, and DKIM selectors.

```bash
python3 scripts/google_workspace_detector.py --domain shell.com
```

### email_security.py

Audits SPF, DKIM, and DMARC records with pass/warn/fail grading.

```bash
python3 scripts/email_security.py --domain shell.com
```

## Threat Intelligence

### breach_intel.py

Queries XposedOrNot for domain breach history and optionally matches CISA KEV vulnerabilities against a detected tech stack.

```bash
# Domain breach lookup
python3 scripts/breach_intel.py --domain shell.com

# With CISA KEV matching (pass tech names from tech_stack_detector)
python3 scripts/breach_intel.py --domain shell.com --kev --tech-products 'apache,nginx,wordpress'

# With explicit vendor/product JSON
python3 scripts/breach_intel.py --domain shell.com --kev --tech-products '[{"vendor":"apache","product":"http server"}]'
```

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | Yes | Domain to check |
| `--kev` | No | Enable CISA KEV matching |
| `--tech-products` | No | Comma-separated tech names or JSON array of vendor/product dicts |

### mitre_client.py

Queries MITRE ATT&CK STIX data (cached from GitHub) for threat actors and techniques.

```bash
# Actors by sector
python3 scripts/mitre_client.py --sector Energy --limit 8

# Actor techniques
python3 scripts/mitre_client.py --actor "Sandworm Team"

# ICS/OT actors
python3 scripts/mitre_client.py --ot
```

## Business Intelligence

### wikidata_search.py

Searches Wikipedia/Wikidata for company data: sector, employees, revenue, headquarters, subsidiaries, CEO, stock ticker.

```bash
python3 scripts/wikidata_search.py --company "Shell" --country "Netherlands"
```

| Flag | Required | Description |
|------|----------|-------------|
| `--company` | Yes | Company name |
| `--country` | No | Country for disambiguation |

### financial_estimator.py

Estimates IT and cybersecurity spend from revenue, sector, and employee count using industry benchmarks. Pure computation, no network calls.

```bash
python3 scripts/financial_estimator.py --sector Energy --revenue '$280B' --employees 90000
python3 scripts/financial_estimator.py --sector Technology --revenue '$25.3B' --risk-level HIGH --incidents 2 --compliance
```

| Flag | Required | Description |
|------|----------|-------------|
| `--sector` | Yes | Industry sector |
| `--revenue` | No | Annual revenue (e.g., `$25.3B`, `150M`) |
| `--employees` | No | Total employee count |
| `--risk-level` | No | CRITICAL, HIGH, MEDIUM, or LOW |
| `--incidents` | No | Incidents in last 24 months |
| `--compliance` | No | Flag if major compliance mandates apply |

### regulatory_analyzer.py

Identifies applicable regulations, deadlines, urgency, and penalties based on sector and country. Pure computation, no network calls.

```bash
python3 scripts/regulatory_analyzer.py --sector "Financial Services" --country "Netherlands" --eu-customers
```

| Flag | Required | Description |
|------|----------|-------------|
| `--sector` | Yes | Industry sector |
| `--country` | Yes | HQ country |
| `--eu-customers` | No | Serves EU customers |
| `--processes-payments` | No | Processes credit cards |
| `--cloud-provider` | No | Provides cloud/SaaS |
| `--defense-contractor` | No | Defense supply chain |

**Regulation database:** NIS2, DORA, CRA, GDPR, HIPAA, PCI-DSS, SOC2, CMMC.

## Utilities

### setup.py

Checks and installs Python dependencies.

```bash
python3 scripts/setup.py --check    # Check only
python3 scripts/setup.py --install  # Install missing
python3 scripts/setup.py            # Check + install
```

### pdf_generator.py

Converts a Markdown report to a styled PDF using WeasyPrint. Uses the Peach Studio orange theme.

```bash
python3 scripts/pdf_generator.py --input report.md --output report.pdf --title "Shell Threat Profile"
```

| Flag | Required | Description |
|------|----------|-------------|
| `--input` | Yes | Input markdown file |
| `--output` | Yes | Output PDF path |
| `--title` | No | PDF document title |

**Mermaid diagram support:** If `mmdc` ([mermaid-cli](https://github.com/mermaid-js/mermaid-cli)) is installed, Mermaid code blocks in the markdown are automatically rendered to PNG images in the PDF. Without it, diagrams fall back to a text representation. Install with:

```bash
npm install -g @mermaid-js/mermaid-cli
```

### config.py

Loads optional API keys from `~/.config/business-profiler/config.json` or environment variables. Not required for core functionality.
