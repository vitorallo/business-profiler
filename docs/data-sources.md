# Data Sources

All core data sources are free and require no API keys.

## Reconnaissance

### crt.sh
- **Used by:** `subdomain_enum.py`
- **What:** Certificate Transparency log search
- **Rate limit:** No hard limit, but be reasonable
- **URL:** `https://crt.sh/?q=%25.<domain>&output=json`

### HackerTarget
- **Used by:** `subdomain_enum.py`
- **What:** Passive DNS subdomain lookup
- **Rate limit:** 100 queries/day (free tier)
- **URL:** `https://api.hackertarget.com/hostsearch/?q=<domain>`

### AlienVault OTX
- **Used by:** `subdomain_enum.py`
- **What:** Open Threat Exchange passive DNS
- **Rate limit:** Generous, no key needed for passive DNS
- **URL:** `https://otx.alienvault.com/api/v1/indicators/domain/<domain>/passive_dns`

### ipinfo.io
- **Used by:** `cloud_detector.py`
- **What:** IP to ASN mapping for cloud provider detection
- **Rate limit:** 50,000 requests/month (free, no key)
- **URL:** `https://ipinfo.io/<ip>/json`

### RDAP
- **Used by:** `whois_lookup.py`
- **What:** Modern WHOIS replacement, structured JSON
- **Rate limit:** Varies by registrar, generally permissive
- **URL:** `https://rdap.org/domain/<domain>` (bootstrap service)

## Email & Identity

### Microsoft GetCredentialType API
- **Used by:** `m365_detector.py`
- **What:** Detects M365 tenant existence and federation status
- **Rate limit:** Not documented, use responsibly
- **URL:** `https://login.microsoftonline.com/common/GetCredentialType`

### Microsoft OpenID Configuration
- **Used by:** `m365_detector.py`
- **What:** Extracts tenant UUID
- **URL:** `https://login.microsoftonline.com/<domain>/.well-known/openid-configuration`

### DNS (MX, TXT, DKIM)
- **Used by:** `m365_detector.py`, `google_workspace_detector.py`, `email_security.py`
- **What:** MX records, SPF/DKIM/DMARC TXT records
- **Rate limit:** Depends on resolver, effectively unlimited

### Python ssl stdlib
- **Used by:** `ssl_analyzer.py`
- **What:** Direct TLS handshake for certificate and cipher analysis
- **Rate limit:** N/A (direct connections)

## Threat Intelligence

### XposedOrNot
- **Used by:** `breach_intel.py`
- **What:** Domain-level breach history
- **Rate limit:** Free, no key. Be reasonable.
- **URL:** `https://api.xposedornot.com/v1/domain-breaches/<domain>`

### CISA KEV
- **Used by:** `breach_intel.py`
- **What:** Known Exploited Vulnerabilities catalog (1100+ CVEs)
- **Rate limit:** Static JSON file, cached 24h locally
- **URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

### MITRE ATT&CK STIX
- **Used by:** `mitre_client.py`
- **What:** Threat actor profiles, TTPs, relationships
- **Rate limit:** Static JSON from GitHub, cached 7 days
- **URL:** GitHub MITRE CTI repository

### Wikipedia / Wikidata
- **Used by:** `wikidata_search.py`
- **What:** Company metadata (industry, employees, revenue, subsidiaries, CEO)
- **Rate limit:** Generous. Uses Wikidata API and EntityData endpoints.
- **URL:** `https://www.wikidata.org/w/api.php`

## Analysis (No Network)

### Regulatory Database
- **Used by:** `regulatory_analyzer.py`
- **What:** Built-in database of 8 regulations (NIS2, DORA, CRA, GDPR, HIPAA, PCI-DSS, SOC2, CMMC)
- **Coverage:** EU, US, and Global regulations
- **Note:** Deadlines and penalties are hardcoded and should be reviewed periodically

### Financial Benchmarks
- **Used by:** `financial_estimator.py`
- **What:** Industry benchmark multipliers for IT spend (2-12% of revenue) and cybersecurity spend (5-15% of IT budget)
- **Coverage:** 10+ sectors
- **Note:** All outputs are clearly marked as estimations

## Optional Paid APIs

These are **not required** for core functionality. Configure in `~/.config/business-profiler/config.json`:

| API | Key | What it adds |
|-----|-----|-------------|
| FOFA | `fofa_email`, `fofa_key` | Additional subdomain and asset discovery |
| SecurityTrails | `securitytrails_key` | Historical DNS data |
