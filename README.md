# Business Profiler

Claude Code plugin for cybersecurity threat intelligence and attack surface profiling. Runs recon, pulls breach data, maps threat actors, checks regulatory exposure, and create a target threat profile (aligned with SANS Threat Intel profiling methodology), produces the report in MarkDown and PDF.

It also includes a sales targeting skill that builds account strategy reports from real threat data. Useful for cybersecurity sales teams who want to show prospects what they're actually exposed to and have a meaninful discussion with CISOs and Security Offices about their real pains and not generic threats. Works well as a KYC tool too.

No external AI APIs. Claude does the analysis. All data sources are free and keyless.

## Install

### From the PEACH STUDIO marketplace

```bash
# Add the marketplace
/plugin marketplace add vitorallo/peach-studio-marketplace

# Install the plugin
/plugin install business-profiler@peach-studio

# Reload to apply
/reload-plugins
```

### From source

```bash
git clone https://github.com/vitorallo/business-profiler.git
cd business-profiler
python3 scripts/setup.py --venv    # creates .venv and installs dependencies
source .venv/bin/activate
```

Then load the plugin:

**Claude Code (CLI)**
```bash
/plugin marketplace add ./business-profiler
/plugin install business-profiler@business-profiler
/reload-plugins
```

**Claude Desktop**
1. Open the **Code tab** > click **+** > **Plugins** > **Add plugin**
2. Enter the local path to the `business-profiler` directory
3. Choose your scope (user, project, or local)

**VS Code Extension**
1. Type `/plugins` > **Marketplaces** tab > add the local `business-profiler` directory
2. Install from the **Plugins** tab

### Verify

Type `/business-profiler:` and tab-complete to see available skills.

```bash
python3 scripts/setup.py --check   # verify dependencies
```

## Usage

```
/business-profiler:full-profile Shell shell.com Energy Netherlands
/business-profiler:attack-surface shell.com
/business-profiler:threat-profile Shell shell.com Energy Netherlands
/business-profiler:threat-actors Energy
/business-profiler:ot-ics-assessment Shell shell.com Energy Netherlands
/business-profiler:incident-lookup Shell
/business-profiler:sales-targeting Shell shell.com Energy Netherlands
```

## Skills

| Skill | What it does |
|-------|-------------|
| `full-profile` | Complete assessment: recon + business intel + threats + regulatory + report + PDF |
| `threat-profile` | Threat actors, TTPs, incidents, risk analysis |
| `attack-surface` | Infrastructure reconnaissance and exposure mapping |
| `threat-actors` | MITRE ATT&CK actor lookup by sector, country, or name |
| `ot-ics-assessment` | OT/ICS/SCADA focused assessment (improved by FOFA if you have an optional KEY) |
| `incident-lookup` | Security breach and incident research |
| `sales-targeting` | Strategic account targeting: 6-part sales report with 38-service catalog, financial/regulatory/contact intelligence |

### Sales Targeting

Run `sales-targeting` to turn a threat assessment into something your sales team can actually use. It builds a 6-part report with service pricing, contact research, and a week-by-week engagement plan.

```
# Full pipeline — runs recon + threat intel + business intel automatically
/business-profiler:sales-targeting Shell shell.com Energy Netherlands

# Fast mode — feed an existing threat report, skip recon entirely
/business-profiler:sales-targeting Shell shell.com Energy Netherlands
> Use existing report at ./reports/threat_attack_surface_shell.md
```

**What it produces:**
- Account classification (STRATEGIC PARTNER / KEY ACCOUNT / TARGET ACCOUNT) with 3-year revenue opportunity
- 6-part report: Opportunity, Pain, Deadline, Approach, Campaign, Action Plan
- Service mapping from a 38-service catalog across 6 categories (assessments, integration, managed services, GRC, IR, training)
- Contact intelligence and engagement strategy for CISO/CIO outreach

**Enhanced mode (optional):** If you have Chrome MCP set up or can use Playwright MCP (authenticating on your account), the skill also pulls data from LinkedIn, Sales Navigator, and Crunchbase. See [Enhanced Mode](docs/enhanced-mode.md).

## Data Sources

All free, no API keys:

| Capability | Source |
|-----------|--------|
| Subdomains | crt.sh, HackerTarget, AlienVault OTX |
| Cloud detection | ipinfo.io |
| M365 / Google Workspace | DNS + Microsoft API |
| Email security | SPF/DKIM/DMARC via DNS |
| SSL/TLS | Python ssl stdlib |
| Tech stack | HTTP headers + HTML fingerprinting |
| Breach intelligence | XposedOrNot |
| Known vulnerabilities | CISA KEV |
| Company data | Wikipedia/Wikidata |
| WHOIS | RDAP |
| Threat actors | MITRE ATT&CK STIX |
| Regulatory analysis | Built-in database (NIS2, DORA, GDPR, HIPAA, PCI-DSS, SOC2, CMMC, CRA) |
| Financial estimates | Industry benchmarks |
| Incidents | WebSearch (via Claude) |

## Output

Reports are saved to `./reports/` as Markdown and PDF.

## Documentation

See [`docs/`](docs/) for detailed documentation:

- [Scripts Reference](docs/scripts.md) — All 15 standalone tools with CLI usage
- [Skills Guide](docs/skills.md) — How each skill orchestrates the tools
- [Architecture](docs/architecture.md) — How the plugin is structured
- [Data Sources](docs/data-sources.md) — Source details, rate limits, caveats
- [Enhanced Mode](docs/enhanced-mode.md) — Browser-based enrichment for sales-targeting
- [Troubleshooting](docs/troubleshooting.md) — Common issues and fixes

## Dependencies

Use a virtual environment so you don't pollute your system Python:

```bash
# One-time setup
cd business-profiler
python3 -m venv .venv
source .venv/bin/activate
python3 scripts/setup.py --install
```

Or let the setup script create the venv for you:

```bash
python3 scripts/setup.py --venv
source .venv/bin/activate
```

Always activate the venv before running the plugin:

```bash
source .venv/bin/activate
```

### Python packages

Installed by `setup.py`:

- `httpx` — HTTP client
- `dnspython` — DNS queries
- `weasyprint` — PDF generation
- `markdown2` — Markdown to HTML
- `beautifulsoup4` — HTML parsing

### Mermaid diagrams in PDFs (recommended)

Reports use [Mermaid](https://mermaid.js.org/) for org charts, attack surface diagrams, and regulatory timelines. These render natively in GitHub, VS Code, and most Markdown viewers.

To render them in **PDF output**, install the Mermaid CLI (requires Node.js):

```bash
npm install -g @mermaid-js/mermaid-cli
```

With `mmdc` installed, `pdf_generator.py` automatically converts Mermaid blocks to embedded PNG images in the PDF. Without it, diagrams fall back to a text-based representation in the PDF.

## License

MIT

---

Built by [PEACH STUDIO](https://www.peachstudio.be)
