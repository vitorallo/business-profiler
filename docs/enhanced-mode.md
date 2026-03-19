# Enhanced Mode

The `sales-targeting` skill can optionally use browser tools to pull contact and financial data from LinkedIn, Sales Navigator, and Crunchbase. Without it, the skill still works fine using WebSearch.

## What Enhanced Mode Provides

| Data Source | Without Browser Tools | With Browser Tools |
|------------|----------------------|-------------------|
| **Contacts** | WebSearch results (names, titles) | LinkedIn profiles (tenure, background, mutual connections) |
| **Buyer Intent** | Not available | Sales Navigator signals (intent badges, company followers) |
| **Financial Data** | WebSearch + Wikidata + financial_estimator | Crunchbase (IT spend, growth score, heat score, funding) |
| **Org Chart** | Estimated from web search | LinkedIn-verified security team structure |

## How It Works

At startup, the skill checks if you have browser tools available. If so, it opens LinkedIn, Sales Navigator, and Crunchbase in your actual browser (using your logins) and pulls data from there.

No browser tools? Phase 3.5 gets skipped. The report uses what WebSearch found and notes what's missing.

## Setup

Enhanced mode requires a browser tool that can access **your authenticated browser sessions** — specifically your LinkedIn, Sales Navigator, and Crunchbase logins.

### Chrome MCP (Recommended)

The Chrome extension approach uses your real Chrome browser with all your existing logins. Run Claude Code with the `--chrome` flag:

```bash
claude --chrome
```

This connects to the Claude-in-Chrome extension, which navigates in your actual browser tabs with your authenticated sessions.

### Other Authenticated Browser Tools

Any MCP server that can control your real browser (not a headless one) will work. The key requirement is access to your existing login sessions.

### Why Playwright MCP Does NOT Work for Enhanced Mode

Playwright MCP opens a **fresh headless browser** with no login sessions. When it navigates to LinkedIn or Sales Navigator, it sees the login page — not your data. The skill detects this and skips enhanced mode when only Playwright is available.

Playwright is still useful for scraping public pages, but enhanced mode specifically needs authenticated access to:
- LinkedIn (contact profiles, tenure, mutual connections)
- Sales Navigator (buyer intent signals)
- Crunchbase (financial metrics, IT spend)

## Privacy & Authentication

- Browser tools use **your** authenticated browser sessions. The plugin never stores credentials.
- LinkedIn, Sales Navigator, and Crunchbase access depends on your existing logins in the browser.
- If you're not logged in to a service, the browser tool will see the login page instead of data. The skill handles this gracefully and falls back to WebSearch.
- No data is sent to external APIs beyond what the browser normally loads.

## Without Enhanced Mode

Everything works without browser tools. You just get less detail:

- Contact intelligence comes from WebSearch (less detailed — may miss tenure, mutual connections)
- No buyer intent signals from Sales Navigator
- Financial data relies on Wikidata + industry benchmarks (no Crunchbase enrichment)
- The report notes these limitations in the intelligence gaps section
