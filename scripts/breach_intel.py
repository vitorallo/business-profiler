#!/usr/bin/env python3
"""External breach intelligence lookups.

Queries free, public APIs for domain-level breach history:
- XposedOrNot — domain breach search (free, no key)
- CISA KEV — known exploited vulnerabilities matched against tech stack

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import time

import httpx

logger = logging.getLogger("breach_intel")

# Module-level cache for CISA KEV (24h TTL)
_kev_cache: dict = {"vulnerabilities": [], "fetched_at": 0}
_CACHE_TTL = 86400  # 24 hours

_UA = "BusinessProfiler/1.0 (threat-intel-plugin)"

# Mega-corp vendors where vendor-only matching would produce hundreds of
# irrelevant CVEs.  For these, we require an exact vendor+product match.
_BROAD_VENDORS = {
    "google", "microsoft", "apple", "adobe", "oracle", "cisco",
    "ibm", "samsung", "facebook", "meta", "amazon", "intel",
}


# ---------------------------------------------------------------------------
# XposedOrNot — domain breach lookup
# ---------------------------------------------------------------------------

def lookup_xposedornot_breaches(domain: str) -> list[dict]:
    """Query XposedOrNot for domain-level breach data (free, no key).

    Returns list of dicts with: name, breach_date, exposed_data, records, source.
    """
    try:
        with httpx.Client(timeout=20) as client:
            resp = client.get(
                f"https://api.xposedornot.com/v1/domain-breaches/{domain}",
                headers={"User-Agent": _UA},
            )
            if resp.status_code != 200:
                logger.debug(f"XposedOrNot: {resp.status_code} for {domain}")
                return []

            data = resp.json()
            # XON response varies — handle both formats
            breaches_exposed = data.get("breaches_details") or data.get("exposedBreaches") or []
            if isinstance(breaches_exposed, dict):
                breaches_exposed = breaches_exposed.get("breaches_details", [])

            results = []
            for b in breaches_exposed:
                if isinstance(b, dict):
                    results.append({
                        "name": b.get("breach") or b.get("name", ""),
                        "breach_date": b.get("xposed_date") or b.get("date", ""),
                        "exposed_data": b.get("xposed_data") or b.get("data_types", ""),
                        "records": b.get("xposed_records") or b.get("records", 0),
                        "source": "xposedornot",
                    })
                elif isinstance(b, str):
                    results.append({
                        "name": b,
                        "source": "xposedornot",
                    })

            logger.info(f"XposedOrNot: {len(results)} breaches for {domain}")
            return results

    except Exception as e:
        logger.error(f"XposedOrNot error for {domain}: {e}")
        return []


# ---------------------------------------------------------------------------
# CISA KEV — Known Exploited Vulnerabilities
# ---------------------------------------------------------------------------

def _fetch_cisa_kev() -> list[dict]:
    """Fetch and cache the CISA KEV catalog (free, no key)."""
    now = time.time()
    if _kev_cache["vulnerabilities"] and (now - _kev_cache["fetched_at"]) < _CACHE_TTL:
        return _kev_cache["vulnerabilities"]

    try:
        with httpx.Client(timeout=30) as client:
            resp = client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                headers={"User-Agent": _UA},
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                _kev_cache["vulnerabilities"] = vulns
                _kev_cache["fetched_at"] = now
                logger.info(f"CISA KEV: cached {len(vulns)} vulnerabilities")
                return vulns
            else:
                logger.warning(f"CISA KEV API returned {resp.status_code}")
    except Exception as e:
        logger.error(f"CISA KEV fetch error: {e}")

    return _kev_cache["vulnerabilities"]


def lookup_cisa_kev(tech_products: list[dict]) -> list[dict]:
    """Match CISA KEV against detected technology stack.

    Args:
        tech_products: list of {"vendor": str, "product": str} dicts
                       extracted from tech_stack results.

    Returns list of matching KEV entries with CVE details.
    """
    if not tech_products:
        return []

    all_kev = _fetch_cisa_kev()
    if not all_kev:
        return []

    matches = []
    seen_cves = set()

    for tp in tech_products:
        vendor = (tp.get("vendor") or "").lower()
        product = (tp.get("product") or "").lower()
        if not vendor and not product:
            continue

        for kev in all_kev:
            kev_vendor = (kev.get("vendorProject") or "").lower()
            kev_product = (kev.get("product") or "").lower()
            cve_id = kev.get("cveID", "")

            if cve_id in seen_cves:
                continue

            matched = False
            if vendor and product:
                if vendor in kev_vendor and product in kev_product:
                    matched = True
                elif vendor == kev_vendor and vendor == kev_product:
                    matched = True
                elif vendor == kev_vendor and vendor not in _BROAD_VENDORS:
                    matched = True
            elif product and len(product) >= 4:
                if product == kev_product or product in kev_product:
                    matched = True
            elif vendor and len(vendor) >= 4 and vendor not in _BROAD_VENDORS:
                if vendor == kev_vendor:
                    matched = True

            if matched:
                seen_cves.add(cve_id)
                matches.append({
                    "cve_id": cve_id,
                    "vendor": kev.get("vendorProject", ""),
                    "product": kev.get("product", ""),
                    "vulnerability_name": kev.get("vulnerabilityName", ""),
                    "date_added": kev.get("dateAdded", ""),
                    "due_date": kev.get("dueDate", ""),
                    "known_ransomware_campaign": kev.get("knownRansomwareCampaignUse", "Unknown"),
                    "short_description": (kev.get("shortDescription") or "")[:300],
                })

    # Sort by date_added descending
    matches.sort(key=lambda x: x.get("date_added", ""), reverse=True)

    logger.info(f"CISA KEV: {len(matches)} matches against {len(tech_products)} tech products")
    return matches


# ---------------------------------------------------------------------------
# Tech-to-KEV mapping (used when --kev is passed with --tech-products)
# ---------------------------------------------------------------------------

TECH_TO_KEV = {
    "nginx": {"vendor": "nginx", "product": "nginx"},
    "apache": {"vendor": "apache", "product": "http server"},
    "iis": {"vendor": "microsoft", "product": "internet information services"},
    "wordpress": {"vendor": "wordpress", "product": "wordpress"},
    "drupal": {"vendor": "drupal", "product": "drupal"},
    "joomla": {"vendor": "joomla", "product": "joomla!"},
    "magento": {"vendor": "adobe", "product": "magento"},
    "shopify": {"vendor": "shopify", "product": "shopify"},
    "php": {"vendor": "php", "product": "php"},
    "asp.net": {"vendor": "microsoft", "product": ".net framework"},
    "jquery": {"vendor": "jquery", "product": "jquery"},
    "cloudflare": {"vendor": "cloudflare", "product": "cloudflare"},
    "varnish": {"vendor": "varnish", "product": "varnish cache"},
}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Breach intelligence lookups")
    parser.add_argument("--domain", required=True, help="Domain to check")
    parser.add_argument("--kev", action="store_true", help="Run CISA KEV matching (requires --tech-products)")
    parser.add_argument("--tech-products", type=str, default="",
                        help='JSON array of {"vendor","product"} dicts, or comma-separated tech names')
    args = parser.parse_args()

    result = {"domain": args.domain}

    # Always run XposedOrNot domain breach lookup
    result["breaches"] = lookup_xposedornot_breaches(args.domain)
    result["breach_count"] = len(result["breaches"])

    # Optionally run CISA KEV matching
    if args.kev and args.tech_products:
        tech_input = args.tech_products.strip()
        if tech_input.startswith("["):
            # JSON array of {"vendor","product"} dicts
            tech_products = json.loads(tech_input)
        else:
            # Comma-separated tech names — map through TECH_TO_KEV
            tech_products = []
            for name in tech_input.split(","):
                name = name.strip().lower()
                if name in TECH_TO_KEV:
                    tech_products.append(TECH_TO_KEV[name])

        result["kev_matches"] = lookup_cisa_kev(tech_products)
        result["kev_match_count"] = len(result["kev_matches"])

    print(json.dumps(result, indent=2))
