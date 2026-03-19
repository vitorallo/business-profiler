#!/usr/bin/env python3
"""Google Workspace detection via DNS.

Methods: MX record analysis, SPF record checking, DKIM selector detection.
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging

logger = logging.getLogger("google_workspace_detector")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

GOOGLE_MX_PATTERNS = [
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com",
    "gmr-smtp-in.l.google.com",
    "googlemail.com",
]

GOOGLE_DKIM_SELECTORS = ["google", "google1", "google2", "google3", "googlemail"]


def _make_resolver(timeout: int = 10) -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def check_mx_records(domain: str) -> dict:
    """Check MX records for Google Workspace patterns."""
    if not HAS_DNS:
        return {"has_google_mx": False, "mx_records": [], "error": "dnspython not installed"}

    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "MX")
        mx_records = [
            {"host": str(r.exchange).rstrip("."), "priority": r.preference}
            for r in answers
        ]

        has_google_mx = any(
            any(pattern in mx["host"].lower() for pattern in GOOGLE_MX_PATTERNS)
            for mx in mx_records
        )

        return {"has_google_mx": has_google_mx, "mx_records": mx_records, "mx_count": len(mx_records)}

    except dns.resolver.NXDOMAIN:
        logger.warning(f"Domain {domain} does not exist")
        return {"has_google_mx": False, "mx_records": [], "mx_count": 0}
    except dns.resolver.NoAnswer:
        logger.warning(f"No MX records found for {domain}")
        return {"has_google_mx": False, "mx_records": [], "mx_count": 0}
    except Exception as e:
        logger.error(f"Error checking MX records for {domain}: {e}")
        return {"has_google_mx": False, "mx_records": [], "mx_count": 0}


def check_spf_records(domain: str) -> dict:
    """Check SPF records for Google Workspace includes."""
    if not HAS_DNS:
        return {"has_google_spf": False, "spf_records": []}

    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "TXT")
        spf_records = []
        has_google_spf = False

        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                spf_records.append(txt)
                if "_spf.google.com" in txt or "include:_netblocks.google.com" in txt:
                    has_google_spf = True

        return {"has_google_spf": has_google_spf, "spf_records": spf_records}

    except dns.resolver.NoAnswer:
        return {"has_google_spf": False, "spf_records": []}
    except Exception as e:
        logger.debug(f"Error checking SPF records for {domain}: {e}")
        return {"has_google_spf": False, "spf_records": []}


def check_dkim_selectors(domain: str) -> dict:
    """Check for Google DKIM selectors."""
    if not HAS_DNS:
        return {"has_google_dkim": False, "dkim_selectors": []}

    resolver = _make_resolver()
    found_selectors = []

    for selector in GOOGLE_DKIM_SELECTORS:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")

            for rdata in answers:
                txt = str(rdata).strip('"')
                if "v=DKIM1" in txt or "k=rsa" in txt:
                    found_selectors.append(selector)
                    break

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except Exception:
            continue

    return {"has_google_dkim": len(found_selectors) > 0, "dkim_selectors": found_selectors}


def detect_google_workspace(domain: str) -> dict:
    """Comprehensive Google Workspace detection using multiple methods."""
    result = {
        "domain": domain,
        "has_google_workspace": False,
        "detection_methods": [],
        "mx_records": [],
        "spf_records": [],
        "dkim_selectors": [],
    }

    mx_data = check_mx_records(domain)
    result["mx_records"] = mx_data.get("mx_records", [])
    if mx_data.get("has_google_mx"):
        result["has_google_workspace"] = True
        result["detection_methods"].append("mx_records")

    spf_data = check_spf_records(domain)
    result["spf_records"] = spf_data.get("spf_records", [])
    if spf_data.get("has_google_spf"):
        result["has_google_workspace"] = True
        result["detection_methods"].append("spf_records")

    dkim_data = check_dkim_selectors(domain)
    result["dkim_selectors"] = dkim_data.get("dkim_selectors", [])
    if dkim_data.get("has_google_dkim"):
        result["has_google_workspace"] = True
        result["detection_methods"].append("dkim_selectors")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect Google Workspace presence")
    parser.add_argument("--domain", required=True, help="Domain to check")
    args = parser.parse_args()

    print(json.dumps(detect_google_workspace(args.domain), indent=2))
