#!/usr/bin/env python3
"""Cloud provider detection from IP addresses using ASN mapping.

Uses ipinfo.io (free: 50K requests/month) for ASN lookup.
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import time
from typing import Any, Optional

import httpx

CLOUD_ASNS = {
    "AS16509": "AWS", "AS14618": "AWS", "AS8987": "AWS",
    "AS8075": "Azure", "AS8068": "Azure",
    "AS15169": "GCP", "AS19527": "GCP", "AS36040": "GCP",
    "AS31898": "Oracle Cloud",
    "AS14061": "DigitalOcean",
    "AS13335": "Cloudflare", "AS209242": "Cloudflare",
    "AS20940": "Akamai", "AS16625": "Akamai",
    "AS54113": "Fastly",
    "AS24940": "Hetzner",
    "AS16276": "OVH",
    "AS63949": "Linode/Akamai",
}

ORG_KEYWORDS = {
    "amazon": "AWS", "aws": "AWS",
    "microsoft": "Azure", "azure": "Azure",
    "google": "GCP", "gcp": "GCP",
    "oracle": "Oracle Cloud",
    "digitalocean": "DigitalOcean",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "hetzner": "Hetzner",
    "ovh": "OVH",
}


def detect_cloud_from_asn(asn: str, org_name: str = "") -> Optional[str]:
    if asn in CLOUD_ASNS:
        return CLOUD_ASNS[asn]
    org_lower = org_name.lower()
    for keyword, provider in ORG_KEYWORDS.items():
        if keyword in org_lower:
            return provider
    return None


def analyze_ip(ip: str, delay: float = 0.3) -> dict[str, Any]:
    result = {
        "ip": ip, "is_cloud": False, "cloud_provider": None,
        "asn": None, "organization": None, "country": None, "city": None,
    }
    try:
        time.sleep(delay)
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"https://ipinfo.io/{ip}/json")

        if resp.status_code == 200:
            data = resp.json()
            org_field = data.get("org", "")
            asn, org_name = None, org_field
            if org_field.startswith("AS"):
                parts = org_field.split(" ", 1)
                asn = parts[0]
                org_name = parts[1] if len(parts) > 1 else org_field

            result.update({
                "asn": asn, "organization": org_name,
                "country": data.get("country"), "city": data.get("city"),
                "region": data.get("region"), "hostname": data.get("hostname"),
            })
            provider = detect_cloud_from_asn(asn or "", org_name)
            if provider:
                result["is_cloud"] = True
                result["cloud_provider"] = provider
        elif resp.status_code == 429:
            result["error"] = "Rate limit exceeded"
    except Exception as e:
        result["error"] = str(e)
    return result


def detect_cloud_providers(ip_addresses: list[str]) -> dict[str, Any]:
    ips = ip_addresses[:20]
    results = [analyze_ip(ip) for ip in ips]

    cloud_ips = [r for r in results if r["is_cloud"]]
    providers: dict[str, list] = {}
    for r in cloud_ips:
        providers.setdefault(r["cloud_provider"], []).append(r["ip"])

    return {
        "total_analyzed": len(results),
        "cloud_hosted": len(cloud_ips),
        "providers_found": providers,
        "results": results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect cloud providers for IP addresses")
    parser.add_argument("--ips", required=True, nargs="+", help="IP addresses to analyze")
    args = parser.parse_args()

    result = detect_cloud_providers(args.ips)
    print(json.dumps(result, indent=2))
