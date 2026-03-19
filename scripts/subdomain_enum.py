#!/usr/bin/env python3
"""Subdomain enumeration using free passive OSINT sources.

Sources: crt.sh (Certificate Transparency), HackerTarget, AlienVault OTX.
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import time
from typing import Any

import httpx

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


async def _enumerate_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    subdomains = set()
    try:
        response = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json", timeout=60.0
        )
        if response.status_code == 200:
            for entry in response.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().replace("*.", "")
                    if name.endswith(f".{domain}") and name != domain:
                        subdomains.add(name)
    except Exception:
        pass
    return subdomains


async def _enumerate_hackertarget(client: httpx.AsyncClient, domain: str) -> set[str]:
    subdomains = set()
    try:
        response = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}"
        )
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith(f".{domain}"):
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains


async def _enumerate_alienvault(client: httpx.AsyncClient, domain: str) -> set[str]:
    subdomains = set()
    try:
        response = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        )
        if response.status_code == 200:
            for entry in response.json().get("passive_dns", []):
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(f".{domain}") and hostname != domain:
                    subdomains.add(hostname)
    except Exception:
        pass
    return subdomains


async def enumerate_async(
    domain: str, max_results: int = 100, resolve_dns: bool = True
) -> dict[str, Any]:
    start = time.time()
    domain = domain.lower().strip()

    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", domain):
        return {"error": f"Invalid domain: {domain}", "subdomains": []}

    subdomains: dict[str, dict] = {}
    sources_used = []

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        tasks = [
            _enumerate_crtsh(client, domain),
            _enumerate_hackertarget(client, domain),
            _enumerate_alienvault(client, domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for source_name, result in zip(["crt.sh", "hackertarget", "alienvault"], results):
            if isinstance(result, set) and result:
                sources_used.append(source_name)
                for sub in result:
                    if sub not in subdomains:
                        subdomains[sub] = {"hostname": sub, "sources": [], "ips": [], "resolved": False}
                    subdomains[sub]["sources"].append(source_name)

    resolved_count = 0
    if resolve_dns and HAS_DNS and subdomains:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 3
        resolver.lifetime = 3

        for hostname in list(subdomains.keys())[: max_results * 2]:
            try:
                answers = resolver.resolve(hostname, "A")
                subdomains[hostname]["resolved"] = True
                subdomains[hostname]["ips"] = [str(r) for r in answers]
                resolved_count += 1
            except Exception:
                pass

    sorted_subs = sorted(
        subdomains.values(), key=lambda x: (not x["resolved"], x["hostname"])
    )[:max_results]

    return {
        "domain": domain,
        "total_found": len(subdomains),
        "total_resolved": resolved_count,
        "sources_used": sources_used,
        "subdomains": sorted_subs,
        "enumeration_time_seconds": round(time.time() - start, 2),
    }


def enumerate_subdomains(domain: str, max_results: int = 100, resolve_dns: bool = True) -> dict:
    try:
        asyncio.get_running_loop()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, enumerate_async(domain, max_results, resolve_dns)).result(timeout=120)
    except RuntimeError:
        return asyncio.run(enumerate_async(domain, max_results, resolve_dns))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enumerate subdomains for a domain")
    parser.add_argument("--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--max-results", type=int, default=100, help="Max subdomains to return")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution")
    args = parser.parse_args()

    result = enumerate_subdomains(args.domain, args.max_results, not args.no_resolve)
    print(json.dumps(result, indent=2))
