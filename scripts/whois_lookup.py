#!/usr/bin/env python3
"""WHOIS lookup via RDAP protocol (free, no API key).

RDAP (Registration Data Access Protocol) is the modern replacement for WHOIS.
Uses rdap.org bootstrap service to find the correct RDAP server.
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

import httpx


def rdap_lookup(domain: str) -> dict[str, Any]:
    """Perform RDAP lookup for a domain.

    Args:
        domain: Domain to look up

    Returns:
        Dict with registrar, dates, nameservers, status
    """
    result = {
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "nameservers": [],
        "status": [],
        "registrant_country": None,
    }

    try:
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            resp = client.get(f"https://rdap.org/domain/{domain}")

        if resp.status_code != 200:
            result["error"] = f"RDAP lookup failed: HTTP {resp.status_code}"
            return result

        data = resp.json()

        # Registrar
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = field[3]
                            break

        # Events (dates)
        for event in data.get("events", []):
            action = event.get("eventAction")
            date = event.get("eventDate")
            if action == "registration":
                result["creation_date"] = date
            elif action == "expiration":
                result["expiration_date"] = date
            elif action == "last changed":
                result["updated_date"] = date

        # Nameservers
        for ns in data.get("nameservers", []):
            ns_name = ns.get("ldhName")
            if ns_name:
                result["nameservers"].append(ns_name.lower())

        # Status
        result["status"] = data.get("status", [])

        # Registrant country (if available)
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrant" in roles:
                vcard = entity.get("vcardArray", [None, []])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "adr" and len(field) > 3:
                            addr = field[3] if isinstance(field[3], list) else []
                            if addr and len(addr) >= 7:
                                result["registrant_country"] = addr[6] or None

    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WHOIS lookup via RDAP")
    parser.add_argument("--domain", required=True, help="Domain to look up")
    args = parser.parse_args()

    print(json.dumps(rdap_lookup(args.domain), indent=2))
