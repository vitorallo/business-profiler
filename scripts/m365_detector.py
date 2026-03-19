#!/usr/bin/env python3
"""Microsoft 365 tenant detection.

Methods: MX record analysis, GetCredentialType API, OpenID configuration.
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Optional

import httpx

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def check_mx_records(domain: str) -> dict[str, Any]:
    if not HAS_DNS:
        return {"has_m365_mx": False, "mx_records": [], "error": "dnspython not installed"}

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        answers = resolver.resolve(domain, "MX")
        mx_records = [
            {"host": str(r.exchange).rstrip("."), "priority": r.preference}
            for r in answers
        ]

        m365_patterns = [
            ".mail.protection.outlook.com",
            ".mail.eo.outlook.com",
            ".protection.outlook.com",
            "mail.messaging.microsoft.com",
        ]
        has_m365 = any(
            any(p in mx["host"] for p in m365_patterns) for mx in mx_records
        )
        return {"has_m365_mx": has_m365, "mx_records": mx_records, "mx_count": len(mx_records)}
    except Exception as e:
        return {"has_m365_mx": False, "mx_records": [], "error": str(e)}


def check_credential_type(domain: str) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                "https://login.microsoftonline.com/common/GetCredentialType",
                json={"Username": f"nonexistent@{domain}"},
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
        if resp.status_code == 200:
            data = resp.json()
            if_exists = data.get("IfExistsResult", 1)
            return {
                "has_m365": if_exists in [0, 5, 6],
                "if_exists_result": if_exists,
                "is_federated": data.get("IsFederatedDomain", False),
            }
        return {"has_m365": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"has_m365": False, "error": str(e)}


def get_tenant_id(domain: str) -> Optional[str]:
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
            )
        if resp.status_code == 200:
            auth_ep = resp.json().get("authorization_endpoint", "")
            if "/oauth2/" in auth_ep:
                parts = auth_ep.split("/")
                for i, part in enumerate(parts):
                    if part == "oauth2" and i > 0:
                        tid = parts[i - 1]
                        if "-" in tid and len(tid) == 36:
                            return tid
    except Exception:
        pass
    return None


def detect_m365(domain: str) -> dict[str, Any]:
    result = {
        "domain": domain,
        "has_m365": False,
        "tenant_id": None,
        "detection_methods": [],
        "mx_records": [],
        "is_federated": False,
    }

    mx_data = check_mx_records(domain)
    result["mx_records"] = mx_data.get("mx_records", [])
    if mx_data.get("has_m365_mx"):
        result["has_m365"] = True
        result["detection_methods"].append("mx_records")

    cred_data = check_credential_type(domain)
    if cred_data.get("has_m365"):
        result["has_m365"] = True
        result["detection_methods"].append("credential_type_api")
        result["is_federated"] = cred_data.get("is_federated", False)

    if result["has_m365"]:
        tid = get_tenant_id(domain)
        if tid:
            result["tenant_id"] = tid
            result["detection_methods"].append("openid_config")

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect Microsoft 365 tenant information")
    parser.add_argument("--domain", required=True, help="Domain to check")
    args = parser.parse_args()

    print(json.dumps(detect_m365(args.domain), indent=2))
