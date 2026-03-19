#!/usr/bin/env python3
"""Email security audit: SPF, DKIM, DMARC record analysis.

Uses DNS queries only (free, no API key required).
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def _query_txt(domain: str, timeout: int = 10) -> list[str]:
    if not HAS_DNS:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, "TXT")
        return [str(r).strip('"') for r in answers]
    except Exception:
        return []


def check_spf(domain: str) -> dict[str, Any]:
    records = _query_txt(domain)
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return {"exists": False, "record": None, "grade": "FAIL", "issues": ["No SPF record found"]}

    spf = spf_records[0]
    issues = []
    grade = "PASS"

    if spf.count("include:") > 10:
        issues.append("Too many includes (DNS lookup limit risk)")
        grade = "WARN"
    if "+all" in spf:
        issues.append("Permissive +all allows any sender")
        grade = "FAIL"
    elif "~all" in spf:
        issues.append("Soft fail ~all (should be -all for strict enforcement)")
        grade = "WARN"
    elif "?all" in spf:
        issues.append("Neutral ?all provides no protection")
        grade = "FAIL"
    elif "-all" not in spf and "redirect=" not in spf:
        issues.append("No -all mechanism found")
        grade = "WARN"

    if len(spf_records) > 1:
        issues.append(f"Multiple SPF records found ({len(spf_records)})")
        grade = "WARN"

    return {"exists": True, "record": spf, "grade": grade, "issues": issues}


def check_dmarc(domain: str) -> dict[str, Any]:
    records = _query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {"exists": False, "record": None, "grade": "FAIL", "issues": ["No DMARC record found"], "policy": None}

    dmarc = dmarc_records[0]
    issues = []
    grade = "PASS"

    policy_match = re.search(r"p=(none|quarantine|reject)", dmarc)
    policy = policy_match.group(1) if policy_match else None

    if policy == "none":
        issues.append("Policy is 'none' — no enforcement")
        grade = "WARN"
    elif policy == "quarantine":
        grade = "PASS"
    elif policy == "reject":
        grade = "PASS"
    else:
        issues.append("No policy (p=) found")
        grade = "FAIL"

    pct_match = re.search(r"pct=(\d+)", dmarc)
    if pct_match and int(pct_match.group(1)) < 100:
        issues.append(f"Only {pct_match.group(1)}% of messages are subject to DMARC policy")
        grade = "WARN"

    if "rua=" not in dmarc:
        issues.append("No aggregate reporting (rua) configured")

    sp_match = re.search(r"sp=(none|quarantine|reject)", dmarc)
    subdomain_policy = sp_match.group(1) if sp_match else None

    return {
        "exists": True, "record": dmarc, "grade": grade,
        "policy": policy, "subdomain_policy": subdomain_policy, "issues": issues,
    }


def check_dkim(domain: str, selectors: list[str] | None = None) -> dict[str, Any]:
    if selectors is None:
        selectors = [
            "default", "google", "selector1", "selector2",
            "k1", "k2", "mail", "dkim", "s1", "s2",
        ]

    found = []
    for sel in selectors:
        records = _query_txt(f"{sel}._domainkey.{domain}")
        dkim_records = [r for r in records if "v=DKIM1" in r or "k=rsa" in r or "p=" in r]
        if dkim_records:
            found.append({"selector": sel, "record": dkim_records[0][:200]})

    if not found:
        return {"exists": False, "selectors_found": [], "grade": "WARN",
                "issues": ["No DKIM records found for common selectors"]}

    return {"exists": True, "selectors_found": found, "grade": "PASS", "issues": []}


def audit_email_security(domain: str) -> dict[str, Any]:
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)

    grades = [spf["grade"], dmarc["grade"], dkim["grade"]]
    if "FAIL" in grades:
        overall = "FAIL"
    elif "WARN" in grades:
        overall = "WARN"
    else:
        overall = "PASS"

    return {
        "domain": domain,
        "overall_grade": overall,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit email security (SPF/DKIM/DMARC)")
    parser.add_argument("--domain", required=True, help="Domain to audit")
    args = parser.parse_args()

    if not HAS_DNS:
        print(json.dumps({"error": "dnspython required: pip install dnspython"}))
    else:
        print(json.dumps(audit_email_security(args.domain), indent=2))
