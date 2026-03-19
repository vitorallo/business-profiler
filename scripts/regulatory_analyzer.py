#!/usr/bin/env python3
"""Regulatory compliance pressure analysis.

Identifies applicable regulations, deadlines, and compliance urgency
based on company sector and country. Pure computation, no external calls.

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

# Regulation database
REGULATIONS_DB = {
    "NIS2": {
        "full_name": "Network and Information Security Directive 2",
        "regions": ["EU"],
        "sectors": [
            "Energy", "Transportation", "Healthcare", "Financial Services",
            "Telecommunications", "Technology", "Manufacturing", "Government",
        ],
        "deadline": "2024-10-17",
        "enforcement": "2025-01-01",
        "requirements": [
            "Incident reporting within 24 hours",
            "Supply chain security measures",
            "Regular penetration testing and security audits",
            "Business continuity and disaster recovery plans",
            "Executive accountability for cybersecurity",
        ],
        "penalties": "Up to 10M EUR or 2% of global annual turnover (whichever is higher)",
        "estimated_cost": "$200K-$800K (initial compliance) + $100K-$300K/year (ongoing)",
    },
    "DORA": {
        "full_name": "Digital Operational Resilience Act",
        "regions": ["EU"],
        "sectors": ["Financial Services"],
        "deadline": "2025-01-17",
        "requirements": [
            "ICT risk management framework",
            "Third-party ICT service provider oversight",
            "Digital operational resilience testing",
            "ICT incident reporting",
            "Information sharing on cyber threats",
        ],
        "penalties": "Up to 10M EUR or 5% of annual turnover",
        "estimated_cost": "$500K-$2M (initial) + $200K-$500K/year",
    },
    "CRA": {
        "full_name": "Cyber Resilience Act",
        "regions": ["EU"],
        "sectors": ["Manufacturing", "Technology"],
        "deadline": "2027-09-01",
        "design_deadline": "2024-09-01",
        "requirements": [
            "Security by design and by default",
            "Vulnerability handling process",
            "Security updates for product lifetime (min 5 years)",
            "Incident reporting",
            "CE marking with cybersecurity attestation",
        ],
        "penalties": "Up to 15M EUR or 2.5% of global annual turnover",
        "estimated_cost": "$300K-$1.5M (product redesign) + $150K-$400K/year",
    },
    "GDPR": {
        "full_name": "General Data Protection Regulation",
        "regions": ["EU"],
        "sectors": ["*"],
        "deadline": "2018-05-25",
        "requirements": [
            "Data protection by design and by default",
            "Privacy impact assessments",
            "Data breach notification (72 hours)",
            "Data subject rights implementation",
            "Records of processing activities",
        ],
        "penalties": "Up to 20M EUR or 4% of global annual turnover",
        "estimated_cost": "$150K-$600K (initial) + $50K-$200K/year",
    },
    "HIPAA": {
        "full_name": "Health Insurance Portability and Accountability Act",
        "regions": ["US"],
        "sectors": ["Healthcare"],
        "deadline": "1996-08-21",
        "requirements": [
            "Administrative, physical, and technical safeguards",
            "Risk analysis and management",
            "Breach notification",
            "Business associate agreements",
            "Security awareness training",
        ],
        "penalties": "Up to $1.5M per violation category per year",
        "estimated_cost": "$100K-$500K (initial) + $75K-$250K/year",
    },
    "PCI-DSS": {
        "full_name": "Payment Card Industry Data Security Standard",
        "regions": ["Global"],
        "sectors": ["Financial Services", "Retail", "Technology"],
        "deadline": "Ongoing",
        "requirements": [
            "Build and maintain secure network",
            "Protect cardholder data",
            "Maintain vulnerability management program",
            "Implement strong access control measures",
            "Regularly monitor and test networks",
            "Maintain information security policy",
        ],
        "penalties": "Fines from card brands ($5K-$100K/month), possible loss of payment processing",
        "estimated_cost": "$50K-$300K (initial) + $30K-$150K/year",
    },
    "SOC2": {
        "full_name": "Service Organization Control 2",
        "regions": ["Global"],
        "sectors": ["Technology"],
        "deadline": "Ongoing",
        "requirements": [
            "Security controls framework",
            "Availability and processing integrity",
            "Confidentiality and privacy controls",
            "Annual audit by independent CPA",
            "Continuous monitoring and evidence collection",
        ],
        "penalties": "Loss of enterprise customers, reputational damage",
        "estimated_cost": "$75K-$400K (initial) + $50K-$200K/year",
    },
    "CMMC": {
        "full_name": "Cybersecurity Maturity Model Certification",
        "regions": ["US"],
        "sectors": ["Defense", "Manufacturing"],
        "deadline": "2026-10-01",
        "requirements": [
            "Level-based maturity (Level 1-3)",
            "NIST SP 800-171 compliance (Level 2)",
            "Third-party assessment",
            "Continuous monitoring",
            "Incident reporting to DoD",
        ],
        "penalties": "Loss of DoD contracts, contract termination",
        "estimated_cost": "$200K-$1M (Level 2) + $100K-$300K/year",
    },
}

EU_COUNTRIES = [
    "Austria", "Belgium", "Bulgaria", "Croatia", "Cyprus", "Czech Republic",
    "Denmark", "Estonia", "Finland", "France", "Germany", "Greece", "Hungary",
    "Ireland", "Italy", "Latvia", "Lithuania", "Luxembourg", "Malta", "Netherlands",
    "Poland", "Portugal", "Romania", "Slovakia", "Slovenia", "Spain", "Sweden",
]


def calculate_months_until(deadline_str: str) -> int:
    """Calculate months remaining until deadline."""
    try:
        deadline = datetime.fromisoformat(deadline_str)
        now = datetime.now(timezone.utc)
        delta = deadline.replace(tzinfo=timezone.utc) - now
        return max(0, int(delta.days / 30))
    except Exception:
        return 999


def classify_urgency(months_remaining: int) -> str:
    """Classify urgency based on months until deadline."""
    if months_remaining <= 6:
        return "IMMEDIATE"
    elif months_remaining <= 12:
        return "HIGH"
    elif months_remaining <= 24:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_regulatory_pressure(
    sector: str,
    country: str,
    has_eu_customers: bool = False,
    processes_payments: bool = False,
    is_cloud_provider: bool = False,
    is_defense_contractor: bool = False,
) -> dict:
    """Analyze regulatory compliance pressure for a company."""
    applicable = []
    compliance_drivers = []

    is_eu = country in EU_COUNTRIES
    is_us = country in ("United States", "US")

    for reg_name, reg_data in REGULATIONS_DB.items():
        applies = False
        reason = None

        # Region check
        if is_eu and "EU" in reg_data["regions"]:
            region_match = True
        elif is_us and "US" in reg_data["regions"]:
            region_match = True
        elif "Global" in reg_data["regions"]:
            region_match = True
        elif has_eu_customers and "EU" in reg_data["regions"] and reg_name == "GDPR":
            region_match = True
            reason = "Processes EU personal data"
        else:
            region_match = False

        # Sector check
        if region_match:
            if "*" in reg_data["sectors"]:
                applies = True
                reason = reason or f"{sector} sector (universal regulation)"
            elif sector in reg_data["sectors"]:
                applies = True
                reason = reason or f"{sector} sector in {reg_data['regions']}"

            # Special cases
            if reg_name == "PCI-DSS" and processes_payments:
                applies = True
                reason = "Processes credit card payments"
            elif reg_name == "SOC2" and is_cloud_provider:
                applies = True
                reason = "Cloud/SaaS provider serving enterprise customers"
            elif reg_name == "CMMC" and is_defense_contractor:
                applies = True
                reason = "Defense contractor or supplier"

        if applies:
            deadline = reg_data.get("enforcement") or reg_data.get("deadline")
            months_remaining = calculate_months_until(deadline)
            urgency = classify_urgency(months_remaining)

            regulation = {
                "name": reg_name,
                "full_name": reg_data["full_name"],
                "scope": reg_data["sectors"][0] if reg_data["sectors"] != ["*"] else "All sectors",
                "deadline": deadline,
                "urgency": urgency,
                "months_remaining": months_remaining,
                "key_requirements": reg_data["requirements"][:5],
                "penalties": reg_data["penalties"],
            }

            applicable.append(regulation)
            if reason:
                compliance_drivers.append(reason)

    # Overall urgency
    if any(r["urgency"] == "IMMEDIATE" for r in applicable):
        overall_urgency = "IMMEDIATE"
    elif any(r["urgency"] == "HIGH" for r in applicable):
        overall_urgency = "HIGH"
    elif any(r["urgency"] == "MEDIUM" for r in applicable):
        overall_urgency = "MEDIUM"
    else:
        overall_urgency = "LOW"

    # Estimate total compliance cost
    if len(applicable) == 0:
        total_cost = "N/A - No major regulations identified"
    elif len(applicable) == 1:
        total_cost = REGULATIONS_DB[applicable[0]["name"]]["estimated_cost"]
    else:
        n = len(applicable)
        total_cost = f"${n * 200}K-${n * 800}K (initial) + ${n * 100}K-${n * 300}K/year"

    return {
        "applicable_regulations": sorted(applicable, key=lambda r: r["months_remaining"]),
        "overall_urgency": overall_urgency,
        "compliance_drivers": compliance_drivers,
        "total_estimated_cost": total_cost,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze regulatory compliance pressure")
    parser.add_argument("--sector", required=True, help="Industry sector")
    parser.add_argument("--country", required=True, help="Company headquarters country")
    parser.add_argument("--eu-customers", action="store_true", help="Company serves EU customers")
    parser.add_argument("--processes-payments", action="store_true", help="Company processes credit card payments")
    parser.add_argument("--cloud-provider", action="store_true", help="Company provides cloud/SaaS services")
    parser.add_argument("--defense-contractor", action="store_true", help="Company works with defense/military")
    args = parser.parse_args()

    result = analyze_regulatory_pressure(
        sector=args.sector,
        country=args.country,
        has_eu_customers=args.eu_customers,
        processes_payments=args.processes_payments,
        is_cloud_provider=args.cloud_provider,
        is_defense_contractor=args.defense_contractor,
    )
    print(json.dumps(result, indent=2))
