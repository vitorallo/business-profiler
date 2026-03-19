#!/usr/bin/env python3
"""Financial intelligence estimation for IT and cybersecurity spend.

All estimates are based on industry benchmarks and clearly marked as estimations.
Pure computation, no external calls.

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json

# IT spend as % of revenue by sector
IT_SPEND_MULTIPLIERS = {
    "Technology": (0.06, 0.08),
    "Financial Services": (0.07, 0.10),
    "Healthcare": (0.04, 0.06),
    "Retail": (0.02, 0.04),
    "Manufacturing": (0.02, 0.04),
    "Energy": (0.03, 0.05),
    "Telecommunications": (0.08, 0.12),
    "Government": (0.04, 0.06),
    "Transportation": (0.03, 0.05),
    "Education": (0.03, 0.05),
    "Other": (0.03, 0.05),
}

# Cybersecurity spend as % of IT budget by sector
CYBERSEC_SPEND_MULTIPLIERS = {
    "Financial Services": (0.10, 0.15),
    "Healthcare": (0.08, 0.12),
    "Technology": (0.06, 0.10),
    "Retail": (0.05, 0.08),
    "Energy": (0.08, 0.12),
    "Telecommunications": (0.07, 0.11),
    "Government": (0.06, 0.10),
    "Manufacturing": (0.05, 0.08),
    "Transportation": (0.05, 0.08),
    "Other": (0.05, 0.08),
}


def parse_revenue_string(revenue_str: str) -> float | None:
    """Parse revenue string like '$25.3B' or '150M' to USD."""
    try:
        clean = revenue_str.replace("$", "").replace("\u20ac", "").replace("\u00a3", "").replace(",", "").strip()

        multiplier = 1
        if clean[-1] in ("B", "b"):
            multiplier = 1_000_000_000
            clean = clean[:-1]
        elif clean[-1] in ("M", "m"):
            multiplier = 1_000_000
            clean = clean[:-1]
        elif clean[-1] in ("K", "k"):
            multiplier = 1_000
            clean = clean[:-1]

        value = float(clean) * multiplier

        if "\u20ac" in revenue_str:
            value *= 1.1
        elif "\u00a3" in revenue_str:
            value *= 1.3

        return value
    except Exception:
        return None


def categorize_revenue(revenue_usd: float) -> str:
    """Categorize company size by revenue."""
    if revenue_usd >= 1_000_000_000:
        return "Enterprise"
    elif revenue_usd >= 100_000_000:
        return "Mid-Market"
    else:
        return "SMB"


def format_currency(value_usd: float) -> str:
    """Format USD value as string with appropriate suffix."""
    if value_usd >= 1_000_000_000:
        return f"${value_usd / 1_000_000_000:.1f}B"
    elif value_usd >= 1_000_000:
        return f"${value_usd / 1_000_000:.0f}M"
    elif value_usd >= 1_000:
        return f"${value_usd / 1_000:.1f}K"
    else:
        return f"${value_usd:.0f}"


def estimate_it_headcount(total_employees: int, sector: str) -> int:
    """Estimate IT team size (3-5% of total headcount)."""
    if sector in ("Technology", "Telecommunications", "Financial Services"):
        pct = 0.05
    else:
        pct = 0.03
    return int(total_employees * pct)


def estimate_it_spend(revenue_usd: float, sector: str, employee_count: int | None = None) -> tuple[float, str]:
    """Estimate annual IT spend based on revenue and sector benchmarks."""
    min_pct, max_pct = IT_SPEND_MULTIPLIERS.get(sector, IT_SPEND_MULTIPLIERS["Other"])
    avg_pct = (min_pct + max_pct) / 2
    it_spend = revenue_usd * avg_pct

    methodology = f"Revenue-based: {format_currency(revenue_usd)} x {avg_pct*100:.1f}% ({sector} sector benchmark)"

    if employee_count:
        employee_based = employee_count * 11_500
        if abs(it_spend - employee_based) / it_spend > 0.5:
            methodology += f" (Employee-based check: {employee_count} employees suggests {format_currency(employee_based)})"

    return it_spend, methodology


def estimate_cybersecurity_spend(
    it_spend_usd: float,
    sector: str,
    risk_level: str | None = None,
    recent_incidents: int = 0,
    nation_state_targeting: bool = False,
    has_compliance_mandate: bool = False,
) -> tuple[tuple[float, float], str]:
    """Estimate annual cybersecurity spend with risk adjustments."""
    base_min, base_max = CYBERSEC_SPEND_MULTIPLIERS.get(sector, CYBERSEC_SPEND_MULTIPLIERS["Other"])

    adjustments = []

    if risk_level == "CRITICAL":
        base_min += 0.03
        base_max += 0.05
        adjustments.append("+3-5% for CRITICAL threat level")
    elif risk_level == "HIGH":
        base_min += 0.02
        base_max += 0.03
        adjustments.append("+2-3% for HIGH threat level")

    if recent_incidents >= 2:
        base_min += 0.02
        base_max += 0.04
        adjustments.append(f"+2-4% for {recent_incidents} recent incidents")
    elif recent_incidents == 1:
        base_min += 0.01
        base_max += 0.02
        adjustments.append("+1-2% for recent security incident")

    if nation_state_targeting:
        base_min += 0.02
        base_max += 0.03
        adjustments.append("+2-3% for nation-state threat actor targeting")

    if has_compliance_mandate:
        base_min += 0.03
        base_max += 0.07
        adjustments.append("+3-7% for regulatory compliance requirements")

    min_spend = it_spend_usd * base_min
    max_spend = it_spend_usd * base_max

    base_methodology = f"IT budget x {base_min*100:.0f}-{base_max*100:.0f}% ({sector} sector)"
    if adjustments:
        methodology = base_methodology + ". Adjustments: " + "; ".join(adjustments)
    else:
        methodology = base_methodology + " (no risk adjustments)"

    return (min_spend, max_spend), methodology


def create_financial_intelligence(
    revenue: str | None = None,
    employees: int | None = None,
    sector: str = "Other",
    risk_level: str | None = None,
    recent_incidents: int = 0,
    has_compliance: bool = False,
) -> dict:
    """Create complete financial intelligence analysis."""
    revenue_usd = None
    revenue_category = "Unknown"
    if revenue:
        revenue_usd = parse_revenue_string(revenue)
        if revenue_usd:
            revenue_category = categorize_revenue(revenue_usd)

    estimated_it_headcount = None
    if employees:
        estimated_it_headcount = estimate_it_headcount(employees, sector)

    estimated_it_spend = None
    estimated_it_spend_usd = None
    it_spend_methodology = None
    if revenue_usd:
        estimated_it_spend_usd, it_spend_methodology = estimate_it_spend(revenue_usd, sector, employees)
        estimated_it_spend = format_currency(estimated_it_spend_usd)

    estimated_cybersec_spend = None
    cybersec_spend_range = None
    cybersec_spend_methodology = None
    if estimated_it_spend_usd:
        (min_spend, max_spend), cybersec_spend_methodology = estimate_cybersecurity_spend(
            estimated_it_spend_usd,
            sector,
            risk_level=risk_level,
            recent_incidents=recent_incidents,
            nation_state_targeting=False,
            has_compliance_mandate=has_compliance,
        )
        estimated_cybersec_spend = f"{format_currency(min_spend)}-{format_currency(max_spend)}"
        cybersec_spend_range = [min_spend, max_spend]

    return {
        "revenue": revenue,
        "revenue_usd": revenue_usd,
        "revenue_category": revenue_category,
        "employees": employees,
        "estimated_it_headcount": estimated_it_headcount,
        "estimated_it_spend": estimated_it_spend,
        "estimated_it_spend_usd": estimated_it_spend_usd,
        "it_spend_methodology": it_spend_methodology,
        "estimated_cybersec_spend": estimated_cybersec_spend,
        "estimated_cybersec_spend_range_usd": cybersec_spend_range,
        "cybersec_spend_methodology": cybersec_spend_methodology,
        "estimation_note": "All financial estimates are based on industry benchmarks and may vary significantly from actual spend",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Estimate IT and cybersecurity spend")
    parser.add_argument("--sector", required=True, help="Industry sector")
    parser.add_argument("--revenue", default=None, help="Annual revenue (e.g., '$25.3B', '150M')")
    parser.add_argument("--employees", type=int, default=None, help="Total employee count")
    parser.add_argument("--risk-level", default=None, choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Threat risk level")
    parser.add_argument("--incidents", type=int, default=0, help="Number of incidents in last 24 months")
    parser.add_argument("--compliance", action="store_true", help="Subject to major compliance mandates")
    args = parser.parse_args()

    result = create_financial_intelligence(
        revenue=args.revenue,
        employees=args.employees,
        sector=args.sector,
        risk_level=args.risk_level,
        recent_incidents=args.incidents,
        has_compliance=args.compliance,
    )
    print(json.dumps(result, indent=2))
