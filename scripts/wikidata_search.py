#!/usr/bin/env python3
"""Wikipedia/Wikidata company search.

Free, public data source for company intelligence: sector, employees,
revenue, headquarters, subsidiaries, CEO, stock ticker.

Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging

import httpx

logger = logging.getLogger("wikidata_search")

_HEADERS = {
    "User-Agent": "BusinessProfiler/1.0 (threat-intel-plugin; research@peachstudio.be)"
}

_COMPANY_TYPES = {
    "Q4830453",   # business
    "Q783794",    # company
    "Q891723",    # public company
    "Q6881511",   # enterprise
    "Q1664720",   # corporation
    "Q47461344",  # private company
    "Q167037",    # organization
}


def _safe_get(data: dict, *keys, default=None):
    """Safely navigate nested dictionaries."""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    return current if current is not None else default


def _fetch_label(entity_id: str) -> str | None:
    """Fetch English label for a Wikidata entity."""
    try:
        url = f"https://www.wikidata.org/wiki/Special:EntityData/{entity_id}.json"
        with httpx.Client(timeout=10) as client:
            resp = client.get(url, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
        return _safe_get(data, "entities", entity_id, "labels", "en", "value")
    except Exception as e:
        logger.warning(f"Failed to fetch label for {entity_id}: {e}")
        return None


def _is_company_entity(entity_data: dict) -> bool:
    """Check if Wikidata entity is a company/business."""
    claims = entity_data.get("claims", {})
    for claim in claims.get("P31", []):
        eid = _safe_get(claim, "mainsnak", "datavalue", "value", "id")
        if eid in _COMPANY_TYPES:
            return True
    return False


def _extract_profile(entity: dict, qid: str) -> dict:
    """Extract company profile from Wikidata entity."""
    claims = entity.get("claims", {})

    label = _safe_get(entity, "labels", "en", "value")
    description = _safe_get(entity, "descriptions", "en", "value")

    # Website
    website = None
    if "P856" in claims:
        website = _safe_get(claims["P856"][0], "mainsnak", "datavalue", "value")

    # Industries
    industries = []
    if "P452" in claims:
        for claim in claims["P452"][:3]:
            eid = _safe_get(claim, "mainsnak", "datavalue", "value", "id")
            if eid:
                lbl = _fetch_label(eid)
                if lbl:
                    industries.append(lbl)

    # Country
    hq_country = None
    if "P17" in claims:
        eid = _safe_get(claims["P17"][0], "mainsnak", "datavalue", "value", "id")
        if eid:
            hq_country = _fetch_label(eid)

    # Founded date
    founded_date = None
    if "P571" in claims:
        founded_date = _safe_get(claims["P571"][0], "mainsnak", "datavalue", "value", "time")
        if founded_date:
            founded_date = founded_date.lstrip("+").split("T")[0]

    # Headquarters location
    hq_location = None
    if "P159" in claims:
        eid = _safe_get(claims["P159"][0], "mainsnak", "datavalue", "value", "id")
        if eid:
            hq_location = _fetch_label(eid)

    # Parent organization
    parent_org = None
    if "P749" in claims:
        eid = _safe_get(claims["P749"][0], "mainsnak", "datavalue", "value", "id")
        if eid:
            parent_org = _fetch_label(eid)

    # Subsidiaries
    subsidiaries = []
    if "P355" in claims:
        for claim in claims["P355"][:5]:
            eid = _safe_get(claim, "mainsnak", "datavalue", "value", "id")
            if eid:
                lbl = _fetch_label(eid)
                if lbl:
                    subsidiaries.append(lbl)

    # CEO
    ceo = None
    if "P169" in claims:
        eid = _safe_get(claims["P169"][0], "mainsnak", "datavalue", "value", "id")
        if eid:
            ceo = _fetch_label(eid)

    # Employee count
    employees = None
    if "P1128" in claims:
        employees = _safe_get(claims["P1128"][0], "mainsnak", "datavalue", "value", "amount")

    # Revenue
    revenue = None
    if "P2139" in claims:
        amount = _safe_get(claims["P2139"][0], "mainsnak", "datavalue", "value", "amount")
        unit = _safe_get(claims["P2139"][0], "mainsnak", "datavalue", "value", "unit")
        if amount:
            revenue = f"{amount} ({unit})"

    # Stock ticker
    stock_ticker = None
    if "P414" in claims:
        stock_ticker = _safe_get(claims["P414"][0], "mainsnak", "datavalue", "value")

    return {
        "source": "Wikipedia/Wikidata",
        "name": label,
        "description": description,
        "website": website,
        "industries": industries,
        "country": hq_country,
        "headquarters_location": hq_location,
        "founded_date": founded_date,
        "parent_organization": parent_org,
        "subsidiaries": subsidiaries,
        "ceo": ceo,
        "employees": employees,
        "revenue": revenue,
        "stock_ticker": stock_ticker,
        "wikidata_id": qid,
        "wikidata_url": f"https://www.wikidata.org/wiki/{qid}",
        "wikipedia_url": f"https://en.wikipedia.org/wiki/{label.replace(' ', '_')}" if label else None,
    }


def search_wikidata(company_name: str, country: str = "") -> dict:
    """Search Wikipedia/Wikidata for company information.

    Returns dict with found=True/False and data or error.
    """
    try:
        # Generate search variations
        search_terms = [company_name]
        name_lower = company_name.lower()
        suffixes = ["Inc", "LLC", "Corporation", "Group", "PLC"]
        has_suffix = any(name_lower.endswith(f" {s.lower()}") for s in suffixes)
        if not has_suffix:
            search_terms.extend([f"{company_name} {s}" for s in suffixes[:3]])

        search_url = "https://www.wikidata.org/w/api.php"
        all_candidates = []

        with httpx.Client(timeout=10) as client:
            for search_term in search_terms:
                try:
                    params = {
                        "action": "wbsearchentities",
                        "search": search_term,
                        "language": "en",
                        "format": "json",
                        "limit": 5,
                    }
                    r = client.get(search_url, params=params, headers=_HEADERS)
                    r.raise_for_status()
                    search_results = r.json()

                    for result in search_results.get("search", []):
                        qid = result["id"]
                        entity_url = f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
                        resp = client.get(entity_url, headers=_HEADERS)
                        resp.raise_for_status()
                        data = resp.json()
                        entity = data["entities"][qid]

                        if _is_company_entity(entity):
                            all_candidates.append((qid, entity))
                            break

                except Exception as e:
                    logger.warning(f"Failed to search '{search_term}': {e}")
                    continue

        if not all_candidates:
            return {
                "found": False,
                "message": f"No company information found in Wikipedia/Wikidata for '{company_name}'",
                "suggestion": "Try using the full legal company name or check spelling",
            }

        qid, entity = all_candidates[0]
        profile = _extract_profile(entity, qid)
        return {"found": True, "data": profile}

    except Exception as e:
        logger.error(f"Error searching Wikidata: {e}")
        return {"error": str(e), "type": type(e).__name__}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search Wikipedia/Wikidata for company data")
    parser.add_argument("--company", required=True, help="Company name to search")
    parser.add_argument("--country", default="", help="Country for disambiguation")
    args = parser.parse_args()

    print(json.dumps(search_wikidata(args.company, args.country), indent=2))
