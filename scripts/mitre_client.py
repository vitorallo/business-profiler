#!/usr/bin/env python3
"""MITRE ATT&CK STIX client for threat intelligence.

Free threat intelligence using MITRE's public STIX data from GitHub.
Features: threat actor lookup, sector mapping, technique details, ICS actors.
Cache: ~/.cache/business-profiler/ (7-day TTL).
Output: JSON to stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

import httpx

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ICS_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

CACHE_DIR = Path.home() / ".cache" / "business-profiler"
CACHE_MAX_AGE = 7 * 24 * 60 * 60  # 7 days

# Expanded sector-to-threat-actor mappings (14 sectors)
SECTOR_MAPPINGS = {
    "Energy": [
        "Sandworm Team", "Dragonfly", "TEMP.Veles", "APT33", "APT34",
        "Lazarus Group", "Volt Typhoon", "CL-STA-0043",
    ],
    "Manufacturing": [
        "APT41", "Dragonfly", "TEMP.Veles", "Sandworm Team", "Lazarus Group",
        "menuPass", "Volt Typhoon", "APT33",
    ],
    "Technology": [
        "APT41", "APT29", "APT28", "Lazarus Group", "Kimsuky",
        "Mustang Panda", "Scattered Spider", "menuPass",
    ],
    "Financial Services": [
        "Lazarus Group", "FIN7", "Carbanak", "APT38", "TA505",
        "Scattered Spider", "APT41", "Silence",
    ],
    "Government": [
        "APT29", "APT28", "Turla", "Kimsuky", "Sandworm Team",
        "Mustang Panda", "Gamaredon Group", "Volt Typhoon",
    ],
    "Healthcare": [
        "APT41", "Lazarus Group", "FIN11", "APT18", "Deep Panda",
        "Mustang Panda", "TA505",
    ],
    "Telecommunications": [
        "APT41", "Mustang Panda", "Turla", "Sandworm Team",
        "Lazarus Group", "APT29", "Volt Typhoon", "Salt Typhoon",
    ],
    "Defense": [
        "APT29", "APT28", "Turla", "Lazarus Group", "Kimsuky",
        "Mustang Panda", "APT33", "Gamaredon Group",
    ],
    "Retail": [
        "FIN7", "Carbanak", "FIN6", "Scattered Spider",
        "Lazarus Group", "TA505", "APT41",
    ],
    "Transportation": [
        "APT41", "Sandworm Team", "Volt Typhoon", "APT28",
        "Lazarus Group", "menuPass", "Dragonfly",
    ],
    "Education": [
        "APT28", "Kimsuky", "Mustang Panda", "APT29",
        "Lazarus Group", "TA505",
    ],
    "Media": [
        "APT28", "APT29", "Kimsuky", "Lazarus Group",
        "Mustang Panda", "Turla",
    ],
    "Aerospace": [
        "APT41", "APT33", "Lazarus Group", "menuPass",
        "APT29", "Turla", "Kimsuky",
    ],
    "Pharmaceuticals": [
        "APT41", "APT29", "Lazarus Group", "Deep Panda",
        "APT18", "Mustang Panda",
    ],
}

# ICS-specific threat actors
ICS_ACTORS = [
    "Sandworm Team", "Dragonfly", "TEMP.Veles", "Lazarus Group",
    "APT33", "Volt Typhoon",
]


class MitreClient:
    def __init__(self):
        self._stix_data: Optional[dict] = None
        self._ics_data: Optional[dict] = None
        self._indexes: dict[str, dict] = {}

    def _cache_path(self, name: str) -> Path:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        return CACHE_DIR / name

    def _is_cache_valid(self, path: Path) -> bool:
        if not path.exists():
            return False
        return (time.time() - path.stat().st_mtime) < CACHE_MAX_AGE

    def _load_stix(self, url: str, cache_name: str) -> dict:
        cache_path = self._cache_path(cache_name)

        if self._is_cache_valid(cache_path):
            try:
                return json.loads(cache_path.read_text())
            except Exception:
                pass

        try:
            with httpx.Client(timeout=120) as client:
                resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                cache_path.write_text(json.dumps(data))
                return data
            return {"error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _ensure_indexes(self):
        if self._indexes:
            return

        if self._stix_data is None:
            self._stix_data = self._load_stix(STIX_URL, "enterprise-attack.json")

        if "error" in self._stix_data:
            return

        self._indexes = {"groups": {}, "techniques": {}, "software": {}, "relationships": []}

        for obj in self._stix_data.get("objects", []):
            t = obj.get("type")
            if t == "intrusion-set":
                self._indexes["groups"][obj.get("name", "")] = obj
            elif t == "attack-pattern":
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        self._indexes["techniques"][ref["external_id"]] = obj
                        break
            elif t in ("malware", "tool"):
                self._indexes["software"][obj.get("name", "")] = obj
            elif t == "relationship":
                self._indexes["relationships"].append(obj)

    def _extract_attack_id(self, obj: dict) -> Optional[str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    def _format_group(self, name: str, group: dict) -> dict:
        desc = group.get("description", "")
        return {
            "id": self._extract_attack_id(group) or group.get("id"),
            "name": name,
            "description": (desc[:300] + "...") if len(desc) > 300 else desc,
            "aliases": group.get("aliases", []),
        }

    def get_groups_by_sector(self, sector: str, limit: int = 10) -> list[dict]:
        self._ensure_indexes()
        actor_names = SECTOR_MAPPINGS.get(sector, [])
        results = []
        for name in actor_names[:limit]:
            if name in self._indexes.get("groups", {}):
                results.append(self._format_group(name, self._indexes["groups"][name]))
        return results

    def get_group_techniques(self, group_name: str) -> list[dict]:
        self._ensure_indexes()
        group = self._indexes.get("groups", {}).get(group_name)
        if not group:
            return []

        group_id = group.get("id")
        techniques = []
        for rel in self._indexes.get("relationships", []):
            if (rel.get("source_ref") == group_id
                    and rel.get("relationship_type") == "uses"
                    and "attack-pattern" in rel.get("target_ref", "")):
                target_id = rel["target_ref"]
                for tech_id, tech in self._indexes["techniques"].items():
                    if tech.get("id") == target_id:
                        phases = [p.get("phase_name") for p in tech.get("kill_chain_phases", [])]
                        techniques.append({"id": tech_id, "name": tech.get("name"), "tactics": phases})
                        break
        return techniques

    def get_technique(self, technique_id: str) -> dict:
        self._ensure_indexes()
        tech = self._indexes.get("techniques", {}).get(technique_id)
        if not tech:
            return {"error": f"Technique {technique_id} not found"}
        return {
            "id": technique_id,
            "name": tech.get("name"),
            "description": tech.get("description"),
            "platforms": tech.get("x_mitre_platforms", []),
            "tactics": [p.get("phase_name") for p in tech.get("kill_chain_phases", [])],
        }

    def get_ics_actors(self, limit: int = 10) -> list[dict]:
        self._ensure_indexes()
        results = []
        for name in ICS_ACTORS[:limit]:
            if name in self._indexes.get("groups", {}):
                results.append(self._format_group(name, self._indexes["groups"][name]))
        return results


_client: Optional[MitreClient] = None


def get_client() -> MitreClient:
    global _client
    if _client is None:
        _client = MitreClient()
    return _client


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITRE ATT&CK threat intelligence lookup")
    parser.add_argument("--sector", help="Industry sector for threat actor lookup")
    parser.add_argument("--actor", help="Threat actor name for technique lookup")
    parser.add_argument("--technique", help="Technique ID (e.g., T1566)")
    parser.add_argument("--ot", action="store_true", help="List ICS/OT threat actors")
    parser.add_argument("--limit", type=int, default=10, help="Max results")
    args = parser.parse_args()

    client = get_client()

    if args.sector:
        actors = client.get_groups_by_sector(args.sector, args.limit)
        print(json.dumps({
            "source": "mitre_attack", "sector": args.sector, "actors": actors,
        }, indent=2))
    elif args.actor:
        techniques = client.get_group_techniques(args.actor)
        print(json.dumps({
            "source": "mitre_attack", "actor": args.actor, "techniques": techniques,
        }, indent=2))
    elif args.technique:
        print(json.dumps(client.get_technique(args.technique), indent=2))
    elif args.ot:
        actors = client.get_ics_actors(args.limit)
        print(json.dumps({
            "source": "mitre_attack", "focus": "ICS/OT", "actors": actors,
        }, indent=2))
    else:
        # List available sectors
        print(json.dumps({
            "available_sectors": list(SECTOR_MAPPINGS.keys()),
            "usage": "Use --sector, --actor, --technique, or --ot",
        }, indent=2))
