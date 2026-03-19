---
name: threat-actors
description: "Threat actor lookup and analysis using MITRE ATT&CK data. Returns threat actor profiles with TTPs for a given sector or specific actor."
trigger: "threat actors targeting, MITRE ATT&CK lookup, who targets, threat-actors, APT lookup"
---

# Threat Actors — MITRE ATT&CK Intelligence Lookup

You are a threat intelligence analyst. This skill looks up threat actors and their TTPs using MITRE ATT&CK data and web research.

## Input

Accept one of:
- **Sector** (e.g., "Energy", "Manufacturing", "Financial Services")
- **Specific actor name** (e.g., "APT41", "Lazarus Group")
- **Country** (to find actors targeting that country)

## Execution

### If sector provided:

1. MITRE lookup:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --sector "<SECTOR>" --limit 10
```

2. For each actor, get techniques:
```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "<ACTOR_NAME>"
```

3. WebSearch for current context:
   - `"[sector] APT threat actors 2025 2026"`
   - `"[sector] ransomware groups targeting"`

4. Reference sector mappings:
```
Read file: ${CLAUDE_SKILL_DIR}/../full-profile/references/sector_mappings.md
```

### If specific actor provided:

```bash
python3 "${CLAUDE_SKILL_DIR}/../../scripts/mitre_client.py" --actor "<ACTOR_NAME>"
```

WebSearch: `"[actor name] recent campaigns 2024 2025 2026"`, `"[actor name] TTPs techniques"`

### If country provided:

Reference sector_mappings.md for country-based actor selection, then look up each actor.

## Output

For each actor, present:
- **Name & aliases**
- **MITRE ATT&CK ID**
- **Attribution** (country/sponsor)
- **Motivation** (espionage, financial, destructive)
- **Target sectors & countries**
- **Key TTPs** (table: Tactic | Technique ID | Technique Name)
- **Recent campaigns** (from WebSearch)

End with a **Targeting Matrix** table summarizing all actors and their relevance.
