"""
MITRE ATT&CK Integration

Downloads and parses the ATT&CK framework for technique mapping.
This helps the agent understand what techniques apply to a given situation.
"""

import json
from pathlib import Path
from typing import Any

import httpx

from sploitgpt.core.config import get_settings

# ATT&CK STIX data URL (Enterprise)
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


async def download_attack_data(force: bool = False) -> Path:
    """Download MITRE ATT&CK STIX data."""
    settings = get_settings()
    cache_path = settings.data_dir / "attack-enterprise.json"
    
    if cache_path.exists() and not force:
        return cache_path
    
    async with httpx.AsyncClient() as client:
        response = await client.get(ATTACK_STIX_URL, timeout=60)
        response.raise_for_status()
        
        cache_path.write_text(response.text)
    
    return cache_path


def parse_attack_data(stix_path: Path) -> list[dict[str, Any]]:
    """Parse STIX data into technique records."""
    with open(stix_path) as f:
        data = json.load(f)
    
    techniques: list[dict[str, Any]] = []
    tactics_map: dict[str, str] = {}
    
    # First pass: build tactics map
    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            short_name = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            tactics_map[short_name] = name
    
    # Second pass: extract techniques
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue
        
        # Get technique ID (e.g., T1046)
        external_refs = obj.get("external_references", [])
        technique_id = None
        for ref in external_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                break
        
        if not technique_id:
            continue
        
        # Get tactics (phases)
        kill_chain = obj.get("kill_chain_phases", [])
        tactics = []
        for phase in kill_chain:
            if phase.get("kill_chain_name") == "mitre-attack":
                phase_name = phase.get("phase_name", "")
                tactics.append(tactics_map.get(phase_name, phase_name))
        
        # Get platforms
        platforms = obj.get("x_mitre_platforms", [])
        
        techniques.append({
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": platforms,
            "detection": obj.get("x_mitre_detection", ""),
        })
    
    return techniques


def load_techniques_to_db(techniques: list[dict[str, Any]]) -> int:
    """Load techniques into the database."""
    from sploitgpt.db import get_connection
    
    conn = get_connection()
    cursor = conn.cursor()
    
    count = 0
    for tech in techniques:
        cursor.execute("""
            INSERT OR REPLACE INTO techniques (id, name, tactic, description, detection, platforms)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            tech["id"],
            tech["name"],
            ",".join(tech["tactics"]),
            tech["description"][:2000] if tech["description"] else "",  # Truncate long descriptions
            tech["detection"][:1000] if tech["detection"] else "",
            ",".join(tech["platforms"])
        ))
        count += 1
    
    conn.commit()
    conn.close()
    
    return count


async def sync_attack_data(force: bool = False) -> int:
    """Download and sync ATT&CK data to database."""
    stix_path = await download_attack_data(force=force)
    techniques = parse_attack_data(stix_path)
    count = load_techniques_to_db(techniques)
    return count


def search_techniques(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Search techniques by keyword."""
    from sploitgpt.db import get_connection
    
    conn = get_connection()
    cursor = conn.cursor()
    
    # Simple LIKE search - could be upgraded to FTS5
    cursor.execute("""
        SELECT id, name, tactic, description
        FROM techniques
        WHERE name LIKE ? OR description LIKE ? OR id LIKE ?
        LIMIT ?
    """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
    
    results: list[dict[str, Any]] = []
    for row in cursor.fetchall():
        results.append({
            "id": row[0],
            "name": row[1],
            "tactics": row[2].split(",") if row[2] else [],
            "description": row[3][:200] + "..." if len(row[3]) > 200 else row[3]
        })
    
    conn.close()
    return results


def get_techniques_for_service(service: str) -> list[dict[str, Any]]:
    """Get relevant techniques for a discovered service.

    Prefer DB-driven mappings (service_techniques table) when available so the
    knowledge base can be updated without code changes.

    Falls back to a small hardcoded map when the table is missing.
    """

    service_lower = (service or "").strip().lower()
    if not service_lower:
        return []

    from sploitgpt.db import get_connection

    conn = get_connection()
    cursor = conn.cursor()

    # First choice: DB mapping (if present)
    try:
        cursor.execute(
            """
            SELECT t.id, t.name, t.tactic, t.description
            FROM service_techniques st
            JOIN techniques t ON st.technique_id = t.id
            WHERE lower(st.service) = ?
            ORDER BY st.priority DESC
            LIMIT 10
            """,
            (service_lower,),
        )

        rows = cursor.fetchall()
        if rows:
            results: list[dict[str, Any]] = []
            for row in rows:
                desc = row[3] or ""
                results.append(
                    {
                        "id": row[0],
                        "name": row[1],
                        "tactics": row[2].split(",") if row[2] else [],
                        "description": (desc[:200] + "...") if len(desc) > 200 else desc,
                    }
                )
            conn.close()
            return results
    except Exception:
        # Missing table or unexpected schema; fall back.
        pass

    # Fallback: small hardcoded mapping
    SERVICE_TECHNIQUES = {
        "ssh": ["T1021.004", "T1110.001", "T1110.003"],  # Remote Services: SSH, Brute Force
        "http": ["T1190", "T1059.007", "T1055"],  # Exploit Public App, JavaScript, Process Injection
        "https": ["T1190", "T1059.007", "T1055"],
        "smb": ["T1021.002", "T1187", "T1135"],  # SMB/Windows Admin Shares, Forced Auth, Network Share Discovery
        "ftp": ["T1021", "T1110.001"],  # Remote Services, Brute Force
        "mysql": ["T1190", "T1110"],  # Exploit, Brute Force
        "mssql": ["T1190", "T1110", "T1505.001"],  # SQL Stored Procedures
        "rdp": ["T1021.001", "T1110"],  # Remote Desktop, Brute Force
        "telnet": ["T1021", "T1110"],
        "dns": ["T1071.004", "T1568.002"],  # DNS Protocol, Domain Generation
        "ldap": ["T1087.002", "T1069.002"],  # Account Discovery, Domain Groups
        "smtp": ["T1071.003", "T1566"],  # Mail Protocols, Phishing
        "snmp": ["T1602"],  # Data from Config Repo
    }

    technique_ids = SERVICE_TECHNIQUES.get(service_lower, [])

    if not technique_ids:
        conn.close()
        return []

    placeholders = ",".join(["?" for _ in technique_ids])
    cursor.execute(
        f"""
        SELECT id, name, tactic, description
        FROM techniques
        WHERE id IN ({placeholders})
        """,
        technique_ids,
    )

    results = []
    for row in cursor.fetchall():
        desc = row[3] or ""
        results.append(
            {
                "id": row[0],
                "name": row[1],
                "tactics": row[2].split(",") if row[2] else [],
                "description": (desc[:200] + "...") if len(desc) > 200 else desc,
            }
        )

    conn.close()
    return results
