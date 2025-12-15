"""MITRE ATT&CK knowledge wrapper.

This module provides a small, script-friendly API over SploitGPT's cached
ATT&CK techniques stored in the SQLite DB (see sploitgpt/db.py).

It exists mainly to support:
- scripts/build_training_data.py

The DB is populated via sploitgpt.knowledge.sync_attack_data().
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AttackTechnique:
    """A single MITRE ATT&CK technique."""

    id: str
    name: str
    description: str = ""
    tactics: list[str] = field(default_factory=list)
    detection: str = ""
    platforms: list[str] = field(default_factory=list)


class AttackKnowledge:
    """Loads and queries ATT&CK techniques from the local cache."""

    def __init__(self) -> None:
        self.techniques: dict[str, AttackTechnique] = {}

    async def initialize(self, force_sync: bool = False) -> int:
        """Initialize the knowledge base.

        Ensures DB schema exists, syncs ATT&CK data if needed, then loads
        techniques into memory.

        Args:
            force_sync: If true, re-download and re-sync ATT&CK data.

        Returns:
            Number of techniques loaded.
        """

        from sploitgpt.db import get_connection, init_db
        from sploitgpt.knowledge import sync_attack_data

        # Ensure tables exist.
        init_db()

        # If techniques table is empty, sync it.
        try:
            conn = get_connection()
            row = conn.execute("SELECT COUNT(1) AS c FROM techniques").fetchone()
            conn.close()
            existing = int(row["c"]) if row and "c" in row.keys() else 0
        except Exception:
            existing = 0

        if force_sync or existing == 0:
            await sync_attack_data(force=force_sync)

        self.techniques = self._load_all_from_db()
        return len(self.techniques)

    def _load_all_from_db(self) -> dict[str, AttackTechnique]:
        from sploitgpt.db import get_connection

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, tactic, description, detection, platforms FROM techniques"
        )

        techniques: dict[str, AttackTechnique] = {}
        for row in cursor.fetchall():
            tech_id = (row["id"] or "").upper()
            tactics = (row["tactic"] or "").split(",") if row["tactic"] else []
            platforms = (
                (row["platforms"] or "").split(",") if row["platforms"] else []
            )
            techniques[tech_id] = AttackTechnique(
                id=tech_id,
                name=row["name"] or "",
                description=row["description"] or "",
                tactics=[t for t in tactics if t],
                detection=row["detection"] or "",
                platforms=[p for p in platforms if p],
            )

        conn.close()
        return techniques

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        """Get a technique by ID (e.g., T1046 or T1021.002)."""
        if not technique_id:
            return None
        return self.techniques.get(technique_id.upper())

    def search(self, query: str, limit: int = 10) -> list[AttackTechnique]:
        """Search in-memory techniques by ID/name/description.

        This is best-effort and meant for scripts and prompts.
        """
        if not query:
            return []

        q = query.lower()
        results: list[AttackTechnique] = []
        for tech in self.techniques.values():
            if (
                q in tech.id.lower()
                or q in tech.name.lower()
                or q in (tech.description or "").lower()
            ):
                results.append(tech)
                if len(results) >= limit:
                    break

        return results
