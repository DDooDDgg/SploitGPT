"""Tests for SploitGPT local RAG and knowledge DB lookups."""

from __future__ import annotations

import sqlite3

from sploitgpt.knowledge import get_techniques_for_service
from sploitgpt.knowledge.rag import get_retrieved_context


def test_rag_retrieves_kali_tools_snippet() -> None:
    """Basic smoke test: queries should retrieve relevant content from bundled docs."""
    ctx = get_retrieved_context("gobuster dir", top_k=3, max_chars=2000)
    assert ctx
    assert "gobuster" in ctx.lower()


def test_get_techniques_for_service_uses_db_mapping() -> None:
    """If service_techniques exists/populated, it should return techniques."""
    results = get_techniques_for_service("ssh")
    assert results
    assert any("id" in r and str(r["id"]).upper().startswith("T") for r in results)


def test_get_techniques_for_service_falls_back_when_table_missing(monkeypatch, tmp_path) -> None:
    """When service_techniques is missing, fallback mapping still works."""

    db_path = tmp_path / "sploitgpt.db"

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE techniques (id TEXT PRIMARY KEY, name TEXT, tactic TEXT, description TEXT)"
    )
    conn.execute(
        "INSERT INTO techniques (id, name, tactic, description) VALUES (?, ?, ?, ?)",
        ("T1602", "Data from Configuration Repository", "Collection", "test"),
    )
    conn.commit()
    conn.close()

    # Patch the global DB connector used by sploitgpt.knowledge to point to our temp DB.
    import sploitgpt.db

    def _fake_get_connection() -> sqlite3.Connection:
        c = sqlite3.connect(db_path)
        c.row_factory = sqlite3.Row
        return c

    monkeypatch.setattr(sploitgpt.db, "get_connection", _fake_get_connection)

    results = get_techniques_for_service("snmp")
    assert results
    assert any(r["id"] == "T1602" for r in results)
