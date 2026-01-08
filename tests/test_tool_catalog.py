"""Tests for Kali tool catalog helpers (tool_search/tool_help)."""

from __future__ import annotations

import sqlite3

import pytest


def _patch_db(monkeypatch, db_path):
    import sploitgpt.db

    def _fake_get_connection() -> sqlite3.Connection:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    monkeypatch.setattr(sploitgpt.db, "get_connection", _fake_get_connection)


@pytest.mark.asyncio
async def test_tool_search_uses_baked_catalog(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "sploitgpt.db"
    _patch_db(monkeypatch, db_path)

    from sploitgpt.db import init_db

    init_db()

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO kali_tools (tool, summary, categories) VALUES (?, ?, ?)",
        ("ffuf", "Fast web fuzzer written in Go", "Web;Fuzzer;"),
    )
    conn.execute(
        "INSERT INTO kali_tools (tool, summary, categories) VALUES (?, ?, ?)",
        ("gobuster", "Directory/file & DNS busting tool", "Web;Discovery;"),
    )
    conn.commit()
    conn.close()

    from sploitgpt.tools import tool_search

    out = await tool_search("fuzz", limit=5)
    assert "ffuf" in out.lower()


@pytest.mark.asyncio
async def test_tool_help_reads_cached_docs(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "sploitgpt.db"
    _patch_db(monkeypatch, db_path)

    from sploitgpt.db import init_db

    init_db()

    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO kali_tool_docs (tool, kind, chunk_index, content, source)
        VALUES (?, ?, ?, ?, ?)
        """,
        ("nmap", "help", 0, "Usage: nmap [Scan Type] [Options] {target}", "nmap --help"),
    )
    conn.commit()
    conn.close()

    from sploitgpt.tools import tool_help

    out = await tool_help("nmap", max_chars=1200)
    assert "usage:" in out.lower()

