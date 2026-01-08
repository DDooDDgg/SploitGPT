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


def test_rag_input_validation_top_k() -> None:
    """Verify top_k input validation."""
    import pytest

    # Invalid type
    with pytest.raises(TypeError, match="top_k must be int"):
        get_retrieved_context("test", top_k="5")

    # Out of bounds
    with pytest.raises(ValueError, match="top_k must be between 1 and 50"):
        get_retrieved_context("test", top_k=0)

    with pytest.raises(ValueError, match="top_k must be between 1 and 50"):
        get_retrieved_context("test", top_k=100)

    # Valid bounds
    ctx = get_retrieved_context("nmap", top_k=1)
    assert isinstance(ctx, str)


def test_rag_input_validation_max_chars() -> None:
    """Verify max_chars input validation."""
    import pytest

    # Invalid type
    with pytest.raises(TypeError, match="max_chars must be int"):
        get_retrieved_context("test", max_chars="1000")

    # Out of bounds
    with pytest.raises(ValueError, match="max_chars must be between 200 and 50000"):
        get_retrieved_context("test", max_chars=100)

    with pytest.raises(ValueError, match="max_chars must be between 200 and 50000"):
        get_retrieved_context("test", max_chars=100000)

    # Valid bounds
    ctx = get_retrieved_context("nmap", max_chars=500)
    assert isinstance(ctx, str)


def test_rag_chunking_empty_document() -> None:
    """Test chunking handles empty documents gracefully."""
    from sploitgpt.knowledge.rag import _chunk_markdown

    # Empty string
    chunks = _chunk_markdown("")
    assert chunks == []

    # Whitespace only
    chunks = _chunk_markdown("   \n\n  ")
    assert chunks == []


def test_rag_chunking_giant_document() -> None:
    """Test chunking splits very large documents when no headers present."""
    from sploitgpt.knowledge.rag import _chunk_markdown

    # Single giant paragraph (no headers) - creates one big chunk by design
    # unless it exceeds 2500 chars and triggers paragraph-level fallback
    giant_text = "This is a test paragraph.\n\n" * 200  # ~5000 chars with paragraph breaks
    chunks = _chunk_markdown(giant_text)

    # With paragraph breaks, should split into multiple chunks
    assert len(chunks) > 1
    # Each chunk should be reasonably sized (under 2500)
    for chunk in chunks:
        assert len(chunk) <= 2500


def test_rag_chunking_preserves_headers() -> None:
    """Test chunking keeps headers with their content."""
    from sploitgpt.knowledge.rag import _chunk_markdown

    text = """# Header 1
Content for section 1.

## Header 2
Content for section 2.

### Header 3
Content for section 3."""

    chunks = _chunk_markdown(text)
    assert len(chunks) == 3
    assert chunks[0].startswith("# Header 1")
    assert chunks[1].startswith("## Header 2")
    assert chunks[2].startswith("### Header 3")


def test_rag_bm25_scoring_relevance() -> None:
    """Test BM25 scores relevant docs higher than irrelevant."""
    from sploitgpt.knowledge.rag import BM25Index, RagDocument

    docs = [
        RagDocument(content="nmap scan ports network discovery reconnaissance", source="doc1"),
        RagDocument(content="hydra brute force password authentication attack", source="doc2"),
        RagDocument(content="the cat sat on the mat in the room", source="doc3"),
    ]

    index = BM25Index(docs)
    hits = index.search("nmap network scan", k=3)

    # Doc1 should score highest (most relevant terms)
    assert len(hits) >= 1
    assert hits[0].doc.source == "doc1"
    assert hits[0].score > 0


def test_rag_bm25_scoring_repeated_terms() -> None:
    """Test BM25 handles term frequency properly."""
    from sploitgpt.knowledge.rag import BM25Index, RagDocument

    docs = [
        RagDocument(content="exploit exploit exploit vulnerability", source="doc1"),
        RagDocument(content="exploit vulnerability", source="doc2"),
    ]

    index = BM25Index(docs)
    hits = index.search("exploit", k=2)

    # Both docs should be retrieved
    assert len(hits) == 2
    # Doc with more occurrences should score higher (BM25 saturates but still boosts)
    assert hits[0].score > 0
