"""Local retrieval (RAG) for SploitGPT.

Design goals:
- Production-friendly: no new heavy Python dependencies.
- Deterministic + fast: pure-Python lexical scoring (BM25-ish) over small curated corpora.
- Uses existing curated markdown sources (sploitgpt/knowledge/sources) and optional
  SQLite DB knowledge (sploitgpt.db, memory.db) when present.

This is intended to provide targeted context injection at runtime instead of
"training the model on databases at boot".
"""

from __future__ import annotations

import math
import re
import sqlite3
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sploitgpt.core.config import get_settings

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._:-][a-z0-9]+)*")
logger = logging.getLogger(__name__)


_STOPWORDS: set[str] = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "but",
    "by",
    "can",
    "for",
    "from",
    "has",
    "have",
    "how",
    "i",
    "if",
    "in",
    "into",
    "is",
    "it",
    "its",
    "me",
    "of",
    "on",
    "or",
    "our",
    "that",
    "the",
    "their",
    "them",
    "then",
    "this",
    "to",
    "use",
    "using",
    "was",
    "we",
    "were",
    "what",
    "when",
    "where",
    "which",
    "who",
    "will",
    "with",
    "you",
    "your",
}


def _tokenize(text: str) -> list[str]:
    if not text:
        return []

    tokens = [t.lower() for t in _TOKEN_RE.findall(text.lower())]
    return [t for t in tokens if t and t not in _STOPWORDS]


@dataclass(frozen=True)
class RagDocument:
    """A single retrievable document chunk."""

    content: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RagHit:
    doc: RagDocument
    score: float


class BM25Index:
    """Simple BM25-ish index implemented with an inverted index."""

    def __init__(self, docs: list[RagDocument]) -> None:
        self._docs = docs

        # Per-doc length and term frequencies
        self._doc_len: list[int] = []
        self._tf: list[dict[str, int]] = []

        # Inverted index: term -> list[(doc_id, tf)]
        self._postings: dict[str, list[tuple[int, int]]] = {}

        # doc frequency: term -> df
        df: dict[str, int] = {}

        for i, doc in enumerate(docs):
            terms = _tokenize(doc.content)
            tf: dict[str, int] = {}
            for t in terms:
                tf[t] = tf.get(t, 0) + 1

            self._tf.append(tf)
            self._doc_len.append(len(terms))

            for t, n in tf.items():
                self._postings.setdefault(t, []).append((i, n))
                df[t] = df.get(t, 0) + 1

        n_docs = max(len(docs), 1)
        self._avgdl = (sum(self._doc_len) / n_docs) if self._doc_len else 0.0

        # Precompute idf
        self._idf: dict[str, float] = {}
        for term, dfi in df.items():
            # Standard-ish BM25 idf with log(1 + (N - df + 0.5)/(df + 0.5))
            self._idf[term] = math.log(1.0 + (n_docs - dfi + 0.5) / (dfi + 0.5))

    def search(self, query: str, *, k: int = 5) -> list[RagHit]:
        query_terms = _tokenize(query)
        if not query_terms or not self._docs:
            return []

        # BM25 parameters
        k1 = 1.5
        b = 0.75

        scores: dict[int, float] = {}
        for term in set(query_terms):
            postings = self._postings.get(term)
            if not postings:
                continue

            idf = self._idf.get(term, 0.0)
            for doc_id, tf in postings:
                dl = float(self._doc_len[doc_id])
                denom = tf + k1 * (1.0 - b + b * (dl / (self._avgdl + 1e-9)))
                score = idf * (tf * (k1 + 1.0)) / (denom + 1e-9)
                scores[doc_id] = scores.get(doc_id, 0.0) + score

        if not scores:
            return []

        ranked = sorted(scores.items(), key=lambda it: (-it[1], it[0]))
        hits: list[RagHit] = []
        for doc_id, score in ranked[: max(k, 1)]:
            hits.append(RagHit(doc=self._docs[doc_id], score=score))

        return hits


def _read_text_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        logger.exception("Failed to read text file: %s", path)
        return ""


def _chunk_markdown(text: str) -> list[str]:
    """Chunk markdown by headers, with a conservative fallback chunking."""
    if not text.strip():
        return []

    # Split on headers (levels 1-3) while keeping the header with its content.
    parts = re.split(r"\n(?=#{1,3}\s)", text)
    chunks = [p.strip() for p in parts if p and p.strip()]

    # Fallback: if we got a single giant chunk, split by paragraphs.
    if len(chunks) <= 1 and len(text) > 2500:
        paras = text.split("\n\n")
        out: list[str] = []
        buf = ""
        for para in paras:
            para = para.strip()
            if not para:
                continue
            if len(buf) + len(para) + 2 <= 2000:
                buf = (buf + "\n\n" + para).strip()
            else:
                if buf:
                    out.append(buf)
                buf = para
        if buf:
            out.append(buf)
        return out

    return chunks


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    try:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,)
        ).fetchone()
        return row is not None
    except Exception:
        logger.exception("Failed to check table existence: %s", table)
        return False


def _safe_connect(path: Path) -> sqlite3.Connection | None:
    try:
        if not path.exists():
            return None
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        logger.exception("Failed to open SQLite DB: %s", path)
        return None


def _load_markdown_sources() -> list[RagDocument]:
    base = Path(__file__).parent / "sources"
    if not base.exists():
        return []

    docs: list[RagDocument] = []
    for fp in sorted(base.glob("*.md")):
        text = _read_text_file(fp)
        for chunk in _chunk_markdown(text):
            docs.append(
                RagDocument(
                    content=chunk,
                    source=str(fp),
                    metadata={"kind": "md", "file": fp.name},
                )
            )

    return docs


def _load_sploitgpt_db_docs() -> list[RagDocument]:
    settings = get_settings()
    db_path = settings.data_dir / "sploitgpt.db"

    conn = _safe_connect(db_path)
    if conn is None:
        return []

    docs: list[RagDocument] = []

    try:
        # MITRE techniques
        if _table_exists(conn, "techniques"):
            rows = conn.execute(
                "SELECT id, name, tactic, description, detection, platforms FROM techniques"
            ).fetchall()
            for r in rows:
                tech_id = str(r["id"] or "").upper()
                name = str(r["name"] or "")
                tactic = str(r["tactic"] or "")
                desc = str(r["description"] or "")
                det = str(r["detection"] or "")
                platforms = str(r["platforms"] or "")

                # Keep technique docs small-ish.
                if len(desc) > 1200:
                    desc = desc[:1200] + "…"
                if len(det) > 800:
                    det = det[:800] + "…"

                content = (
                    f"MITRE ATT&CK Technique {tech_id}: {name}\n"
                    f"Tactic(s): {tactic}\n"
                    f"Platforms: {platforms}\n\n"
                    f"Description: {desc}\n\n"
                    f"Detection: {det}\n"
                ).strip()

                docs.append(
                    RagDocument(
                        content=content,
                        source=str(db_path),
                        metadata={"kind": "technique", "id": tech_id},
                    )
                )

        # Tool command templates
        if _table_exists(conn, "tool_techniques"):
            rows = conn.execute(
                "SELECT tool_name, technique_id, command_template FROM tool_techniques"
            ).fetchall()
            for r in rows:
                tool = str(r["tool_name"] or "")
                tech_id = str(r["technique_id"] or "").upper()
                template = str(r["command_template"] or "")
                if not template:
                    continue

                content = (
                    f"Tool template for {tech_id}\n"
                    f"Tool: {tool}\n"
                    f"Command: {template}\n"
                ).strip()

                docs.append(
                    RagDocument(
                        content=content,
                        source=str(db_path),
                        metadata={"kind": "tool_template", "tool": tool, "technique_id": tech_id},
                    )
                )

        # Service->technique mappings
        if _table_exists(conn, "service_techniques"):
            rows = conn.execute(
                "SELECT service, port, technique_id, priority FROM service_techniques"
            ).fetchall()
            for r in rows:
                service = str(r["service"] or "").lower()
                port = r["port"]
                tech_id = str(r["technique_id"] or "").upper()
                priority = int(r["priority"] or 0)

                content = (
                    f"Service mapping\n"
                    f"Service: {service}\n"
                    f"Port: {port if port is not None else ''}\n"
                    f"Technique: {tech_id}\n"
                    f"Priority: {priority}\n"
                ).strip()

                docs.append(
                    RagDocument(
                        content=content,
                        source=str(db_path),
                        metadata={"kind": "service_mapping", "service": service, "technique_id": tech_id},
                    )
                )

        # Atomic tests (when present in DB)
        if _table_exists(conn, "atomic_tests"):
            rows = conn.execute(
                "SELECT technique_id, name, description, executor, command, cleanup, elevation_required FROM atomic_tests"
            ).fetchall()
            for r in rows:
                tech_id = str(r["technique_id"] or "").upper()
                name = str(r["name"] or "")
                desc = str(r["description"] or "")
                executor = str(r["executor"] or "")
                command = str(r["command"] or "")
                cleanup = str(r["cleanup"] or "")
                elev = int(r["elevation_required"] or 0)

                if not command:
                    continue

                # Keep chunks compact.
                if len(command) > 500:
                    command = command[:500] + "…"

                content = (
                    f"Atomic test for {tech_id}: {name}\n"
                    f"Executor: {executor}\n"
                    f"Elevation required: {bool(elev)}\n\n"
                    f"Description: {desc}\n\n"
                    f"Command: {command}\n"
                ).strip()

                if cleanup:
                    if len(cleanup) > 400:
                        cleanup = cleanup[:400] + "…"
                    content += f"\nCleanup: {cleanup}\n"

                docs.append(
                    RagDocument(
                        content=content,
                        source=str(db_path),
                        metadata={"kind": "atomic_test", "technique_id": tech_id},
                    )
                )

        # GTFOBins (if present as table)
        if _table_exists(conn, "gtfobins"):
            rows = conn.execute(
                "SELECT binary, suid, sudo, shell, file_read, file_write, reverse_shell, capabilities FROM gtfobins"
            ).fetchall()
            for r in rows:
                binary = str(r["binary"] or "")
                if not binary:
                    continue

                parts: list[str] = [f"GTFOBins: {binary}"]
                for key in (
                    "suid",
                    "sudo",
                    "shell",
                    "file_read",
                    "file_write",
                    "reverse_shell",
                    "capabilities",
                ):
                    val = str(r[key] or "")
                    if val:
                        if len(val) > 400:
                            val = val[:400] + "…"
                        parts.append(f"{key}: {val}")

                docs.append(
                    RagDocument(
                        content="\n".join(parts),
                        source=str(db_path),
                        metadata={"kind": "gtfobins", "binary": binary},
                    )
                )

    finally:
        conn.close()

    return docs


def _load_memory_db_docs(limit: int = 250) -> list[RagDocument]:
    """Load prior observed attack patterns (if present) as retrievable docs."""
    settings = get_settings()
    db_path = settings.data_dir / "memory.db"

    conn = _safe_connect(db_path)
    if conn is None:
        return []

    docs: list[RagDocument] = []
    try:
        if not _table_exists(conn, "attack_patterns"):
            return []

        rows = conn.execute(
            """
            SELECT service_name, port, product, version, technique_id, technique_name, phase,
                   command, tool, outcome, success, target_os, target_info, notes, created_at
            FROM attack_patterns
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        for r in rows:
            service = str(r["service_name"] or "").lower()
            port = r["port"]
            product = str(r["product"] or "")
            version = str(r["version"] or "")
            tech_id = str(r["technique_id"] or "").upper()
            tech_name = str(r["technique_name"] or "")
            phase = str(r["phase"] or "")
            command = str(r["command"] or "")
            tool = str(r["tool"] or "")
            outcome = str(r["outcome"] or "")
            success = int(r["success"] or 0)
            target_os = str(r["target_os"] or "")
            target_info = str(r["target_info"] or "")
            notes = str(r["notes"] or "")

            if not command:
                continue

            # Avoid giant blobs
            if len(command) > 400:
                command = command[:400] + "…"
            if len(outcome) > 600:
                outcome = outcome[:600] + "…"
            if len(notes) > 400:
                notes = notes[:400] + "…"

            content = (
                "Observed attack pattern (local memory)\n"
                f"Service: {service} {f'({port})' if port is not None else ''}\n"
                f"Product: {product} {version}\n"
                f"Phase: {phase}\n"
                f"Technique: {tech_id} {tech_name}\n"
                f"Tool: {tool}\n"
                f"Success: {bool(success)}\n\n"
                f"Command: {command}\n"
                f"Outcome: {outcome}\n"
            ).strip()

            if target_os:
                content += f"\nTarget OS: {target_os}\n"
            if target_info:
                content += f"Target info: {target_info}\n"
            if notes:
                content += f"Notes: {notes}\n"

            docs.append(
                RagDocument(
                    content=content,
                    source=str(db_path),
                    metadata={"kind": "memory_pattern", "service": service},
                )
            )

        return docs
    finally:
        conn.close()


_RAG_INDEX: BM25Index | None = None


def get_rag_index(*, force_reload: bool = False) -> BM25Index:
    """Build (or return) the global RAG index."""
    global _RAG_INDEX

    if _RAG_INDEX is not None and not force_reload:
        return _RAG_INDEX

    docs: list[RagDocument] = []
    docs.extend(_load_markdown_sources())
    docs.extend(_load_sploitgpt_db_docs())
    docs.extend(_load_memory_db_docs())

    _RAG_INDEX = BM25Index(docs)
    return _RAG_INDEX


def get_retrieved_context(
    query: str,
    *,
    services: list[str] | None = None,
    phase: str | None = None,
    top_k: int = 4,
    max_chars: int = 2200,
) -> str:
    """Return a concise, bounded context block relevant to the query."""
    q = (query or "").strip()
    if not q:
        return ""

    # Lightly enrich query with known services/phase (helps retrieval without embeddings).
    extra: list[str] = []
    if services:
        extra.append(" ".join(services[:8]))
    if phase:
        extra.append(phase)

    enriched = " ".join([q, *extra]).strip()

    index = get_rag_index()
    hits = index.search(enriched, k=max(1, top_k))
    if not hits:
        return ""

    out_lines: list[str] = ["## Retrieved Knowledge (local)", ""]
    remaining = max(200, max_chars)

    for i, hit in enumerate(hits, 1):
        src = hit.doc.metadata.get("file") or Path(hit.doc.source).name
        header = f"[{i}] {src}"

        chunk = hit.doc.content.strip()
        if len(chunk) > remaining:
            chunk = chunk[: max(0, remaining - 1)].rstrip() + "…"

        if len(chunk) < 80:
            # Skip ultra-short chunks; they usually don’t add value.
            continue

        out_lines.append(header)
        out_lines.append(chunk)
        out_lines.append("")

        remaining = max_chars - sum(len(line) + 1 for line in out_lines)
        if remaining <= 200:
            break

    # If we filtered everything out, return empty.
    joined = "\n".join(out_lines).strip()
    if joined == "## Retrieved Knowledge (local)":
        return ""

    return joined
