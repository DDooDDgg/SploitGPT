"""Kali tool catalog + docs ingestion.

This is intentionally lightweight and offline-friendly. It builds a local SQLite
catalog from OS-maintained metadata (man-db/whatis, desktop entries, dpkg).

Design:
- Build-time: populate `kali_tools` with a broad list + 1-line summaries.
- Runtime: `tool_help` can lazily cache per-tool help/man snippets into
  `kali_tool_docs` so the agent learns "how to use it" over time without
  pre-indexing thousands of man pages.
"""

from __future__ import annotations

import argparse
import configparser
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_SAFE_TOOL_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$")


@dataclass
class ToolCard:
    tool: str
    summary: str = ""
    categories: str = ""
    exec: str = ""
    path: str = ""
    package: str = ""
    aliases: str = ""


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS kali_tools (
            tool TEXT PRIMARY KEY,
            package TEXT,
            summary TEXT,
            categories TEXT,
            exec TEXT,
            path TEXT,
            aliases TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS kali_tool_docs (
            tool TEXT NOT NULL,
            kind TEXT NOT NULL,
            chunk_index INTEGER NOT NULL DEFAULT 0,
            content TEXT NOT NULL,
            source TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (tool, kind, chunk_index)
        );

        CREATE INDEX IF NOT EXISTS idx_kali_tools_pkg ON kali_tools(package);
        CREATE INDEX IF NOT EXISTS idx_kali_tool_docs_kind ON kali_tool_docs(kind);
        """
    )


def _run(argv: list[str], *, timeout_s: float = 4.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env={**os.environ, "LC_ALL": "C"},
    )


def _parse_desktop_file(path: Path) -> dict[str, str]:
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read(path, encoding="utf-8")
    except Exception:
        return {}

    section = "Desktop Entry"
    if section not in cp:
        return {}

    d = cp[section]
    out: dict[str, str] = {}
    for key in ("Name", "Comment", "Exec", "Categories"):
        val = (d.get(key) or "").strip()
        if val:
            out[key.lower()] = val
    return out


def _extract_exec_binary(exec_str: str) -> str:
    # Desktop Exec entries can contain placeholders like %U, %f.
    if not exec_str:
        return ""
    try:
        parts = shlex.split(exec_str)
    except Exception:
        parts = exec_str.split()
    parts = [p for p in parts if p and not p.startswith("%")]
    if not parts:
        return ""
    # Sometimes entries are like "sh -c <cmd>"; treat the underlying tool as unknown.
    if parts[0] in ("sh", "bash", "zsh") and len(parts) >= 3 and parts[1] == "-c":
        return ""
    return parts[0]


def collect_from_desktop_entries(
    *,
    applications_dir: Path = Path("/usr/share/applications"),
) -> dict[str, ToolCard]:
    cards: dict[str, ToolCard] = {}
    if not applications_dir.exists():
        return cards

    for fp in sorted(applications_dir.glob("*.desktop")):
        meta = _parse_desktop_file(fp)
        if not meta:
            continue

        exec_str = meta.get("exec", "")
        binary = _extract_exec_binary(exec_str)
        if not binary:
            continue

        tool = Path(binary).name
        if not _SAFE_TOOL_RE.match(tool):
            continue

        summary = meta.get("comment", "").strip()
        categories = meta.get("categories", "").strip()
        card = cards.get(tool) or ToolCard(tool=tool)
        if summary and not card.summary:
            card.summary = summary
        if categories and not card.categories:
            card.categories = categories
        if exec_str and not card.exec:
            card.exec = exec_str
        cards[tool] = card

    return cards


def _iter_manpage_names(base: Path) -> Iterable[str]:
    if not base.exists():
        return

    # Focus on command-relevant sections: 1 (user) and 8 (admin).
    for section in ("man1", "man8"):
        d = base / section
        if not d.exists():
            continue
        for fp in d.iterdir():
            name = fp.name
            # e.g., nmap.1.gz or ssh.1
            if ".1" not in name and ".8" not in name:
                continue
            # strip .gz then section suffix
            if name.endswith(".gz"):
                name = name[:-3]
            tool = name.split(".", 1)[0]
            if _SAFE_TOOL_RE.match(tool):
                yield tool


def collect_from_manpages() -> dict[str, ToolCard]:
    cards: dict[str, ToolCard] = {}
    bases = [
        Path("/usr/share/man"),
        Path("/usr/local/share/man"),
    ]
    seen: set[str] = set()
    for base in bases:
        for tool in _iter_manpage_names(base):
            if tool in seen:
                continue
            seen.add(tool)
            cards[tool] = ToolCard(tool=tool)
    return cards


def _whatis_summary(tool: str) -> str:
    try:
        proc = _run(["whatis", tool], timeout_s=2.5)
    except Exception:
        return ""

    out = (proc.stdout or "").strip()
    if not out:
        return ""
    # Take first line: "nmap (1) - Network exploration tool and security / port scanner"
    line = out.splitlines()[0]
    if " - " in line:
        return line.split(" - ", 1)[1].strip()
    return line.strip()


def _batch_whatis_summaries(tools: list[str]) -> dict[str, str]:
    """Return tool -> summary using batched `whatis` calls.

    This is backed by man-db's index and is typically much faster than reading
    and parsing full man pages. Batching avoids thousands of subprocess calls
    when generating an image snapshot.
    """
    if not tools:
        return {}

    summaries: dict[str, str] = {}
    chunk_size = 120  # conservative to avoid argv limits
    for i in range(0, len(tools), chunk_size):
        chunk = tools[i : i + chunk_size]
        try:
            proc = _run(["whatis", *chunk], timeout_s=10.0)
        except Exception:
            continue

        text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        for line in text.splitlines():
            line = line.strip()
            if not line or ": nothing appropriate." in line or " - " not in line:
                continue

            left, desc = line.split(" - ", 1)
            desc = desc.strip()
            name_part = left.split("(", 1)[0].strip()
            names = [n.strip() for n in name_part.split(",") if n.strip()]
            for name in names:
                tool = name.split()[0]
                if _SAFE_TOOL_RE.match(tool) and desc and tool not in summaries:
                    summaries[tool] = desc

    return summaries


def _which_path(tool: str) -> str:
    p = shutil.which(tool)
    return p or ""


def _dpkg_owning_package(path: str) -> str:
    if not path:
        return ""
    try:
        proc = _run(["dpkg", "-S", path], timeout_s=3.5)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    line = (proc.stdout or "").splitlines()[0].strip()
    # Format: "pkg: /usr/bin/tool"
    if ":" in line:
        return line.split(":", 1)[0].strip()
    return ""


def _batch_dpkg_owning_packages(paths: list[str]) -> dict[str, str]:
    """Return path -> package using batched `dpkg -S` calls."""
    if not paths:
        return {}

    out: dict[str, str] = {}
    chunk_size = 160
    for i in range(0, len(paths), chunk_size):
        chunk = paths[i : i + chunk_size]
        try:
            proc = _run(["dpkg", "-S", *chunk], timeout_s=12.0)
        except Exception:
            continue

        text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        for line in text.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            pkg, rest = line.split(":", 1)
            pkg = pkg.strip()
            rest = rest.strip()
            path = rest.split()[0] if rest else ""
            if pkg and path and path not in out:
                out[path] = pkg

    return out


def _dpkg_short_description(package: str) -> str:
    if not package:
        return ""
    try:
        proc = _run(["dpkg-query", "-s", package], timeout_s=3.5)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    for line in (proc.stdout or "").splitlines():
        if line.startswith("Description:"):
            return line.split(":", 1)[1].strip()
    return ""


def upsert_tool_cards(conn: sqlite3.Connection, cards: Iterable[ToolCard]) -> int:
    ensure_schema(conn)
    rows = list(cards)
    if not rows:
        return 0

    now = _utc_now_iso()
    conn.executemany(
        """
        INSERT INTO kali_tools (tool, package, summary, categories, exec, path, aliases, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(tool) DO UPDATE SET
            package=excluded.package,
            summary=CASE WHEN excluded.summary != '' THEN excluded.summary ELSE kali_tools.summary END,
            categories=CASE WHEN excluded.categories != '' THEN excluded.categories ELSE kali_tools.categories END,
            exec=CASE WHEN excluded.exec != '' THEN excluded.exec ELSE kali_tools.exec END,
            path=CASE WHEN excluded.path != '' THEN excluded.path ELSE kali_tools.path END,
            aliases=CASE WHEN excluded.aliases != '' THEN excluded.aliases ELSE kali_tools.aliases END,
            updated_at=excluded.updated_at
        """,
        [
            (
                c.tool,
                c.package,
                c.summary,
                c.categories,
                c.exec,
                c.path,
                c.aliases,
                now,
            )
            for c in rows
        ],
    )
    conn.commit()
    return len(rows)


def build_catalog(*, include_manpages: bool = True, include_desktop: bool = True) -> list[ToolCard]:
    merged: dict[str, ToolCard] = {}

    if include_manpages:
        merged.update(collect_from_manpages())
    if include_desktop:
        merged.update(collect_from_desktop_entries())

    # Enrich using OS metadata.
    tools = list(merged.keys())

    # Paths (cheap)
    for tool in tools:
        card = merged[tool]
        if not card.path:
            card.path = _which_path(tool)

    # Summaries (batched)
    need_summary = [t for t in tools if not merged[t].summary]
    summaries = _batch_whatis_summaries(need_summary)
    for tool, summary in summaries.items():
        if tool in merged and summary and not merged[tool].summary:
            merged[tool].summary = summary

    # Package ownership (batched)
    need_pkg_paths = [merged[t].path for t in tools if merged[t].path and not merged[t].package]
    path_to_pkg = _batch_dpkg_owning_packages(need_pkg_paths)
    for tool in tools:
        card = merged[tool]
        if card.path and not card.package:
            card.package = path_to_pkg.get(card.path, "") or card.package

    # Last resort summary from package description
    for tool in tools:
        card = merged[tool]
        if not card.summary and card.package:
            card.summary = _dpkg_short_description(card.package)

    return list(merged.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build SploitGPT Kali tool catalog.")
    parser.add_argument(
        "--db",
        type=str,
        default="",
        help="SQLite DB path; default uses SploitGPT settings (data/sploitgpt.db).",
    )
    parser.add_argument("--no-manpages", action="store_true", help="Skip /usr/share/man scan.")
    parser.add_argument("--no-desktop", action="store_true", help="Skip /usr/share/applications scan.")
    parser.add_argument("--limit", type=int, default=0, help="Optional max tools to write (0 = no limit).")
    args = parser.parse_args(argv)

    if args.db:
        db_path = Path(args.db)
        db_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        from sploitgpt.db import get_db_path

        db_path = get_db_path()
        db_path.parent.mkdir(parents=True, exist_ok=True)

    include_manpages = not bool(args.no_manpages)
    include_desktop = not bool(args.no_desktop)
    cards = build_catalog(include_manpages=include_manpages, include_desktop=include_desktop)

    if args.limit and args.limit > 0:
        cards = cards[: args.limit]

    with sqlite3.connect(db_path) as conn:
        upsert_tool_cards(conn, cards)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
