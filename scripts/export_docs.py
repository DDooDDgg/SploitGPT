"""Export SploitGPT knowledge sources into chunked JSON documents.

This prepares data for downstream synthetic instruction generation or
retriever training. It ingests:

1. Markdown playbooks under sploitgpt/knowledge/sources/
2. MITRE ATT&CK techniques (via AttackKnowledge)
3. Command templates from sploitgpt.tools.commands
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

import sys

# Ensure project root is importable when running via `python scripts/...`
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sploitgpt.knowledge.attack import AttackKnowledge
from sploitgpt.tools import commands as command_module


def _chunk_markdown(text: str) -> list[str]:
    """Split markdown content into manageable sections."""

    text = text.strip()
    if not text:
        return []

    # Split on headers while preserving the header text inside the chunk
    parts = re.split(r"\n(?=#{1,3}\s)", text)
    chunks = [p.strip() for p in parts if p and p.strip()]

    if len(chunks) <= 1 and len(text) > 2500:
        # Conservative paragraph fallback
        buffered: list[str] = []
        buf = ""
        for para in text.split("\n\n"):
            para = para.strip()
            if not para:
                continue
            if len(buf) + len(para) + 2 <= 2000:
                buf = (buf + "\n\n" + para).strip()
            else:
                if buf:
                    buffered.append(buf)
                buf = para
        if buf:
            buffered.append(buf)
        chunks = buffered

    return chunks


def _load_markdown_docs(source_dir: Path) -> list[dict]:
    docs: list[dict] = []
    for md_file in sorted(source_dir.glob("*.md")):
        content = md_file.read_text(encoding="utf-8", errors="ignore")
        for idx, chunk in enumerate(_chunk_markdown(content)):
            docs.append(
                {
                    "id": f"md::{md_file.name}::{idx}",
                    "title": f"{md_file.stem} section {idx+1}",
                    "content": chunk,
                    "source": str(md_file.relative_to(REPO_ROOT)),
                    "metadata": {"kind": "markdown", "file": md_file.name},
                }
            )
    return docs


async def _load_attack_docs(include_attack: bool) -> list[dict]:
    if not include_attack:
        return []

    attack_kb = AttackKnowledge()
    await attack_kb.initialize()

    docs: list[dict] = []
    for tech in attack_kb.techniques.values():
        content_lines = [f"**{tech.name}** ({tech.id})", tech.description.strip()]
        if tech.tactics:
            content_lines.append(f"Tactics: {', '.join(tech.tactics)}")
        if tech.platforms:
            content_lines.append(f"Platforms: {', '.join(tech.platforms)}")
        if tech.detection:
            content_lines.append(f"Detection: {tech.detection}")

        docs.append(
            {
                "id": f"mitre::{tech.id}",
                "title": f"MITRE {tech.id}",
                "content": "\n".join(line for line in content_lines if line),
                "source": "mitre_attack.sqlite",
                "metadata": {"kind": "technique", **asdict(tech)},
            }
        )

    return docs


def _load_command_docs(include_commands: bool) -> list[dict]:
    if not include_commands:
        return []

    docs: list[dict] = []

    def _iter_commands() -> Iterable[tuple[str, dict[str, dict]]]:
        for name in dir(command_module):
            if not name.isupper() or not name.endswith("COMMANDS"):
                continue
            value = getattr(command_module, name)
            if isinstance(value, dict):
                yield name, value

    for category, table in _iter_commands():
        for key, entry in table.items():
            content = [entry.get("description", "").strip()]
            if entry.get("command"):
                content.append(f"Command: {entry['command']}")
            if entry.get("example"):
                content.append(f"Example: {entry['example']}")
            docs.append(
                {
                    "id": f"command::{category.lower()}::{key}",
                    "title": f"{category}:{key}",
                    "content": "\n".join(content),
                    "source": "sploitgpt/tools/commands.py",
                    "metadata": {
                        "kind": "command",
                        "category": category,
                        "key": key,
                    },
                }
            )

    return docs


async def main() -> None:
    parser = argparse.ArgumentParser(description="Export SploitGPT knowledge docs")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/rag_docs.json"),
        help="Path to write JSON document list",
    )
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=REPO_ROOT / "sploitgpt" / "knowledge" / "sources",
        help="Directory containing markdown sources",
    )
    parser.add_argument(
        "--no-attack",
        action="store_true",
        help="Skip MITRE ATT&CK export",
    )
    parser.add_argument(
        "--no-commands",
        action="store_true",
        help="Skip command reference export",
    )

    args = parser.parse_args()

    docs = _load_markdown_docs(args.source_dir)
    docs.extend(_load_command_docs(not args.no_commands))
    docs.extend(await _load_attack_docs(not args.no_attack))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(docs, fh, ensure_ascii=False, indent=2)

    print(f"Exported {len(docs)} documents to {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
