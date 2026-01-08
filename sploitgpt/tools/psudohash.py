"""psudohash wrapper for targeted wordlist generation."""

from __future__ import annotations

import logging
import re
import shlex
from pathlib import Path

from sploitgpt.core.config import get_settings
from sploitgpt.tools import register_tool, terminal

logger = logging.getLogger(__name__)


def _safe_name(raw: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
    return cleaned or "wordlist"


@register_tool("generate_wordlist")
async def generate_wordlist(
    base: str,
    extra_words: list[str] | None = None,
    years: str | None = None,
    min_len: int = 6,
    max_len: int = 18,
    save_as: str | None = None,
) -> str:
    """
    Generate a targeted wordlist using psudohash mutations.

    Args:
        base: Base word (e.g., company, username, hostname).
        extra_words: Additional keywords to include (list).
        years: Optional year or comma/range string to append (e.g., "2022" or "2010-2024").
        min_len: Minimum word length.
        max_len: Maximum word length.
        save_as: Optional filename; defaults to <base>.txt in loot/wordlists.

    Returns:
        Summary with path and sample lines.
    """
    settings = get_settings()
    loot_dir = settings.loot_dir / "wordlists"
    loot_dir.mkdir(parents=True, exist_ok=True)

    fname = save_as or f"{_safe_name(base)}.txt"
    outfile = loot_dir / fname

    cmd = [
        "python3",
        str(Path(__file__).resolve().parent.parent.parent / "vendor" / "psudohash.py"),
    ]
    words = [base, *(extra_words or [])]
    cmd += ["-w", ",".join([w for w in (str(x).strip() for x in words) if w])]
    if years:
        cmd += ["-y", years]
    cmd += ["-o", str(outfile)]
    cmd += ["--minlen", str(min_len), "--maxlen", str(max_len)]

    # psudohash prompts for confirmation; feed "y" via shell.
    shell_cmd = "printf 'y\\n' | " + shlex.join(cmd)
    result = await terminal(command=shell_cmd, args=None, allow_shell=True)

    sample = ""
    try:
        lines = outfile.read_text(encoding="utf-8", errors="ignore").splitlines()
        sample = "\n".join(lines[:10])
    except Exception:
        pass

    out_lines = [
        f"psudohash generated wordlist: {outfile}",
        f"Command: {shlex.join(cmd)}",
    ]
    if "Error" in result or "Traceback" in result:
        out_lines.append("Generation reported errors; check output above.")
    if sample:
        out_lines.append("\nSample:")
        out_lines.append(sample)

    return "\n".join(out_lines)
