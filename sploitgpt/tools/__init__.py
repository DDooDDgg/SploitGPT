"""SploitGPT Tools Module."""

import asyncio
import importlib
import logging
import os
import re
import shlex
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

ToolFunc = Callable[..., Awaitable[str]]
F = TypeVar("F", bound=ToolFunc)

# Tool registry
TOOLS: dict[str, ToolFunc] = {}
logger = logging.getLogger(__name__)


def register_tool(name: str) -> Callable[[F], F]:
    """Decorator to register a tool."""

    def decorator(func: F) -> F:
        TOOLS[name] = func
        return func

    return decorator


async def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a tool by name."""
    import time

    from sploitgpt.core.audit import get_audit_logger

    audit = get_audit_logger()

    if name not in TOOLS:
        audit.log_error(f"Unknown tool '{name}'", context="execute_tool")
        return f"Error: Unknown tool '{name}'"

    # Log tool call
    audit.log_tool_call(tool_name=name, args=args)
    start_time = time.monotonic()

    try:
        result = await TOOLS[name](**args)
        execution_time_ms = int((time.monotonic() - start_time) * 1000)
        audit.log_tool_result(
            tool_name=name,
            success=True,
            result=result,
            execution_time_ms=execution_time_ms,
        )
        return result
    except Exception as e:  # pragma: no cover - defensive logging
        execution_time_ms = int((time.monotonic() - start_time) * 1000)
        logger.exception("Error executing tool %s", name)
        audit.log_tool_result(
            tool_name=name,
            success=False,
            error=str(e),
            execution_time_ms=execution_time_ms,
        )
        return f"Error executing {name}: {e}"


def _msf_unavailable_error() -> str:
    return (
        "Error: could not connect/authenticate to msfrpcd. "
        "Check that msfrpcd is running (systemd: `systemctl start metasploit`) "
        "and verify SPLOITGPT_MSF_HOST/PORT/PASSWORD/SSL."
    )


async def _connect_msf_with_retry(msf: Any, max_attempts: int = 3, delay_s: float = 1.0) -> bool:
    if bool(getattr(msf, "is_connected", False)):
        return True

    for attempt in range(max_attempts):
        if await msf.connect():
            return True
        if attempt < max_attempts - 1:
            await asyncio.sleep(delay_s)
    return False


@register_tool("terminal")
async def terminal(
    command: str | list[str] | None = None,
    timeout: int = 300,
    allow_shell: bool = False,
    args: list[str] | None = None,
) -> str:
    """Execute a command.

    - Prefer passing a list of args via `args` (no shell).
    - If a string is provided, it will be split with shlex and run without a shell.
    - Set allow_shell=True only when you intentionally need shell features (pipes, redirects)
      and have already sanitized/quoted the input. Multiline shell commands are rejected.
    """

    async def _maybe_fix_bind_mount_ownership() -> None:
        """Best-effort fix for root-owned files in bind-mounted work dirs.

        When running inside a container as root, tools like nmap write to /app/loot and
        those files appear on the host as root-owned. This makes host-side workflows
        painful. We detect the owner of the mount and chown only root-owned files.
        """
        try:
            if os.geteuid() != 0:
                return

            candidates = ["/app/loot", "/app/sessions", "/app/data"]
            existing = [p for p in candidates if os.path.isdir(p)]
            if not existing:
                return

            # Prefer explicit host UID/GID overrides.
            env_uid = os.environ.get("SPLOITGPT_HOST_UID")
            env_gid = os.environ.get("SPLOITGPT_HOST_GID")
            uid: int | None = int(env_uid) if (env_uid and env_uid.isdigit()) else None
            gid: int | None = int(env_gid) if (env_gid and env_gid.isdigit()) else None

            # Otherwise infer from the directory owner (bind mount will usually reflect host uid/gid).
            if uid is None or gid is None:
                for p in existing:
                    st = os.stat(p)
                    if st.st_uid != 0 or st.st_gid != 0:
                        uid, gid = st.st_uid, st.st_gid
                        break

            if uid is None or gid is None:
                return
            if uid == 0 and gid == 0:
                return

            def _chown_root_owned(base: str) -> None:
                try:
                    base_stat = os.lstat(base)
                except FileNotFoundError:
                    return

                for root, dirs, files in os.walk(base):
                    try:
                        root_stat = os.lstat(root)
                        if root_stat.st_dev != base_stat.st_dev:
                            dirs[:] = []
                            continue
                    except FileNotFoundError:
                        continue

                    for entry in dirs + files:
                        target = os.path.join(root, entry)
                        try:
                            st = os.lstat(target)
                            if st.st_dev != base_stat.st_dev:
                                continue
                            if st.st_uid == 0 and st.st_gid == 0:
                                os.chown(target, uid, gid)
                        except FileNotFoundError:
                            continue
                        except PermissionError:
                            continue
                        except Exception:
                            logger.debug("Failed to chown %s", target, exc_info=True)

            for p in existing:
                _chown_root_owned(p)
        except Exception:
            # Never fail the tool because of ownership adjustments.
            return

    def _normalize_command(
        cmd: str | list[str] | None,
        argv: list[str] | None,
        shell_ok: bool,
    ) -> tuple[list[str] | str | None, bool, str | None]:
        if argv is not None:
            normalized = [str(part) for part in argv if str(part).strip()]
            if not normalized:
                return None, False, "Error: empty command"
            return normalized, False, None

        if cmd is None:
            return None, False, "Error: empty command"

        if isinstance(cmd, list):
            normalized = [str(part) for part in cmd if str(part).strip()]
            if not normalized:
                return None, False, "Error: empty command"
            return normalized, False, None

        cmd_str = cmd.strip()
        if not cmd_str:
            return None, False, "Error: empty command"

        if shell_ok:
            if any(ch in cmd_str for ch in ("\n", "\r")):
                return None, False, "Error: multiline shell commands are not allowed"
            return cmd_str, True, None

        return shlex.split(cmd_str), False, None

    try:
        proc = None

        normalized, use_shell, error = _normalize_command(command, args, allow_shell)
        if error:
            return error

        if normalized is None:
            return "Error: empty command"

        if use_shell and isinstance(normalized, str):
            proc = await asyncio.create_subprocess_shell(
                normalized,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        elif isinstance(normalized, list):
            proc = await asyncio.create_subprocess_exec(
                *normalized,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        else:
            return "Error: invalid command format"

        try:
            if timeout <= 0:
                stdout, _ = await proc.communicate()
            else:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode() if stdout else "(no output)"
        except TimeoutError:
            proc.kill()
            try:
                # Ensure the process is fully reaped to avoid resource warnings.
                await proc.wait()
            except Exception as e:
                logger.warning(f"Failed to wait for killed process: {e}")
            output = f"Command timed out after {timeout}s"

        await _maybe_fix_bind_mount_ownership()
        return output

    except Exception as e:
        # Still attempt ownership fix in case partial output was written.
        await _maybe_fix_bind_mount_ownership()
        return f"Error: {e}"


@register_tool("knowledge_search")
async def knowledge_search(query: str, top_k: int = 5) -> str:
    """Search SploitGPT's local knowledge base (docs + cached DB knowledge).

    This is a read-only tool: it does not execute commands.
    """
    from sploitgpt.knowledge.rag import get_retrieved_context

    q = (query or "").strip()
    if not q:
        return "Error: empty query"

    ctx = get_retrieved_context(q, top_k=max(1, top_k), max_chars=3200)
    return ctx if ctx else "No relevant local knowledge found."


@register_tool("tool_search")
async def tool_search(query: str, limit: int = 8) -> str:
    """Search installed Kali tools and return short "tool cards".

    Prefers the baked `kali_tools` catalog in `data/sploitgpt.db`.
    Falls back to `apropos` when the catalog is missing/empty.
    """
    q = (query or "").strip()
    if not q:
        return "Error: empty query"

    try:
        limit_n = int(limit)
    except Exception:
        limit_n = 8
    limit_n = max(1, min(limit_n, 20))

    # 1) Preferred: local SQLite catalog
    rows: list[dict[str, Any]] = []
    try:
        from sploitgpt.db import get_connection, init_db

        init_db()
        conn = get_connection()
        try:
            like = f"%{q}%"
            db_rows = conn.execute(
                """
                SELECT tool, summary, categories, exec, package, path
                FROM kali_tools
                WHERE tool LIKE ? COLLATE NOCASE
                   OR summary LIKE ? COLLATE NOCASE
                   OR categories LIKE ? COLLATE NOCASE
                LIMIT 120
                """,
                (like, like, like),
            ).fetchall()
            for r in db_rows:
                rows.append(
                    {
                        "tool": str(r["tool"] or ""),
                        "summary": str(r["summary"] or ""),
                        "categories": str(r["categories"] or ""),
                        "exec": str(r["exec"] or ""),
                        "package": str(r["package"] or ""),
                        "path": str(r["path"] or ""),
                    }
                )
        finally:
            conn.close()
    except Exception:
        rows = []

    ql = q.lower()

    def _score(card: dict[str, Any]) -> int:
        tool = str(card.get("tool") or "")
        summary = str(card.get("summary") or "")
        categories = str(card.get("categories") or "")
        tl = tool.lower()
        s = 0
        if tl == ql:
            s += 200
        elif tl.startswith(ql):
            s += 120
        elif ql in tl:
            s += 80
        if ql and ql in (summary or "").lower():
            s += 40
        if ql and ql in (categories or "").lower():
            s += 10
        # Prefer tools we can locate on PATH.
        if card.get("path"):
            s += 5
        return s

    if rows:
        ranked = sorted(rows, key=lambda c: (-_score(c), str(c.get("tool") or "")))
        ranked = [c for c in ranked if c.get("tool")]
        ranked = ranked[:limit_n]
        lines: list[str] = [f"Found {len(ranked)} tools for '{q}':", ""]
        for i, c in enumerate(ranked, 1):
            tool = c.get("tool", "")
            summary = c.get("summary", "")
            pkg = c.get("package", "")
            suffix = f" (pkg: {pkg})" if pkg else ""
            if summary:
                lines.append(f"{i}. {tool} — {summary}{suffix}")
            else:
                lines.append(f"{i}. {tool}{suffix}")
        return "\n".join(lines).strip()

    # 2) Fallback: man-db keyword search
    def _apropos(query: str) -> str:
        import os
        import subprocess

        proc = subprocess.run(
            ["apropos", query],
            capture_output=True,
            text=True,
            timeout=4.0,
            env={**os.environ, "LC_ALL": "C"},
        )
        return (proc.stdout or proc.stderr or "").strip()

    try:
        out = await asyncio.to_thread(_apropos, q)
    except Exception:
        out = ""

    if not out:
        return f"No tools found for '{q}'."

    # Parse lines like: "nmap (1) - Network exploration tool..."
    safe_tool_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$")
    candidates: list[tuple[str, str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or " - " not in line:
            continue
        left, desc = line.split(" - ", 1)
        name_part = left.split("(", 1)[0].strip()
        # Handle "name1, name2" output.
        names = [n.strip() for n in name_part.split(",") if n.strip()]
        for name in names[:2]:
            tool = name.split()[0]
            if safe_tool_re.match(tool):
                candidates.append((tool, desc.strip()))
        if len(candidates) >= 80:
            break

    if not candidates:
        return f"No tools found for '{q}'."

    # De-dup while preserving order.
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for tool, desc in candidates:
        if tool in seen:
            continue
        seen.add(tool)
        unique.append((tool, desc))
        if len(unique) >= limit_n:
            break

    lines = [f"Found {len(unique)} tools for '{q}' (apropos):", ""]
    for i, (tool, desc) in enumerate(unique, 1):
        lines.append(f"{i}. {tool} — {desc}")
    return "\n".join(lines).strip()


@register_tool("tool_help")
async def tool_help(tool: str, max_chars: int = 3200) -> str:
    """Return usage/help for a local tool (from cache, man, or --help).

    This tool is designed to prevent the agent from guessing flags/options.
    """
    name = (tool or "").strip()
    if not name:
        return "Error: empty tool name"

    safe_tool_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,127}$")
    if not safe_tool_re.match(name):
        return "Error: tool name must be a simple command name (no spaces)."

    try:
        max_n = int(max_chars)
    except Exception:
        max_n = 3200
    max_n = max(800, min(max_n, 12000))

    from sploitgpt.db import get_connection, init_db

    init_db()

    def _load_cached() -> tuple[str, list[tuple[str, int, str, str]]]:
        import sqlite3

        conn = get_connection()
        try:
            summary = ""
            try:
                row = conn.execute(
                    "SELECT summary FROM kali_tools WHERE tool = ? LIMIT 1", (name,)
                ).fetchone()
                if row:
                    summary = str(row["summary"] or "")
            except sqlite3.OperationalError:
                summary = ""

            docs: list[tuple[str, int, str, str]] = []
            try:
                rows = conn.execute(
                    """
                    SELECT kind, chunk_index, content, COALESCE(source, '') AS source
                    FROM kali_tool_docs
                    WHERE tool = ?
                    ORDER BY
                        CASE kind
                            WHEN 'help' THEN 0
                            WHEN 'man' THEN 1
                            WHEN 'tldr' THEN 2
                            WHEN 'pkgdesc' THEN 3
                            ELSE 9
                        END,
                        chunk_index
                    """,
                    (name,),
                ).fetchall()
                for r in rows:
                    docs.append(
                        (
                            str(r["kind"] or ""),
                            int(r["chunk_index"] or 0),
                            str(r["content"] or ""),
                            str(r["source"] or ""),
                        )
                    )
            except sqlite3.OperationalError:
                docs = []

            return summary, docs
        finally:
            conn.close()

    summary, cached = _load_cached()
    if cached:
        out_lines: list[str] = [f"Tool: {name}"]
        if summary:
            out_lines.append(f"Summary: {summary}")
        out_lines.append("")
        remaining = max_n
        current_kind: str | None = None
        for kind, _, content, source in cached:
            if not content.strip():
                continue
            if kind != current_kind:
                current_kind = kind
                label = f"{kind.upper()}"
                if source:
                    label += f" ({source})"
                out_lines.append(f"[{label}]")
            chunk = content.strip()
            if len(chunk) > remaining:
                chunk = chunk[: max(0, remaining - 1)].rstrip() + "…"
            out_lines.append(chunk)
            out_lines.append("")
            remaining = max_n - sum(len(line) + 1 for line in out_lines)
            if remaining <= 200:
                break
        return "\n".join(out_lines).strip()

    # No cached docs: capture and cache best-effort.
    def _capture_help_and_man(cmd: str) -> tuple[str, str]:
        import os
        import subprocess

        def run(argv: list[str], timeout_s: float) -> str:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout_s,
                env={
                    **os.environ,
                    "LC_ALL": "C",
                    "PAGER": "cat",
                    "MANPAGER": "cat",
                    "MANWIDTH": "80",
                },
            )
            return (proc.stdout or "").strip()

        help_out = ""
        for flag in ("--help", "-h"):
            try:
                help_out = run([cmd, flag], timeout_s=3.0)
            except Exception:
                help_out = ""
            if help_out:
                break

        man_out = ""
        try:
            man_out = run(["man", cmd], timeout_s=4.0)
        except Exception:
            man_out = ""

        # Strip common backspace overstrikes from man output.
        if "\b" in man_out:
            cleaned = []
            skip_next = False
            for i, ch in enumerate(man_out):
                if skip_next:
                    skip_next = False
                    continue
                if i + 1 < len(man_out) and man_out[i + 1] == "\b":
                    # drop this char and the backspace, keep the overstruck char later
                    skip_next = True
                    continue
                if ch != "\b":
                    cleaned.append(ch)
            man_out = "".join(cleaned)

        return help_out, man_out

    help_out, man_out = await asyncio.to_thread(_capture_help_and_man, name)

    # Keep captured docs bounded.
    def _truncate(text: str, *, max_lines: int, max_chars: int) -> str:
        if not text:
            return ""
        lines = text.splitlines()[:max_lines]
        clipped = "\n".join(lines).strip()
        if len(clipped) > max_chars:
            clipped = clipped[: max_chars - 1].rstrip() + "…"
        return clipped

    help_out = _truncate(help_out, max_lines=220, max_chars=14000)
    man_out = _truncate(man_out, max_lines=260, max_chars=18000)

    def _chunk(text: str, size: int = 1800) -> list[str]:
        t = (text or "").strip()
        if not t:
            return []
        out: list[str] = []
        while t:
            out.append(t[:size])
            t = t[size:]
        return out

    # Cache into DB for future retrieval.
    def _cache(kind: str, content: str, source: str) -> None:
        import sqlite3
        from datetime import datetime

        chunks = _chunk(content)
        if not chunks:
            return
        conn = get_connection()
        try:
            ts = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            for idx, chunk in enumerate(chunks):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO kali_tool_docs (tool, kind, chunk_index, content, source, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, kind, idx, chunk, source, ts),
                )
            conn.commit()
        except sqlite3.OperationalError:
            # Best-effort: ignore caching if schema is missing.
            pass
        finally:
            conn.close()

    if help_out:
        await asyncio.to_thread(_cache, "help", help_out, f"{name} --help")
    if man_out:
        await asyncio.to_thread(_cache, "man", man_out, f"man {name}")

    # Compose response
    out_lines = [f"Tool: {name}"]
    if summary:
        out_lines.append(f"Summary: {summary}")
    out_lines.append("")
    if help_out:
        out_lines.append("[HELP]")
        out_lines.append(help_out[:max_n])
        out_lines.append("")
    if man_out and (not help_out or len("\n".join(out_lines)) < max_n):
        out_lines.append("[MAN]")
        remaining = max_n - sum(len(line) + 1 for line in out_lines)
        chunk = man_out
        if len(chunk) > remaining:
            chunk = chunk[: max(0, remaining - 1)].rstrip() + "…"
        out_lines.append(chunk)
        out_lines.append("")

    joined = "\n".join(out_lines).strip()
    if joined == f"Tool: {name}":
        return f"No help/man text found for '{name}'."
    return joined


@register_tool("msf_search")
async def msf_search(query: str, module_type: str | None = None) -> str:
    """Search Metasploit modules.

    By default, searches across all module types. You can optionally pass
    module_type (exploit, auxiliary, post, payload) to filter results.

    Prefers msfrpcd (fast, structured). Falls back to searchsploit if RPC is unavailable.

    Note: searchsploit fallback is exploit-focused.
    """
    query = (query or "").strip()
    module_type = (module_type or "").strip() or None
    if not query:
        return "Error: empty query"

    try:
        from sploitgpt.core.boot import get_shared_msf_client

        msf = await get_shared_msf_client()
        if await _connect_msf_with_retry(msf):
            modules = await msf.search_modules(query, module_type=module_type)
            if not modules:
                mt = f" ({module_type})" if module_type else ""
                return f"No Metasploit modules found for '{query}'{mt}."

            mt = f" ({module_type})" if module_type else ""
            lines: list[str] = [f"Found {len(modules)} Metasploit modules for '{query}'{mt}:", ""]
            for i, m in enumerate(modules[:25], 1):
                lines.append(f"{i}. [{m.rank}] {m.name} — {m.description}")
            if len(modules) > 25:
                lines.append("")
                lines.append(f"...and {len(modules) - 25} more")
            return "\n".join(lines)
    except Exception as e:
        # Ignore MSF failure and fall back to searchsploit
        logger.debug(f"MSF search failed, using searchsploit fallback: {e}")

    # Fallback: exploit-db search
    import shlex

    return await terminal(f"searchsploit {shlex.quote(query)}")


@register_tool("msf_info")
async def msf_info(module: str) -> str:
    """Get module info and required options from Metasploit via msfrpcd."""

    module = (module or "").strip()
    if not module or "/" not in module:
        return "Error: provide a full module path like 'auxiliary/scanner/portscan/tcp'"

    module_type, module_name = module.split("/", 1)

    try:
        from sploitgpt.core.boot import get_shared_msf_client

        msf = await get_shared_msf_client()
        if not await _connect_msf_with_retry(msf):
            return _msf_unavailable_error()

        info = await msf.get_module_info(module_type, module_name)
        options = await msf.get_module_options(module_type, module_name)

        # Format output
        lines: list[str] = [f"Module: {module}", ""]

        if isinstance(info, dict):
            rank = info.get("rank") or info.get("Rank")
            name = info.get("name") or info.get("Name")
            desc = info.get("description") or info.get("Description")
            refs = info.get("references") or info.get("References")

            if name:
                lines.append(f"Name: {name}")
            if rank:
                lines.append(f"Rank: {rank}")
            if desc:
                lines.append(f"Description: {str(desc)[:500]}")
            if refs and isinstance(refs, list):
                shown = [str(r) for r in refs[:10]]
                if shown:
                    lines.append(f"References: {', '.join(shown)}")

        required: list[str] = []
        common: list[str] = []
        option_rows: list[tuple[str, dict[str, Any]]] = []

        if isinstance(options, dict):
            for k, v in options.items():
                if isinstance(v, dict):
                    option_rows.append((str(k), v))

        option_rows.sort(key=lambda kv: kv[0])

        common_names = {
            "RHOSTS",
            "RHOST",
            "RPORT",
            "LHOST",
            "LPORT",
            "TARGETURI",
            "SSL",
            "VHOST",
            "USERNAME",
            "PASSWORD",
            "THREADS",
            "URI",
            "SRVHOST",
            "SRVPORT",
        }

        for name, meta in option_rows:
            if bool(meta.get("required")):
                required.append(name)
            if name.upper() in common_names:
                common.append(name)

        if required:
            lines.append("")
            lines.append("Required options:")
            for name in required:
                meta = dict(options.get(name, {})) if isinstance(options, dict) else {}
                default = meta.get("default")
                desc = meta.get("desc") or meta.get("description") or ""
                dflt = f" (default: {default})" if default not in (None, "") else ""
                lines.append(f"- {name}{dflt} — {str(desc)[:120]}")

        if common:
            lines.append("")
            lines.append("Common options present:")
            lines.append("- " + ", ".join(sorted(set(common))))

        lines.append("")
        lines.append("Tip: run via msf_run with an options dict (e.g., set RHOSTS/RPORT).")

        return "\n".join(lines).strip()

    except Exception as e:
        return f"Error: {e}"


@register_tool("msf_sessions")
async def msf_sessions() -> str:
    """List active Metasploit sessions (read-only)."""

    try:
        from sploitgpt.core.boot import get_shared_msf_client

        msf = await get_shared_msf_client()
        if not await _connect_msf_with_retry(msf):
            return _msf_unavailable_error()

        sessions = await msf.list_sessions()

        if not sessions:
            return "No active Metasploit sessions."
        lines = [f"Active sessions ({len(sessions)}):", ""]
        for s in sessions:
            lines.append(f"- #{s.id} {s.type} {s.tunnel_peer} via {s.via_exploit}")
        return "\n".join(lines)

    except Exception as e:
        return f"Error: {e}"


@register_tool("msf_meterpreter")
async def msf_meterpreter(session_id: int, command: str) -> str:
    """Run a meterpreter command on a session."""
    command = (command or "").strip()
    if not command:
        return "Error: missing command"

    try:
        session_id_int = int(session_id)
    except (TypeError, ValueError):
        return "Error: session_id must be an integer"

    try:
        import time

        from sploitgpt.core.boot import get_shared_msf_client

        msf = await get_shared_msf_client()
        if not await _connect_msf_with_retry(msf):
            return _msf_unavailable_error()

        try:
            result = await msf._call("session.meterpreter_run_single", [session_id_int, command])
            if isinstance(result, dict):
                data = result.get("data") or result.get("result")
                if data is not None:
                    return str(data).strip() or "(no output)"
            return str(result).strip() or "(no output)"
        except Exception as e:
            logger.debug(f"Meterpreter RPC failed, falling back to console: {e}")

        console_id = await msf.console_create()
        try:

            async def _read_until_idle(timeout_s: float) -> str:
                deadline = time.monotonic() + timeout_s
                idle_reads = 0
                chunks: list[str] = []

                while time.monotonic() < deadline:
                    data, busy = await msf.console_read(console_id)
                    if data:
                        chunks.append(data)
                        idle_reads = 0
                    else:
                        idle_reads += 1

                    if not busy and idle_reads >= 2:
                        break

                    await asyncio.sleep(0.5)

                output = "".join(chunks).strip()
                if output:
                    output = re.sub("\x1b\\[[0-9;]*m", "", output)
                return output

            await msf.console_write(console_id, f"sessions -i {session_id_int}")
            await _read_until_idle(10)
            await msf.console_write(console_id, command)
            output = await _read_until_idle(30)
            return output if output else "(no output)"
        finally:
            try:
                await msf.console_destroy(console_id)
            except Exception as e:
                logger.debug(f"Console cleanup failed: {e}")

    except Exception as e:
        return f"Error: {e}"


def _quote_msf_value(value: Any) -> str:
    """Quote values for msfconsole set commands."""
    s = str(value).replace("\\", "\\\\").replace('"', '\\"')
    if " " in s or ";" in s:
        return f'"{s}"'
    return s


@register_tool("msf_run")
async def msf_run(
    module: str,
    options: dict[str, Any],
    target: str | None = None,
    lhost: str | None = None,
) -> str:
    """Run a Metasploit module.

    Prefers msfrpcd console (avoids msfconsole startup cost and returns output).
    Falls back to msfconsole if RPC is unavailable.
    """
    module = (module or "").strip()
    if not module:
        return "Error: missing module"

    options = options or {}

    # Best-effort autofill from agent context.
    if target and "RHOSTS" not in options:
        options["RHOSTS"] = target
    if lhost and "LHOST" not in options:
        options["LHOST"] = lhost

    # Preferred: RPC console
    try:
        import time

        from sploitgpt.core.boot import get_shared_msf_client

        msf = await get_shared_msf_client()
        connected = await _connect_msf_with_retry(msf)
        if connected:
            # Validate required options (best-effort) before starting a console.
            try:
                if "/" in module:
                    module_type, module_name = module.split("/", 1)
                    module_opts = await msf.get_module_options(module_type, module_name)
                    missing: list[str] = []
                    if isinstance(module_opts, dict):
                        for opt_name, meta in module_opts.items():
                            if not isinstance(meta, dict):
                                continue
                            required = bool(meta.get("required"))
                            default = meta.get("default")
                            if not required:
                                continue
                            # If a required option has a default value, MSF can use it.
                            has_default = default not in (None, "")
                            if has_default:
                                continue
                            val = options.get(str(opt_name))
                            if val is None or str(val).strip() == "":
                                missing.append(str(opt_name))

                    if missing:
                        missing_str = ", ".join(sorted(set(missing)))
                        return (
                            "Error: missing required Metasploit module option(s): "
                            f"{missing_str}.\n"
                            "Tip: use msf_info to inspect required options and defaults."
                        )
            except Exception as e:
                # Never block on introspection.
                logger.debug(f"Module introspection failed: {e}")

            console_id = await msf.console_create()
            try:
                # Drain initial banner/prompt output so results are concise.
                try:
                    for _ in range(4):
                        _data, _busy = await msf.console_read(console_id)
                        if not _busy:
                            break
                        await asyncio.sleep(0.2)
                except Exception as e:
                    logger.debug(f"Console banner drain failed: {e}")

                await msf.console_write(console_id, f"use {module}")
                for k, v in options.items():
                    await msf.console_write(console_id, f"set {k} {_quote_msf_value(v)}")
                await msf.console_write(console_id, "run")

                out_chunks: list[str] = []
                deadline = time.monotonic() + 600
                idle_reads = 0

                while time.monotonic() < deadline:
                    data, busy = await msf.console_read(console_id)
                    if data:
                        out_chunks.append(data)
                        idle_reads = 0
                    else:
                        idle_reads += 1

                    # Consider the run complete once the console is not busy and we've
                    # observed a little idle time.
                    if not busy and idle_reads >= 4:
                        break

                    await asyncio.sleep(0.5)

                output = "".join(out_chunks).strip()

                # msfrpcd console output includes ANSI color codes; strip for stable UX/logs.
                if output:
                    import re

                    output = re.sub("\x1b\\[[0-9;]*m", "", output)

                return output if output else "(no output)"
            finally:
                try:
                    await msf.console_destroy(console_id)
                except Exception as e:
                    logger.debug(f"Console cleanup failed: {e}")
    except Exception as e:
        # Ignore MSF failure and fall back to msfconsole
        logger.debug(f"MSF RPC run failed, using msfconsole fallback: {e}")

    # Fallback: run via msfconsole (slower)
    import shlex

    quoted_module = shlex.quote(module)
    opts = " ".join(
        [f"set {shlex.quote(str(k))} {shlex.quote(str(v))};" for k, v in (options or {}).items()]
    )
    cmd = f"msfconsole -q -x 'use {quoted_module}; {opts} run; exit'"
    return await terminal(cmd, timeout=600)


@register_tool("nmap_scan")
async def nmap_scan(target: str, ports: str = "-", options: str = "-sV") -> str:
    """Run an nmap scan."""
    import re

    from sploitgpt.core.config import get_settings

    loot_dir = get_settings().loot_dir
    loot_dir.mkdir(parents=True, exist_ok=True)
    # Limit target/ports to safe characters; options are split, not shelled.
    safe_target = re.sub(r"[^A-Za-z0-9_.:-]+", "_", target).strip("_") or "target"
    if ports.strip() != "-" and not re.fullmatch(r"[0-9,\-]+", ports.strip()):
        return "Error: invalid ports format; use digits, comma, dash, or '-'"
    try:
        option_args = shlex.split(options)
    except ValueError as e:
        return f"Error parsing options: {e}"

    output_base = str((loot_dir / f"nmap_{safe_target}").resolve())
    argv: list[str] = ["nmap", *option_args, "-p", ports, target, "-oA", output_base]
    return await terminal(args=argv, timeout=600)


def _register_builtin_tools() -> None:
    """Import tool modules for side effects (registers them via decorator)."""

    for mod in (
        "sploitgpt.tools.cve",
        "sploitgpt.tools.intel",
        "sploitgpt.tools.nuclei",
        "sploitgpt.tools.payloads",
        "sploitgpt.tools.shodan",
        "sploitgpt.tools.psudohash",
    ):
        importlib.import_module(mod)


_register_builtin_tools()
