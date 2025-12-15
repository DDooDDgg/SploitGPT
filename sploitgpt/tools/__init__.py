"""SploitGPT Tools Module."""

import asyncio
import importlib
import logging
import os
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
    if name not in TOOLS:
        return f"Error: Unknown tool '{name}'"
    
    try:
        result = await TOOLS[name](**args)
        return result
    except Exception as e:  # pragma: no cover - defensive logging
        logger.exception("Error executing tool %s", name)
        return f"Error executing {name}: {e}"


@register_tool("terminal")
async def terminal(
    command: str | list[str] | None,
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

        When running inside Docker as root, tools like nmap write to /app/loot and
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
        except asyncio.TimeoutError:
            proc.kill()
            try:
                # Ensure the process is fully reaped to avoid resource warnings.
                await proc.wait()
            except Exception:
                pass
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
        from sploitgpt.msf import get_msf_client

        msf = get_msf_client()
        if await msf.connect():
            try:
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
            finally:
                await msf.disconnect()
    except Exception:
        # Ignore and fall back
        pass

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
        from sploitgpt.msf import get_msf_client

        msf = get_msf_client()
        if not await msf.connect():
            return "Error: could not connect/authenticate to msfrpcd"

        try:
            info = await msf.get_module_info(module_type, module_name)
            options = await msf.get_module_options(module_type, module_name)
        finally:
            await msf.disconnect()

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
        lines.append("Tip: run via msf_module with an options dict (e.g., set RHOSTS/RPORT).")

        return "\n".join(lines).strip()

    except Exception as e:
        return f"Error: {e}"


@register_tool("msf_sessions")
async def msf_sessions() -> str:
    """List active Metasploit sessions (read-only)."""

    try:
        from sploitgpt.msf import get_msf_client

        msf = get_msf_client()
        if not await msf.connect():
            return "Error: could not connect/authenticate to msfrpcd"

        try:
            sessions = await msf.list_sessions()
        finally:
            await msf.disconnect()

        if not sessions:
            return "No active Metasploit sessions."
        lines = [f"Active sessions ({len(sessions)}):", ""]
        for s in sessions:
            lines.append(f"- #{s.id} {s.type} {s.tunnel_peer} via {s.via_exploit}")
        return "\n".join(lines)

    except Exception as e:
        return f"Error: {e}"


@register_tool("cloud_gpu_status")
async def cloud_gpu_status(ssh_host: str, ssh_user: str = "root", ssh_port: int = 22, ssh_key_path: str | None = None) -> str:
    """Check connectivity to a cloud GPU host.

    Returns a short string status. This is a read-only operation and does not change remote state.
    """
    try:
        from sploitgpt.tools.cloud_gpu import CloudGPU

        client = CloudGPU(ssh_user=ssh_user, ssh_host=ssh_host, ssh_port=ssh_port, ssh_key_path=ssh_key_path)
        ok = await __run_in_thread(lambda: client.verify_connectivity())
        return "OK: reachable" if ok else "Error: not reachable or auth failed"
    except Exception as e:
        return f"Error: {e}"


@register_tool("cloud_gpu_sync")
async def cloud_gpu_sync(
    ssh_host: str,
    ssh_user: str = "root",
    local_dir: str | None = None,
    ssh_port: int = 22,
    ssh_key_path: str | None = None,
    dry_run: bool = False,
    consent: bool = False,
) -> str:
    """Sync local wordlists to remote GPU host.

    This operation requires explicit `consent=True` to proceed. If `dry_run=True`, the
    actions will be planned and shown but not executed.
    """
    if not consent:
        return "Error: operation requires explicit consent (set consent=True)"

    try:
        from sploitgpt.tools.cloud_gpu import CloudGPU
        from sploitgpt.core.config import get_settings

        settings = get_settings()
        local_dir = local_dir or str(settings.data_dir / "wordlists")

        client = CloudGPU(
            ssh_user=ssh_user,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_key_path=ssh_key_path,
            dry_run=dry_run,
        )

        ok = await __run_in_thread(lambda: client.sync_wordlists(local_dir))
        return "OK: synced" if ok else "Error: sync failed"
    except Exception as e:
        return f"Error: {e}"


async def __run_in_thread(func):
    """Run blocking function in a thread and return result."""
    import asyncio

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func)


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

        from sploitgpt.msf import get_msf_client

        msf = get_msf_client()
        connected = await msf.connect()
        try:
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
                except Exception:
                    # Never block on introspection.
                    pass

                console_id = await msf.console_create()
                try:
                    # Drain initial banner/prompt output so results are concise.
                    try:
                        for _ in range(4):
                            _data, _busy = await msf.console_read(console_id)
                            if not _busy:
                                break
                            await asyncio.sleep(0.2)
                    except Exception:
                        pass

                    await msf.console_write(console_id, f"use {module}")
                    for k, v in options.items():
                        await msf.console_write(console_id, f"set {k} {v}")
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
                    except Exception:
                        pass
        finally:
            await msf.disconnect()
    except Exception:
        # Ignore and fall back
        pass

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
    from sploitgpt.core.config import get_settings

    import re

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
        "sploitgpt.tools.shodan",
    ):
        importlib.import_module(mod)


_register_builtin_tools()
