"""
SploitGPT Boot Sequence

Initializes the agent with:
1. Environment enumeration
2. Tool availability check
3. Prior loot parsing
4. Session state loading
5. LLM connection verification
"""

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from sploitgpt.core.config import get_settings
from sploitgpt.core.ollama import OllamaClient, test_ollama_connection

console = Console()
logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sploitgpt.msf import MetasploitRPC

_msf_client: "MetasploitRPC | None" = None
_msf_client_lock = asyncio.Lock()


class LootFindings(TypedDict):
    hosts: list[str]
    ports: dict[str, list[int]]
    services: list[str]
    vulns: list[str]


def _empty_findings() -> LootFindings:
    return {
        "hosts": [],
        "ports": {},
        "services": [],
        "vulns": [],
    }


def _is_kali() -> bool:
    """Detect Kali Linux to avoid noisy tool warnings in the default image."""
    try:
        data = Path("/etc/os-release").read_text()
        return "ID=kali" in data or "ID_LIKE=kali" in data
    except Exception:
        return False


def _is_loopback_host(host: str) -> bool:
    """Check if a host string refers to loopback."""
    return host in ("127.0.0.1", "localhost", "::1")


async def get_shared_msf_client() -> "MetasploitRPC | None":
    """Return a shared Metasploit RPC client instance, or None if connection fails."""
    global _msf_client

    async with _msf_client_lock:
        if _msf_client is None:
            from sploitgpt.msf import get_msf_client

            client = get_msf_client()
            connected = False
            for attempt in range(3):
                if await client.connect():
                    connected = True
                    break
                if attempt < 2:
                    await asyncio.sleep(1)

            if connected:
                _msf_client = client
            else:
                # Don't cache failed client - allow retry on next call
                logger.warning("Failed to connect to Metasploit RPC after 3 attempts")
                return None

    return _msf_client


@dataclass
class BootContext:
    """Context gathered during boot sequence."""

    # Environment
    hostname: str = ""
    username: str = ""
    interfaces: list[dict[str, str]] = field(default_factory=list)

    # Tools
    available_tools: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)

    # Prior work
    known_hosts: list[str] = field(default_factory=list)
    open_ports: dict[str, list[int]] = field(default_factory=dict)
    findings: LootFindings = field(default_factory=_empty_findings)

    # State
    msf_connected: bool = False
    ollama_connected: bool = False
    model_loaded: bool = False

    # Session
    session_count: int = 0


async def _run_cmd(cmd: list[str]) -> str:
    """Run a command asynchronously and return stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip()
    except Exception:
        return ""


async def enumerate_environment() -> dict[str, Any]:
    """Gather information about the current environment."""
    env: dict[str, Any] = {}

    # Run commands concurrently
    hostname_task = _run_cmd(["hostname"])
    username_task = _run_cmd(["whoami"])
    interfaces_task = _run_cmd(["ip", "-br", "addr"])

    hostname, username, interfaces_output = await asyncio.gather(
        hostname_task, username_task, interfaces_task
    )

    env["hostname"] = hostname
    env["username"] = username

    # Parse network interfaces
    interfaces = []
    for line in interfaces_output.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            interfaces.append(
                {"name": parts[0], "state": parts[1], "addr": parts[2] if len(parts) > 2 else ""}
            )
    env["interfaces"] = interfaces

    return env


async def check_tools() -> tuple[list[str], list[str]]:
    """Check which essential security tools are available.

    Note: Kali has 600+ tools installed. This only verifies the core tools
    that SploitGPT uses most frequently are present and working.
    """
    if _is_kali():
        # Trust the base Kali image and skip noisy checks to keep boot fast.
        essential_tools = [
            "nmap",
            "masscan",
            "msfconsole",
            "searchsploit",
            "sqlmap",
            "gobuster",
            "nikto",
            "nuclei",
            "hydra",
            "john",
            "smbclient",
            "enum4linux",
            "crackmapexec",
            "netcat",
            "curl",
            "wget",
        ]
        return essential_tools, []

    # Core tools that SploitGPT relies on heavily
    essential_tools = [
        # Reconnaissance
        "nmap",
        "masscan",
        # Exploitation
        "msfconsole",
        "searchsploit",
        # Web
        "sqlmap",
        "gobuster",
        "nikto",
        "nuclei",
        # Credentials
        "hydra",
        "john",
        # SMB/Network
        "smbclient",
        "enum4linux",
        "crackmapexec",
        # Utilities
        "netcat",
        "curl",
        "wget",
    ]

    async def check_tool(tool: str) -> tuple[str, bool]:
        """Check if a tool is available."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "which",
                tool,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            returncode = await proc.wait()
            return tool, returncode == 0
        except Exception:
            return tool, False

    # Check all tools concurrently
    results = await asyncio.gather(*[check_tool(t) for t in essential_tools])

    available = [tool for tool, found in results if found]
    missing = [tool for tool, found in results if not found]

    return available, missing


async def parse_loot_directory(loot_dir: Path) -> LootFindings:
    """Parse prior reconnaissance data from loot directory."""
    findings: LootFindings = _empty_findings()

    if not loot_dir.exists():
        return findings

    # Parse .gnmap files for quick host/port extraction
    for gnmap_file in loot_dir.glob("*.gnmap"):
        try:
            content = gnmap_file.read_text()
            for line in content.split("\n"):
                if "Host:" in line and "Ports:" in line:
                    # Extract host
                    host_match = line.split("Host:")[1].split()[0]
                    if host_match and host_match not in findings["hosts"]:
                        findings["hosts"].append(host_match)

                    # Extract ports
                    if "Ports:" in line:
                        ports_section = line.split("Ports:")[1]
                        ports = []
                        for port_info in ports_section.split(","):
                            port_info = port_info.strip()
                            if "/" in port_info:
                                port_num = port_info.split("/")[0]
                                if port_num.isdigit():
                                    ports.append(int(port_num))
                        if host_match and ports:
                            findings["ports"][host_match] = ports
        except Exception:
            logger.debug("Failed to parse %s", gnmap_file, exc_info=True)

    return findings


def _try_open_msf_viewer(settings) -> None:
    """Attempt to open MSF viewer terminal (fails silently if unavailable)."""
    if not getattr(settings, "msf_viewer_enabled", False):
        return

    try:
        from sploitgpt.msf.viewer import open_msf_viewer

        open_msf_viewer()
    except ImportError:
        # viewer.py not present (feature removed)
        pass
    except Exception as e:
        # Don't fail boot if viewer can't open
        logger.debug(f"Could not open MSF viewer: {e}")


async def check_msf_connection(*, retries: int = 8, delay_s: float = 0.5) -> bool:
    """Check if Metasploit RPC is available.

    We treat "available" as:
    - TCP port reachable AND
    - authentication succeeds via msfrpcd API.

    msfrpcd can take a few seconds to come up after container start, so we retry briefly.
    """
    import socket

    settings = get_settings()
    for attempt in range(1, retries + 1):
        try:
            # Use context manager to ensure socket is always closed
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                result = sock.connect_ex((settings.msf_host, settings.msf_port))
                if result != 0:
                    raise RuntimeError("msfrpcd port not reachable")

            from sploitgpt.msf import get_msf_client

            msf = get_msf_client()
            try:
                if await msf.connect():
                    # Open MSF viewer terminal if enabled
                    _try_open_msf_viewer(settings)
                    return True
            finally:
                await msf.disconnect()

        except Exception as e:
            # Log and retry
            logger.debug(f"MSF connection attempt {attempt + 1} failed: {e}")

        if attempt < retries:
            await asyncio.sleep(delay_s)

    return False


async def check_ollama_connection() -> tuple[bool, bool]:
    """Check if Ollama is available and target model is present."""
    try:
        status = await test_ollama_connection()
        connected = status.get("connected", False)
        healthy = status.get("healthy", False)
        # Fallback to a direct health_check for stronger signal if reachable but not marked healthy.
        if connected and not healthy:
            async with OllamaClient() as client:
                healthy = await client.health_check()
        return connected, healthy
    except Exception:
        logger.exception("Ollama connection check failed")
        return False, False


async def boot_sequence(quiet: bool = False) -> BootContext:
    """Run the full boot sequence and return context.

    Args:
        quiet: If True, suppress progress output (for TUI mode)
    """
    ctx = BootContext()
    settings = get_settings()
    kali_mode = _is_kali()

    # Ensure DB schema exists (including tool catalog/doc cache tables).
    try:
        from sploitgpt.db import init_db

        init_db()
    except Exception:
        logger.debug("DB init failed (continuing)", exc_info=True)

    if quiet:
        # Quiet mode for TUI - no progress spinners
        env = await enumerate_environment()
        ctx.hostname = env.get("hostname", "unknown")
        ctx.username = env.get("username", "unknown")
        ctx.interfaces = env.get("interfaces", [])

        ctx.available_tools, ctx.missing_tools = await check_tools()

        findings = await parse_loot_directory(settings.loot_dir)
        ctx.known_hosts = findings["hosts"]
        ctx.open_ports = findings["ports"]
        ctx.findings = findings

        ctx.msf_connected = await check_msf_connection()

        connected, healthy = await check_ollama_connection()
        ctx.ollama_connected = connected
        ctx.model_loaded = healthy

        return ctx

    # Normal mode with progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Step 1: Environment
        task = progress.add_task("[cyan]Enumerating environment...", total=None)
        env = await enumerate_environment()
        ctx.hostname = env.get("hostname", "unknown")
        ctx.username = env.get("username", "unknown")
        ctx.interfaces = env.get("interfaces", [])
        progress.update(task, description=f"[green]✓ Environment: {ctx.username}@{ctx.hostname}")

        # Step 2: Core tool checks
        task = progress.add_task("[cyan]Verifying core tools...", total=None)
        ctx.available_tools, ctx.missing_tools = await check_tools()
        if kali_mode:
            progress.update(
                task, description="[green]✓ Kali detected: core toolset assumed present"
            )
        elif ctx.missing_tools:
            progress.update(
                task,
                description=f"[yellow]⚠ Core checks: {len(ctx.available_tools)}/{len(ctx.available_tools) + len(ctx.missing_tools)} passed (missing: {', '.join(ctx.missing_tools[:3])})",
            )
        else:
            progress.update(
                task, description=f"[green]✓ Core checks: {len(ctx.available_tools)} passed"
            )

        # Step 3: Prior loot
        task = progress.add_task("[cyan]Parsing prior reconnaissance...", total=None)
        findings = await parse_loot_directory(settings.loot_dir)
        ctx.known_hosts = findings["hosts"]
        ctx.open_ports = findings["ports"]
        ctx.findings = findings
        progress.update(
            task, description=f"[green]✓ Prior work: {len(ctx.known_hosts)} hosts known"
        )

        # Step 4: Metasploit
        task = progress.add_task("[cyan]Connecting to Metasploit...", total=None)
        ctx.msf_connected = await check_msf_connection()
        if ctx.msf_connected:
            desc = "[green]✓ Metasploit RPC connected"
            if not _is_loopback_host(settings.msf_host):
                desc += " [yellow](host is not loopback — restrict access)[/yellow]"
            progress.update(task, description=desc)
        else:
            progress.update(task, description="[yellow]⚠ Metasploit RPC not available")

        # Step 5: Ollama/LLM
        task = progress.add_task("[cyan]Connecting to LLM...", total=None)
        connected, healthy = await check_ollama_connection()
        ctx.ollama_connected = connected
        ctx.model_loaded = healthy
        if ctx.ollama_connected and ctx.model_loaded:
            progress.update(task, description=f"[green]✓ LLM ready ({settings.effective_model})")
        elif ctx.ollama_connected:
            progress.update(
                task,
                description=f"[yellow]⚠ LLM reachable but model missing ({settings.effective_model})",
            )
        else:
            progress.update(task, description="[yellow]⚠ LLM not available - check Ollama")

    # Summary
    console.print()
    if ctx.known_hosts:
        console.print(
            f"[dim]Known targets: {', '.join(ctx.known_hosts[:5])}{'...' if len(ctx.known_hosts) > 5 else ''}[/]"
        )
    if ctx.missing_tools:
        console.print(f"[dim yellow]Missing tools: {', '.join(ctx.missing_tools[:5])}[/]")
    if not _is_loopback_host(settings.msf_host):
        console.print(
            "[bold yellow]Metasploit RPC host is not loopback; keep it LAN-local and passworded to avoid exposing msfrpcd.[/bold yellow]"
        )
    console.print()

    return ctx
