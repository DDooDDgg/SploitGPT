"""
SploitGPT Tools Module
"""

import asyncio
from typing import Any

# Tool registry
TOOLS: dict[str, callable] = {}


def register_tool(name: str):
    """Decorator to register a tool."""
    def decorator(func):
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
    except Exception as e:
        return f"Error executing {name}: {e}"


@register_tool("terminal")
async def terminal(command: str, timeout: int = 300) -> str:
    """Execute a shell command."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout
            )
            return stdout.decode() if stdout else "(no output)"
        except asyncio.TimeoutError:
            proc.kill()
            return f"Command timed out after {timeout}s"
            
    except Exception as e:
        return f"Error: {e}"


@register_tool("msf_search")
async def msf_search(query: str) -> str:
    """Search for Metasploit modules using searchsploit."""
    return await terminal(f"searchsploit {query}")


@register_tool("msf_run")
async def msf_run(module: str, options: dict[str, str]) -> str:
    """Run a Metasploit module."""
    # Build msfconsole command
    opts = " ".join([f"set {k} {v};" for k, v in options.items()])
    cmd = f"msfconsole -q -x 'use {module}; {opts} run; exit'"
    return await terminal(cmd, timeout=600)


@register_tool("nmap_scan")
async def nmap_scan(target: str, ports: str = "-", options: str = "-sV") -> str:
    """Run an nmap scan."""
    output_base = f"/app/loot/nmap_{target.replace('/', '_').replace('.', '_')}"
    cmd = f"nmap {options} -p {ports} {target} -oA {output_base}"
    return await terminal(cmd, timeout=600)


# Import submodules
from .wordlists import (
    get_wordlist,
    get_wordlists_for_task,
    suggest_wordlist,
    format_wordlist_suggestions,
)
from .payloads import (
    generate_reverse_shells,
    format_reverse_shells_for_agent,
    php_web_shell,
    jsp_web_shell,
)
from .commands import (
    get_command,
    search_commands,
    format_commands_for_agent,
    ALL_COMMANDS,
)

# Import new tools (registers them via decorator)
from . import intel
from . import cve
from . import shodan
