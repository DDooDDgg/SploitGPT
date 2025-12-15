"""
Atomic Red Team Integration

Parses Atomic Red Team tests to get executable commands for each technique.
"""


from typing import Any

import httpx
import yaml  # type: ignore[import-untyped]

# Atomic Red Team repository
ATOMIC_REPO_URL = "https://github.com/redcanaryco/atomic-red-team.git"
ATOMIC_ATOMICS_URL = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{technique_id}/{technique_id}.yaml"


async def download_atomic_test(technique_id: str) -> dict[str, Any] | None:
    """Download atomic test for a specific technique."""
    url = ATOMIC_ATOMICS_URL.format(technique_id=technique_id)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=30)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            
            loaded = yaml.safe_load(response.text)
            return loaded if isinstance(loaded, dict) else None
    except Exception:
        return None


def parse_atomic_tests(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse atomic test YAML into command structures."""
    if not data:
        return []
    
    tests: list[dict[str, Any]] = []
    
    for test in data.get("atomic_tests", []):
        # Filter for Linux-compatible tests
        platforms = test.get("supported_platforms", [])
        if not any(p in ["linux", "macos"] for p in platforms):
            continue
        
        executor = test.get("executor", {})
        command = executor.get("command", "")
        
        if not command:
            continue
        
        # Get input arguments with defaults
        input_args = test.get("input_arguments", {})
        defaults = {}
        for arg_name, arg_info in input_args.items():
            defaults[arg_name] = arg_info.get("default", f"${{{arg_name}}}")
        
        # Substitute defaults into command
        for arg_name, default_val in defaults.items():
            command = command.replace(f"#{{{arg_name}}}", str(default_val))
        
        tests.append({
            "name": test.get("name", ""),
            "description": test.get("description", ""),
            "platforms": platforms,
            "executor": executor.get("name", "sh"),
            "command": command,
            "cleanup": executor.get("cleanup_command", ""),
            "elevation_required": executor.get("elevation_required", False),
        })
    
    return tests


async def get_commands_for_technique(technique_id: str) -> list[dict[str, Any]]:
    """Get executable commands for a MITRE ATT&CK technique."""
    # Normalize technique ID (T1046 -> T1046, T1021.001 -> T1021.001)
    technique_id = technique_id.upper()
    
    data = await download_atomic_test(technique_id)
    if not data:
        return []
    
    return parse_atomic_tests(data)


def format_commands_for_agent(tests: list[dict[str, Any]], target: str = "") -> str:
    """Format atomic tests as readable options for the agent."""
    if not tests:
        return "No pre-built commands available for this technique."
    
    lines = []
    for i, test in enumerate(tests, 1):
        command = test["command"]
        
        # Substitute common variables
        if target:
            command = command.replace("${target}", target)
            command = command.replace("$target", target)
        
        lines.append(f"**Option {i}: {test['name']}**")
        lines.append(f"  {test['description'][:100]}...")
        lines.append("  ```")
        lines.append(f"  {command[:200]}{'...' if len(command) > 200 else ''}")
        lines.append("  ```")
        if test["elevation_required"]:
            lines.append("  ⚠️ Requires root/sudo")
        lines.append("")
    
    return "\n".join(lines)


# Common technique to tool mapping (for when Atomic doesn't have tests)
TECHNIQUE_TOOLS = {
    "T1046": [  # Network Service Discovery
        {"tool": "nmap", "command": "nmap -sV -sC {target}", "description": "Service/version detection with scripts"},
        {"tool": "masscan", "command": "masscan -p1-65535 {target} --rate=1000", "description": "Fast port scan"},
        {"tool": "rustscan", "command": "rustscan -a {target} -- -sV", "description": "Fast scan with nmap follow-up"},
    ],
    "T1190": [  # Exploit Public-Facing Application
        {"tool": "nuclei", "command": "nuclei -u http://{target}", "description": "Vulnerability scanner"},
        {"tool": "nikto", "command": "nikto -h http://{target}", "description": "Web server scanner"},
        {"tool": "sqlmap", "command": "sqlmap -u 'http://{target}/' --forms --batch", "description": "SQL injection testing"},
    ],
    "T1110": [  # Brute Force
        {"tool": "hydra", "command": "hydra -L users.txt -P passwords.txt {target} ssh", "description": "SSH brute force"},
        {"tool": "crackmapexec", "command": "crackmapexec smb {target} -u users.txt -p passwords.txt", "description": "SMB brute force"},
    ],
    "T1021.002": [  # SMB/Windows Admin Shares
        {"tool": "smbclient", "command": "smbclient -L //{target}/ -N", "description": "List SMB shares (null session)"},
        {"tool": "enum4linux", "command": "enum4linux -a {target}", "description": "Full SMB enumeration"},
        {"tool": "crackmapexec", "command": "crackmapexec smb {target} --shares", "description": "Enumerate shares"},
    ],
    "T1087": [  # Account Discovery
        {"tool": "enum4linux", "command": "enum4linux -U {target}", "description": "Enumerate users via SMB"},
        {"tool": "ldapsearch", "command": "ldapsearch -x -h {target} -b 'dc=domain,dc=com'", "description": "LDAP user enumeration"},
    ],
}


def get_tool_commands(technique_id: str, target: str = "{target}") -> list[dict[str, str]]:
    """Get Kali tool commands for a technique."""
    technique_id = technique_id.upper()
    
    # Handle sub-techniques (T1021.002 -> check T1021.002, then T1021)
    commands = TECHNIQUE_TOOLS.get(technique_id, [])
    if not commands and "." in technique_id:
        parent_id = technique_id.split(".")[0]
        commands = TECHNIQUE_TOOLS.get(parent_id, [])
    
    # Substitute target
    result: list[dict[str, str]] = []
    for cmd in commands:
        result.append({
            **cmd,
            "command": cmd["command"].format(target=target)
        })
    
    return result
