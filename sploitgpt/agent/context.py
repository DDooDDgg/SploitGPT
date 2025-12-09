"""
SploitGPT Context Builder

Builds rich context for the agent using:
- MITRE ATT&CK techniques
- GTFOBins for privilege escalation
- Atomic Red Team for test procedures
- Command templates for common tasks
- Wordlist suggestions
- Payload generation
"""

from typing import Optional, Any

from sploitgpt.knowledge import (
    search_techniques,
    get_techniques_for_service,
)
from sploitgpt.knowledge.gtfobins import (
    find_suid_escalation,
    find_sudo_escalation,
    find_reverse_shell,
)
from sploitgpt.knowledge.atomic import (
    get_tool_commands,
    format_commands_for_agent as format_atomic_commands,
)
from sploitgpt.tools.commands import (
    get_command,
    search_commands,
    format_commands_for_agent,
)
from sploitgpt.tools.wordlists import (
    get_wordlists_for_task,
    format_wordlist_suggestions,
)
from sploitgpt.tools.payloads import (
    generate_reverse_shells,
    format_reverse_shells_for_agent,
)


class ContextBuilder:
    """Builds context for the agent based on the current situation."""
    
    def __init__(self):
        self.discovered_services: list[str] = []
        self.discovered_hosts: list[str] = []
        self.current_phase: str = "recon"
        self.lhost: str = ""
        self.lport: int = 4444
        self.target: str = ""
    
    def set_target(self, target: str) -> None:
        """Set the current target."""
        self.target = target
    
    def set_lhost(self, lhost: str) -> None:
        """Set the attacker's IP."""
        self.lhost = lhost
    
    def add_discovered_service(self, service: str) -> None:
        """Track a discovered service."""
        if service.lower() not in self.discovered_services:
            self.discovered_services.append(service.lower())
    
    def add_discovered_host(self, host: str) -> None:
        """Track a discovered host."""
        if host not in self.discovered_hosts:
            self.discovered_hosts.append(host)
    
    def get_attack_context(self) -> str:
        """Get MITRE ATT&CK techniques relevant to discovered services."""
        if not self.discovered_services:
            return ""
        
        context_parts = ["## Relevant MITRE ATT&CK Techniques\n"]
        
        for service in self.discovered_services[:5]:  # Limit to avoid huge context
            techniques = get_techniques_for_service(service)
            if techniques:
                context_parts.append(f"\n### {service.upper()}")
                for tech in techniques[:3]:
                    context_parts.append(f"- **{tech['id']}** {tech['name']}")
                    if tech.get('description'):
                        desc = tech['description'][:150]
                        context_parts.append(f"  {desc}...")
        
        return "\n".join(context_parts)
    
    def get_phase_commands(self) -> str:
        """Get relevant commands for the current phase."""
        phase_to_category = {
            "recon": "recon",
            "enumeration": "enum",
            "vulnerability": "web",
            "exploitation": "exploit",
            "post": "privesc",
            "persistence": "persist",
        }
        
        category = phase_to_category.get(self.current_phase, "recon")
        return format_commands_for_agent(category)
    
    def get_wordlist_suggestions(self) -> str:
        """Get wordlist suggestions for the current phase."""
        phase_to_task = {
            "recon": "dns",
            "enumeration": "web",
            "vulnerability": "web",
            "exploitation": "web",
            "post": "passwords",
        }
        
        task = phase_to_task.get(self.current_phase, "web")
        return format_wordlist_suggestions(task)
    
    def get_privesc_context(self, binaries: list[str]) -> str:
        """Get privilege escalation techniques for discovered SUID/sudo binaries."""
        if not binaries:
            return ""
        
        context_parts = ["## Privilege Escalation Opportunities\n"]
        
        for binary in binaries[:10]:  # Limit
            # Check SUID
            suid_tech = find_suid_escalation(binary)
            if suid_tech:
                context_parts.append(f"### SUID: {binary}")
                context_parts.append(f"```bash\n{suid_tech['command']}\n```")
            
            # Check sudo
            sudo_tech = find_sudo_escalation(binary)
            if sudo_tech:
                context_parts.append(f"### Sudo: {binary}")
                context_parts.append(f"```bash\n{sudo_tech['command']}\n```")
        
        return "\n".join(context_parts)
    
    def get_reverse_shell_context(self) -> str:
        """Get reverse shell payloads."""
        if not self.lhost:
            return ""
        
        return format_reverse_shells_for_agent(self.lhost, self.lport)
    
    def get_atomic_context(self, technique_id: str) -> str:
        """Get Atomic Red Team tests for a technique."""
        tests = get_tool_commands(technique_id)
        if not tests:
            return ""
        
        return format_atomic_commands(tests)
    
    def build_full_context(self) -> str:
        """Build full context for the current situation."""
        parts = []
        
        # Attack techniques for discovered services
        attack_ctx = self.get_attack_context()
        if attack_ctx:
            parts.append(attack_ctx)
        
        # Phase-appropriate commands
        cmd_ctx = self.get_phase_commands()
        if cmd_ctx:
            parts.append(cmd_ctx)
        
        # Wordlist suggestions
        wl_ctx = self.get_wordlist_suggestions()
        if wl_ctx:
            parts.append(wl_ctx)
        
        return "\n\n".join(parts)


# Singleton for easy access
_context_builder: Optional[ContextBuilder] = None


def get_context_builder() -> ContextBuilder:
    """Get the global context builder."""
    global _context_builder
    if _context_builder is None:
        _context_builder = ContextBuilder()
    return _context_builder


def build_dynamic_context(
    target: Optional[str] = None,
    services: Optional[list[str]] = None,
    phase: str = "recon",
    lhost: Optional[str] = None,
    binaries: Optional[list[str]] = None,
) -> str:
    """
    Build dynamic context based on current pentest state.
    
    Args:
        target: The target IP or hostname
        services: Discovered services (ssh, http, smb, etc.)
        phase: Current pentest phase
        lhost: Attacker IP for reverse shells
        binaries: SUID/sudo binaries found for privesc
    
    Returns:
        Formatted context string to append to system prompt
    """
    builder = get_context_builder()
    
    if target:
        builder.set_target(target)
    if lhost:
        builder.set_lhost(lhost)
    if services:
        for svc in services:
            builder.add_discovered_service(svc)
    
    builder.current_phase = phase
    
    parts = [builder.build_full_context()]
    
    # Add privesc context if we have binaries
    if binaries:
        privesc = builder.get_privesc_context(binaries)
        if privesc:
            parts.append(privesc)
    
    # Add reverse shells if we have lhost
    if lhost:
        shells = builder.get_reverse_shell_context()
        if shells:
            parts.append(shells)
    
    return "\n\n---\n\n".join(filter(None, parts))


def parse_service_from_nmap(nmap_output: str) -> list[str]:
    """Parse services from nmap output."""
    services = []
    
    # Common service patterns
    service_patterns = [
        "ssh", "http", "https", "ftp", "smb", "rdp", "telnet",
        "mysql", "mssql", "postgresql", "oracle", "mongodb",
        "dns", "smtp", "pop3", "imap", "ldap", "snmp",
        "vnc", "nfs", "rpc", "kerberos",
    ]
    
    output_lower = nmap_output.lower()
    
    for svc in service_patterns:
        if svc in output_lower:
            services.append(svc)
    
    return services


def parse_suid_binaries(find_output: str) -> list[str]:
    """Parse SUID binaries from 'find' output."""
    binaries = []
    
    for line in find_output.strip().split("\n"):
        line = line.strip()
        if line and "/" in line:
            # Extract binary name from path
            binary = line.split("/")[-1]
            if binary:
                binaries.append(binary)
    
    return binaries
