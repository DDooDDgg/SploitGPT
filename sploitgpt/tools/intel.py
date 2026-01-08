"""Target intelligence tool for SploitGPT.

Maintains structured intelligence about discovered targets, services,
vulnerabilities, and credentials throughout the engagement.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from . import register_tool


def _get_intel_file() -> Path:
    """Get intel file path lazily to avoid import-time config evaluation."""
    from sploitgpt.core.config import get_settings

    return get_settings().loot_dir / "intel.json"


@dataclass
class Service:
    """Discovered service on a port."""

    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    banner: str = ""
    vulnerabilities: list[str] = field(default_factory=list)


@dataclass
class Credential:
    """Discovered credential."""

    username: str
    password: str = ""
    hash: str = ""
    service: str = ""
    host: str = ""
    source: str = ""  # How it was found
    verified: bool = False


@dataclass
class Host:
    """Intelligence about a discovered host."""

    ip: str
    hostname: str = ""
    os: str = ""
    os_version: str = ""
    services: dict[int, Service] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)  # e.g., "domain_controller", "web_server"


@dataclass
class Intel:
    """Full intelligence store for an engagement."""

    target: str = ""
    scope: list[str] = field(default_factory=list)
    hosts: dict[str, Host] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)  # High-level findings
    attack_path: list[str] = field(default_factory=list)  # Kill chain steps taken
    updated_at: str = ""


def _load_intel() -> Intel:
    """Load intel from file."""
    intel_file = _get_intel_file()
    if intel_file.exists():
        try:
            data = json.loads(intel_file.read_text())
            if not isinstance(data, dict):
                return Intel()
            intel = Intel(
                target=data.get("target", ""),
                scope=data.get("scope", []),
                findings=data.get("findings", []),
                attack_path=data.get("attack_path", []),
                updated_at=data.get("updated_at", ""),
            )
            # Reconstruct hosts
            for ip, host_data in data.get("hosts", {}).items():
                services = {}
                for port_str, svc_data in host_data.get("services", {}).items():
                    services[int(port_str)] = Service(**svc_data)
                intel.hosts[ip] = Host(
                    ip=ip,
                    hostname=host_data.get("hostname", ""),
                    os=host_data.get("os", ""),
                    os_version=host_data.get("os_version", ""),
                    services=services,
                    notes=host_data.get("notes", []),
                    tags=host_data.get("tags", []),
                )
            # Reconstruct credentials
            for cred_data in data.get("credentials", []):
                intel.credentials.append(Credential(**cred_data))
            return intel
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
    return Intel()


def _save_intel(intel: Intel) -> None:
    """Save intel to file."""
    intel.updated_at = datetime.now().isoformat()

    # Convert to JSON-serializable format
    data: dict[str, Any] = {
        "target": intel.target,
        "scope": intel.scope,
        "findings": intel.findings,
        "attack_path": intel.attack_path,
        "updated_at": intel.updated_at,
        "hosts": {},
        "credentials": [],
    }

    for ip, host in intel.hosts.items():
        host_data: dict[str, Any] = {
            "hostname": host.hostname,
            "os": host.os,
            "os_version": host.os_version,
            "notes": host.notes,
            "tags": host.tags,
            "services": {},
        }
        services_data: dict[str, Any] = {}
        for port, svc in host.services.items():
            services_data[str(port)] = asdict(svc)
        host_data["services"] = services_data
        hosts_data = data.setdefault("hosts", {})
        if isinstance(hosts_data, dict):
            hosts_data[ip] = host_data

    creds_data = data.setdefault("credentials", [])
    if isinstance(creds_data, list):
        for cred in intel.credentials:
            creds_data.append(asdict(cred))

    intel_file = _get_intel_file()
    intel_file.parent.mkdir(parents=True, exist_ok=True)
    intel_file.write_text(json.dumps(data, indent=2))


def get_intel() -> Intel:
    """Get current intel (for TUI display)."""
    return _load_intel()


def get_intel_summary() -> str:
    """Get a formatted summary of current intel."""
    intel = _load_intel()

    if not intel.hosts and not intel.credentials:
        return "No intelligence collected yet."

    lines = ["# Target Intelligence\n"]

    if intel.target:
        lines.append(f"**Primary Target:** {intel.target}")
    if intel.scope:
        lines.append(f"**Scope:** {', '.join(intel.scope)}")
    lines.append("")

    # Host summary
    if intel.hosts:
        lines.append(f"## Hosts ({len(intel.hosts)})\n")
        for ip, host in intel.hosts.items():
            host_line = f"- **{ip}**"
            if host.hostname:
                host_line += f" ({host.hostname})"
            if host.os:
                host_line += f" - {host.os}"
            lines.append(host_line)

            if host.services:
                for port, svc in sorted(host.services.items()):
                    svc_line = f"  - :{port}/{svc.protocol}"
                    if svc.service:
                        svc_line += f" {svc.service}"
                    if svc.version:
                        svc_line += f" ({svc.version})"
                    if svc.vulnerabilities:
                        svc_line += f" ⚠️ {len(svc.vulnerabilities)} vulns"
                    lines.append(svc_line)

            if host.tags:
                lines.append(f"  Tags: {', '.join(host.tags)}")
        lines.append("")

    # Credentials
    if intel.credentials:
        lines.append(f"## Credentials ({len(intel.credentials)})\n")
        for cred in intel.credentials:
            cred_line = f"- {cred.username}"
            if cred.password:
                cred_line += f":{cred.password}"
            elif cred.hash:
                cred_line += f" (hash: {cred.hash[:16]}...)"
            if cred.service:
                cred_line += f" @ {cred.service}"
            if cred.verified:
                cred_line += " ✓"
            lines.append(cred_line)
        lines.append("")

    # Findings
    if intel.findings:
        lines.append("## Key Findings\n")
        for finding in intel.findings:
            lines.append(f"- {finding}")
        lines.append("")

    # Attack path
    if intel.attack_path:
        lines.append("## Attack Path\n")
        for i, step in enumerate(intel.attack_path, 1):
            lines.append(f"{i}. {step}")

    return "\n".join(lines)


@register_tool("intel")
async def intel(
    action: str,
    ip: str = "",
    hostname: str = "",
    os: str = "",
    port: int | None = None,
    protocol: str = "tcp",
    service: str = "",
    version: str = "",
    username: str = "",
    password: str = "",
    hash: str = "",
    finding: str = "",
    step: str = "",
    tag: str = "",
    vulnerability: str = "",
    source: str = "",
) -> str:
    """
    Manage target intelligence. Track hosts, services, credentials, and findings.

    Actions: add_host, add_service, add_credential, add_finding, add_attack_step,
    get_host, list_hosts, summary, clear.

    Args:
        action: The action to perform (add_host, add_service, add_credential, etc.)
        ip: Host IP address (for host operations)
        hostname: Hostname (for add_host)
        os: Operating system (for add_host)
        port: Port number (for add_service)
        protocol: Protocol tcp/udp (for add_service, default: tcp)
        service: Service name (for add_service, e.g., 'ssh', 'http')
        version: Service version (for add_service)
        username: Username (for add_credential)
        password: Password (for add_credential)
        hash: Password hash (for add_credential)
        finding: Finding text (for add_finding)
        step: Attack step description (for add_attack_step)
        tag: Tag to add to host (for tag_host)
        vulnerability: Vulnerability to add to service (e.g., CVE-2021-44228)
        source: How credential was found (for add_credential)

    Returns:
        Result message
    """
    intel_data = _load_intel()

    if action == "add_host":
        ip = ip.strip()
        if not ip:
            return "Error: ip is required for add_host"

        if ip not in intel_data.hosts:
            intel_data.hosts[ip] = Host(ip=ip)

        host = intel_data.hosts[ip]
        if hostname:
            host.hostname = hostname
        if os:
            host.os = os

        _save_intel(intel_data)
        return f"Added/updated host: {ip}" + (f" ({hostname})" if hostname else "")

    elif action == "add_service":
        ip = ip.strip()
        if not ip:
            return "Error: ip is required for add_service"
        if port is None:
            return "Error: port is required for add_service"

        # Auto-create host if needed
        if ip not in intel_data.hosts:
            intel_data.hosts[ip] = Host(ip=ip)

        host = intel_data.hosts[ip]

        if port not in host.services:
            host.services[port] = Service(port=port)

        svc = host.services[port]
        if protocol:
            svc.protocol = protocol
        if service:
            svc.service = service
        if version:
            svc.version = version
        if vulnerability:
            if vulnerability not in svc.vulnerabilities:
                svc.vulnerabilities.append(vulnerability)

        _save_intel(intel_data)
        return f"Added service: {ip}:{port}/{svc.protocol} {svc.service} {svc.version}".strip()

    elif action == "add_credential":
        username = username.strip()
        if not username:
            return "Error: username is required for add_credential"

        cred = Credential(
            username=username,
            password=password,
            hash=hash,
            service=service,
            host=ip,
            source=source,
        )
        intel_data.credentials.append(cred)
        _save_intel(intel_data)

        cred_str = f"{username}"
        if cred.password:
            cred_str += f":{cred.password}"
        return f"Added credential: {cred_str}"

    elif action == "add_finding":
        finding = finding.strip()
        if not finding:
            return "Error: finding is required for add_finding"

        intel_data.findings.append(finding)
        _save_intel(intel_data)
        return f"Added finding: {finding}"

    elif action == "add_attack_step":
        step = step.strip()
        if not step:
            return "Error: step is required for add_attack_step"

        intel_data.attack_path.append(step)
        _save_intel(intel_data)
        return f"Added attack step #{len(intel_data.attack_path)}: {step}"

    elif action == "tag_host":
        ip = ip.strip()
        tag = tag.strip()
        if not ip:
            return "Error: ip is required for tag_host"
        if not tag:
            return "Error: tag is required for tag_host"
        if ip not in intel_data.hosts:
            return f"Error: host {ip} not found"

        host = intel_data.hosts[ip]
        if tag not in host.tags:
            host.tags.append(tag)
            _save_intel(intel_data)
        return f"Tagged {ip} with '{tag}'"

    elif action == "get_host":
        ip = ip.strip()
        if not ip:
            return "Error: ip is required for get_host"
        if ip not in intel_data.hosts:
            return f"Host {ip} not found"

        host = intel_data.hosts[ip]
        lines = [f"Host: {ip}"]
        if host.hostname:
            lines.append(f"Hostname: {host.hostname}")
        if host.os:
            lines.append(f"OS: {host.os}")
        if host.tags:
            lines.append(f"Tags: {', '.join(host.tags)}")
        if host.services:
            lines.append("Services:")
            for prt, svc in sorted(host.services.items()):
                svc_line = f"  {prt}/{svc.protocol}: {svc.service}"
                if svc.version:
                    svc_line += f" ({svc.version})"
                lines.append(svc_line)
                if svc.vulnerabilities:
                    lines.append(f"    Vulns: {', '.join(svc.vulnerabilities)}")
        if host.notes:
            lines.append("Notes:")
            for note in host.notes:
                lines.append(f"  - {note}")

        return "\n".join(lines)

    elif action == "list_hosts":
        if not intel_data.hosts:
            return "No hosts discovered"

        lines = [f"Discovered hosts ({len(intel_data.hosts)}):"]
        for ip_addr, host in intel_data.hosts.items():
            host_line = f"  {ip_addr}"
            if host.hostname:
                host_line += f" ({host.hostname})"
            port_count = len(host.services)
            if port_count:
                host_line += f" - {port_count} open ports"
            lines.append(host_line)

        return "\n".join(lines)

    elif action == "list_credentials":
        if not intel_data.credentials:
            return "No credentials found"

        lines = [f"Credentials ({len(intel_data.credentials)}):"]
        for cred in intel_data.credentials:
            cred_line = f"  {cred.username}"
            if cred.password:
                cred_line += f":{cred.password}"
            elif cred.hash:
                cred_line += " (hash)"
            if cred.host:
                cred_line += f" @ {cred.host}"
            if cred.service:
                cred_line += f" [{cred.service}]"
            lines.append(cred_line)

        return "\n".join(lines)

    elif action == "summary":
        return get_intel_summary()

    elif action == "clear":
        intel_data = Intel()
        _save_intel(intel_data)
        return "Intelligence cleared"

    else:
        return f"Unknown action: {action}"
