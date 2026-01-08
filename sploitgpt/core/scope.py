"""
Scope Enforcement Module

Handles checking whether targets are within the defined engagement scope.
Supports IP addresses, CIDR ranges, and hostnames.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

from sploitgpt.core.config import get_settings


@dataclass
class ScopeCheckResult:
    """Result of a scope check."""

    in_scope: bool
    target: str
    matched_rule: str | None = None  # Which rule matched (if in scope)
    reason: str = ""  # Explanation of why out of scope


class ScopeChecker:
    """
    Checks whether targets are within the engagement scope.

    Supports:
    - Individual IP addresses (e.g., "192.168.1.100")
    - CIDR ranges (e.g., "10.0.0.0/24")
    - Hostnames (e.g., "target.htb")
    - Wildcard hostnames (e.g., "*.htb")
    """

    def __init__(self, scope_string: str = ""):
        """
        Initialize the scope checker.

        Args:
            scope_string: Comma-separated list of allowed targets
        """
        self.raw_scope = scope_string
        self.ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.hostnames: set[str] = set()
        self.wildcard_suffixes: list[str] = []
        self._parse_scope(scope_string)

    def _parse_scope(self, scope_string: str) -> None:
        """Parse the scope string into usable components."""
        if not scope_string or not scope_string.strip():
            return

        for entry in scope_string.split(","):
            entry = entry.strip().lower()
            if not entry:
                continue

            # Try to parse as IP or CIDR
            try:
                # Check if it's a single IP (add /32 for IPv4, /128 for IPv6)
                if "/" not in entry:
                    ip = ipaddress.ip_address(entry)
                    if isinstance(ip, ipaddress.IPv4Address):
                        network = ipaddress.ip_network(f"{entry}/32", strict=False)
                    else:
                        network = ipaddress.ip_network(f"{entry}/128", strict=False)
                else:
                    network = ipaddress.ip_network(entry, strict=False)
                self.ip_networks.append(network)
                continue
            except ValueError:
                pass

            # Check for wildcard hostname (e.g., "*.htb")
            if entry.startswith("*."):
                suffix = entry[1:]  # Keep the dot: ".htb"
                self.wildcard_suffixes.append(suffix)
                continue

            # Regular hostname
            self.hostnames.add(entry)

    def is_empty(self) -> bool:
        """Check if no scope has been defined."""
        return not self.ip_networks and not self.hostnames and not self.wildcard_suffixes

    def check(self, target: str) -> ScopeCheckResult:
        """
        Check if a target is within scope.

        Args:
            target: IP address or hostname to check

        Returns:
            ScopeCheckResult with in_scope status and details
        """
        if not target:
            return ScopeCheckResult(
                in_scope=False,
                target=target,
                reason="Empty target",
            )

        target_lower = target.strip().lower()

        # If no scope defined, everything is in scope
        if self.is_empty():
            return ScopeCheckResult(
                in_scope=True,
                target=target,
                matched_rule="(no scope defined)",
                reason="No scope restrictions configured",
            )

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(target_lower)
            for network in self.ip_networks:
                if ip in network:
                    return ScopeCheckResult(
                        in_scope=True,
                        target=target,
                        matched_rule=str(network),
                    )
            # IP not in any allowed network
            return ScopeCheckResult(
                in_scope=False,
                target=target,
                reason=f"IP {target} not in any allowed network",
            )
        except ValueError:
            pass

        # Check as hostname
        # Exact match
        if target_lower in self.hostnames:
            return ScopeCheckResult(
                in_scope=True,
                target=target,
                matched_rule=target_lower,
            )

        # Wildcard suffix match
        for suffix in self.wildcard_suffixes:
            if target_lower.endswith(suffix):
                return ScopeCheckResult(
                    in_scope=True,
                    target=target,
                    matched_rule=f"*{suffix}",
                )

        # Not matched
        return ScopeCheckResult(
            in_scope=False,
            target=target,
            reason=f"Hostname {target} not in scope",
        )

    def check_command(self, command: str) -> list[ScopeCheckResult]:
        """
        Extract targets from a command and check each one.

        Args:
            command: Shell command that may contain targets

        Returns:
            List of ScopeCheckResults for each extracted target
        """
        targets = self._extract_targets_from_command(command)
        return [self.check(t) for t in targets]

    def _extract_targets_from_command(self, command: str) -> list[str]:
        """Extract potential targets (IPs/hostnames) from a command."""
        targets: list[str] = []

        # IP address pattern
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        ip_matches = re.findall(ip_pattern, command)
        targets.extend(ip_matches)

        # Hostname pattern (simplified - looks for common TLDs and pentest domains)
        hostname_pattern = (
            r"\b[a-zA-Z][a-zA-Z0-9-]*\.(?:com|net|org|io|local|htb|thm|box|lan|internal)\b"
        )
        hostname_matches = re.findall(hostname_pattern, command, re.IGNORECASE)
        targets.extend(hostname_matches)

        # Remove duplicates while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for t in targets:
            t_lower = t.lower()
            if t_lower not in seen:
                seen.add(t_lower)
                unique.append(t)

        return unique

    def get_scope_summary(self) -> str:
        """Get a human-readable summary of the current scope."""
        if self.is_empty():
            return "No scope defined (all targets allowed)"

        parts: list[str] = []

        if self.ip_networks:
            networks = [str(n) for n in self.ip_networks]
            parts.append(f"Networks: {', '.join(networks)}")

        if self.hostnames:
            parts.append(f"Hostnames: {', '.join(sorted(self.hostnames))}")

        if self.wildcard_suffixes:
            wildcards = [f"*{s}" for s in self.wildcard_suffixes]
            parts.append(f"Wildcards: {', '.join(wildcards)}")

        return " | ".join(parts)


# Global scope checker instance
_scope_checker: ScopeChecker | None = None


def get_scope_checker(reload: bool = False) -> ScopeChecker:
    """Get the global scope checker instance."""
    global _scope_checker
    if reload or _scope_checker is None:
        settings = get_settings()
        _scope_checker = ScopeChecker(settings.scope_targets)
    return _scope_checker


def check_target_scope(target: str) -> ScopeCheckResult:
    """Convenience function to check if a target is in scope."""
    return get_scope_checker().check(target)


def check_command_scope(command: str) -> list[ScopeCheckResult]:
    """Convenience function to check targets in a command."""
    return get_scope_checker().check_command(command)


def get_scope_mode() -> Literal["warn", "block"]:
    """Get the current scope enforcement mode."""
    settings = get_settings()
    mode = settings.scope_mode.lower().strip()
    if mode == "block":
        return "block"
    return "warn"


def is_scope_defined() -> bool:
    """Check if any scope has been configured."""
    return not get_scope_checker().is_empty()
