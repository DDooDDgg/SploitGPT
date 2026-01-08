"""
Nuclei vulnerability scanner integration.

Provides tools to run nuclei scans against targets using various templates.
"""

import asyncio
import json
import logging
import re
import shlex
from typing import Any

from . import register_tool

logger = logging.getLogger(__name__)

# Common nuclei template tags for categorization
TEMPLATE_TAGS = {
    "cve": "CVE-based vulnerability checks",
    "panel": "Admin panel detection",
    "login": "Login page detection",
    "exposure": "Sensitive data exposure",
    "misconfig": "Misconfigurations",
    "takeover": "Subdomain takeover checks",
    "tech": "Technology detection",
    "default-login": "Default credentials",
    "file": "Sensitive file detection",
    "xss": "Cross-site scripting",
    "sqli": "SQL injection",
    "lfi": "Local file inclusion",
    "rce": "Remote code execution",
    "ssrf": "Server-side request forgery",
    "redirect": "Open redirect",
    "creds-stuffing": "Credential stuffing",
}

# Severity levels
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]


def _sanitize_for_filename(s: str) -> str:
    """Sanitize a string for use in filenames."""
    return re.sub(r"[^A-Za-z0-9_.:-]+", "_", s).strip("_") or "target"


def _parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into structured findings."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
            findings.append(finding)
        except json.JSONDecodeError:
            # Not a JSON line (could be status output)
            continue
    return findings


def _format_findings_text(findings: list[dict[str, Any]]) -> str:
    """Format nuclei findings as human-readable text."""
    if not findings:
        return "No vulnerabilities found."

    # Group by severity
    by_severity: dict[str, list[dict]] = {s: [] for s in SEVERITY_LEVELS}
    for f in findings:
        sev = f.get("info", {}).get("severity", "info").lower()
        if sev not in by_severity:
            sev = "info"
        by_severity[sev].append(f)

    lines = [f"Found {len(findings)} findings:\n"]

    # Show critical/high first
    for severity in reversed(SEVERITY_LEVELS):
        items = by_severity[severity]
        if not items:
            continue

        lines.append(f"\n[{severity.upper()}] ({len(items)} findings)")
        for f in items[:10]:  # Limit per severity
            info = f.get("info", {})
            name = info.get("name", "Unknown")
            template_id = f.get("template-id", "")
            matched_at = f.get("matched-at", f.get("host", ""))
            matcher_name = f.get("matcher-name", "")

            line = f"  - {name}"
            if template_id:
                line += f" [{template_id}]"
            if matched_at:
                line += f"\n    URL: {matched_at}"
            if matcher_name:
                line += f"\n    Matcher: {matcher_name}"

            # Add CVE if present
            refs = info.get("reference", [])
            cves = [r for r in refs if isinstance(r, str) and r.startswith("CVE-")]
            if cves:
                line += f"\n    CVE: {', '.join(cves[:3])}"

            lines.append(line)

        if len(items) > 10:
            lines.append(f"  ... and {len(items) - 10} more {severity} findings")

    return "\n".join(lines)


@register_tool("nuclei_scan")
async def nuclei_scan(
    target: str,
    tags: str | None = None,
    templates: str | None = None,
    severity: str | None = None,
    rate_limit: int = 150,
    timeout: int = 600,
    output_format: str = "text",
    extra_args: str | None = None,
) -> str:
    """
    Run a nuclei vulnerability scan against a target.

    Args:
        target: Target URL or host to scan (e.g., https://example.com or 10.0.0.1)
        tags: Comma-separated template tags to filter (e.g., "cve,exposure,misconfig")
        templates: Specific template path or ID (e.g., "cves/2021/CVE-2021-44228")
        severity: Filter by severity (e.g., "high,critical" or "medium,high,critical")
        rate_limit: Maximum requests per second (default: 150)
        timeout: Scan timeout in seconds (default: 600)
        output_format: Output format - "text" (default) or "json"
        extra_args: Additional nuclei arguments (advanced users)

    Returns:
        Scan results as formatted text or JSON
    """
    from sploitgpt.core.config import get_settings

    # Input validation
    target = (target or "").strip()
    if not target:
        return "Error: target is required"

    # Validate target format (URL or IP/hostname)
    if not re.match(r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9._:-]*", target):
        return "Error: invalid target format. Provide a URL or hostname."

    # Bound rate limit
    rate_limit = max(1, min(rate_limit, 1000))
    timeout = max(30, min(timeout, 3600))

    # Get loot directory for output
    settings = get_settings()
    loot_dir = settings.loot_dir
    loot_dir.mkdir(parents=True, exist_ok=True)

    # Build output filename
    safe_target = _sanitize_for_filename(target.replace("https://", "").replace("http://", ""))
    output_file = loot_dir / f"nuclei_{safe_target}.jsonl"

    # Build nuclei command
    argv = [
        "nuclei",
        "-u",
        target,
        "-jsonl",  # JSON Lines output for parsing
        "-o",
        str(output_file),
        "-rate-limit",
        str(rate_limit),
        "-silent",  # Reduce noise
        "-no-color",
    ]

    # Add tag filters
    if tags:
        tags_clean = tags.strip()
        if tags_clean:
            # Validate tags
            tag_list = [t.strip() for t in tags_clean.split(",") if t.strip()]
            if tag_list:
                argv.extend(["-tags", ",".join(tag_list)])

    # Add specific templates
    if templates:
        templates_clean = templates.strip()
        if templates_clean:
            argv.extend(["-t", templates_clean])

    # Add severity filter
    if severity:
        severity_clean = severity.strip().lower()
        if severity_clean:
            # Validate severity levels
            sev_list = [s.strip() for s in severity_clean.split(",") if s.strip()]
            valid_sevs = [s for s in sev_list if s in SEVERITY_LEVELS]
            if valid_sevs:
                argv.extend(["-severity", ",".join(valid_sevs)])

    # Add extra arguments (advanced)
    if extra_args:
        try:
            extra = shlex.split(extra_args)
            # Filter out potentially dangerous args
            dangerous = {"-o", "-output", "-jsonl", "-json", "-markdown"}
            extra = [a for a in extra if a.split("=")[0] not in dangerous]
            argv.extend(extra)
        except ValueError as e:
            return f"Error parsing extra_args: {e}"

    # Run nuclei
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            return (
                f"Nuclei scan timed out after {timeout}s. Partial results may be in {output_file}"
            )

    except FileNotFoundError:
        return (
            "Error: nuclei is not installed or not in PATH. "
            "Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
    except Exception as e:
        return f"Error running nuclei: {e}"

    # Parse results from output file
    findings = []
    if output_file.exists():
        try:
            content = output_file.read_text()
            findings = _parse_nuclei_jsonl(content)
        except Exception as e:
            logger.warning(f"Failed to parse nuclei output: {e}")

    # Format output
    if output_format == "json":
        result = {
            "target": target,
            "findings_count": len(findings),
            "findings": findings[:50],  # Limit for response size
            "output_file": str(output_file),
        }
        if len(findings) > 50:
            result["note"] = (
                f"Showing 50 of {len(findings)} findings. Full results in {output_file}"
            )
        return json.dumps(result, indent=2, default=str)

    # Text format
    result_text = _format_findings_text(findings)
    result_text += f"\n\nFull results saved to: {output_file}"

    return result_text


@register_tool("nuclei_templates")
async def nuclei_templates(
    search: str | None = None,
    tag: str | None = None,
    limit: int = 20,
) -> str:
    """
    List available nuclei templates.

    Args:
        search: Search term to filter templates by name/description
        tag: Filter by template tag (e.g., "cve", "exposure", "panel")
        limit: Maximum templates to return (default: 20)

    Returns:
        List of matching templates
    """
    # Bound limit
    limit = max(1, min(limit, 100))

    # Build nuclei command to list templates
    argv = ["nuclei", "-tl", "-silent", "-no-color"]

    if tag:
        tag_clean = tag.strip()
        if tag_clean:
            argv.extend(["-tags", tag_clean])

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode() if stdout else ""
    except FileNotFoundError:
        return (
            "Error: nuclei is not installed or not in PATH. "
            "Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
    except TimeoutError:
        return "Error: template listing timed out"
    except Exception as e:
        return f"Error listing templates: {e}"

    # Parse template list
    templates = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        templates.append(line)

    # Filter by search term
    if search:
        search_lower = search.lower()
        templates = [t for t in templates if search_lower in t.lower()]

    # Limit results
    total = len(templates)
    templates = templates[:limit]

    if not templates:
        return f"No templates found{' matching ' + repr(search) if search else ''}."

    lines = [f"Found {total} templates{' matching ' + repr(search) if search else ''}:\n"]
    for t in templates:
        lines.append(f"  - {t}")

    if total > limit:
        lines.append(
            f"\n... and {total - limit} more. Use nuclei_scan with -t to use a specific template."
        )

    # Add available tags info
    lines.append("\n\nCommon tags for filtering:")
    for tag_name, desc in list(TEMPLATE_TAGS.items())[:8]:
        lines.append(f"  - {tag_name}: {desc}")

    return "\n".join(lines)
