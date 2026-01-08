"""CVE and exploit search tools for SploitGPT.

Provides CVE database lookup and searchsploit integration.
"""

import re
import shlex

import httpx

from . import register_tool, terminal


def _parse_searchsploit_output(output: str) -> str:
    """Parse searchsploit output into clean format."""
    lines = output.strip().split("\n")
    results = []

    for line in lines:
        # Skip header lines and separators
        if not line.strip() or line.startswith("-") or "Exploit Title" in line:
            continue
        # Extract title and path
        if "|" in line:
            parts = line.split("|")
            if len(parts) >= 2:
                title = parts[0].strip()
                path = parts[1].strip()
                if title and path:
                    results.append(f"• {title}\n  Path: {path}")

    if not results:
        return "No exploits found."

    return "\n".join(results[:10])  # Limit to 10 results


@register_tool("cve_search")
async def cve_search(
    query: str,
    source: str = "both",
    limit: int = 5,
) -> str:
    """
    Search for CVEs and known vulnerabilities.

    Can search by CVE ID, product name, or service/version string.
    Useful for identifying exploitable vulnerabilities in discovered services.

    Args:
        query: Search query - CVE ID (e.g., 'CVE-2021-44228'), product ('Apache 2.4.49'), or keyword ('log4j')
        source: Search source: 'cve' for CVE database, 'searchsploit' for exploits, 'both' for both (default: both)
        limit: Max results to return (default: 5)

    Returns:
        Formatted CVE/exploit results
    """
    query = query.strip()
    if not query:
        return "Error: query is required"

    limit = min(limit, 10)
    results = []

    # Check for CVE ID pattern
    cve_pattern = r"CVE-\d{4}-\d{4,}"
    cve_match = re.search(cve_pattern, query.upper())

    # CVE database search
    if source in ("cve", "both"):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Use NIST NVD API 2.0
                if cve_match:
                    # Exact CVE lookup
                    cve_id = cve_match.group()
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                else:
                    # Keyword search
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage={limit}"

                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])

                    if vulns:
                        results.append("## CVE Database Results\n")
                        for vuln in vulns[:limit]:
                            cve = vuln.get("cve", {})
                            cve_id = cve.get("id", "Unknown")

                            # Get description
                            descriptions = cve.get("descriptions", [])
                            desc = ""
                            for d in descriptions:
                                if d.get("lang") == "en":
                                    desc = d.get("value", "")[:200]
                                    break

                            # Get CVSS score
                            metrics = cve.get("metrics", {})
                            cvss_score = "N/A"
                            severity = ""

                            # Try CVSS 3.1, then 3.0, then 2.0
                            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                                if metrics.get(version):
                                    cvss_data = metrics[version][0].get("cvssData", {})
                                    cvss_score = cvss_data.get("baseScore", "N/A")
                                    severity = cvss_data.get("baseSeverity", "")
                                    break

                            results.append(f"**{cve_id}** (CVSS: {cvss_score} {severity})")
                            if desc:
                                results.append(f"  {desc}...")
                            results.append("")
                    else:
                        results.append("No CVEs found in NVD database.\n")

        except Exception as e:
            results.append(f"CVE search error: {e!s}\n")

    # SearchSploit search (via terminal)
    if source in ("searchsploit", "both"):
        try:
            # Use args list to avoid shell injection - no shell=True needed
            output = await terminal(
                args=["searchsploit", "--color", "--disable-colour", query],
                timeout=30,
            )

            if output and "Error" not in output:
                # Limit output to ~30 lines worth
                lines = output.strip().split("\n")[:30]
                parsed = _parse_searchsploit_output("\n".join(lines))
                if parsed != "No exploits found." or source == "searchsploit":
                    results.append("## Exploit-DB Results\n")
                    results.append(parsed)
                    results.append("")
            elif source == "searchsploit":
                results.append("## Exploit-DB Results\n")
                results.append("No exploits found (or searchsploit not installed).")
                results.append("")

        except Exception as e:
            if source == "searchsploit":
                results.append(f"SearchSploit error: {e!s}\n")

    if not results:
        return f"No results found for: {query}"

    return "\n".join(results)


@register_tool("searchsploit")
async def searchsploit(
    query: str,
    options: str = "",
) -> str:
    """
    Search Exploit-DB via searchsploit for known exploits.

    Use when you find a vulnerable service version.
    Example queries: 'Apache 2.4.49', 'vsftpd 2.3.4', 'Windows SMB'

    Args:
        query: Search term - service name and version (e.g., 'vsftpd 2.3.4')
        options: Additional searchsploit options (e.g., '-w' for www exploits, '-x ID' to examine)

    Returns:
        Formatted exploit results
    """
    query = query.strip()
    if not query:
        return "Error: query is required"

    # Build command args list to avoid shell injection
    cmd_args = ["searchsploit", "--color", "--disable-colour"]

    # Parse and validate options (only allow known safe flags)
    if options:
        allowed_flags = {
            "-w",
            "-j",
            "-p",
            "-t",
            "-s",
            "-e",
            "--www",
            "--json",
            "--path",
            "--title",
            "--strict",
            "--exact",
        }
        try:
            opt_parts = shlex.split(options)
            for part in opt_parts:
                # Only allow known flags, not arbitrary arguments
                if part in allowed_flags or part.startswith("--"):
                    cmd_args.append(part)
        except ValueError:
            pass  # Ignore malformed options

    cmd_args.append(query)

    try:
        output = await terminal(args=cmd_args, timeout=30)

        if not output or output.strip() == "(no output)":
            return f"No exploits found for: {query}"

        if "Error" in output:
            return "searchsploit command failed (is it installed?)"

        # Limit output to ~50 lines
        lines = output.strip().split("\n")[:50]
        return f"SearchSploit results for '{query}':\n\n" + "\n".join(lines)

    except Exception as e:
        return f"Error running searchsploit: {e}"
