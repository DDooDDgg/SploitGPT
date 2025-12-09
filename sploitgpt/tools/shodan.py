"""Shodan search tool for SploitGPT."""

import os
from typing import List

import httpx

from . import register_tool


def _format_match(match: dict) -> str:
    """Format a single Shodan match for LLM consumption."""
    ip = match.get("ip_str", "unknown")
    port = match.get("port", "?")
    org = match.get("org") or match.get("isp") or ""
    hostnames = ", ".join(match.get("hostnames") or [])
    location = match.get("location") or {}
    city = location.get("city") or ""
    country = location.get("country_name") or ""
    product = match.get("product") or match.get("_shodan", {}).get("module", "")

    # Service banner (truncate to keep output concise)
    banner = (match.get("data") or "").strip()
    if len(banner) > 400:
        banner = banner[:400] + "..."

    vulns: List[str] = []
    if isinstance(match.get("vulns"), dict):
        vulns = list(match["vulns"].keys())[:10]

    lines = [f"- {ip}:{port}"]
    if hostnames:
        lines.append(f"  hostnames: {hostnames}")
    if org:
        lines.append(f"  org: {org}")
    if city or country:
        lines.append(f"  location: {city}, {country}".rstrip(", "))
    if product:
        lines.append(f"  service: {product}")
    if vulns:
        lines.append(f"  vulns: {', '.join(vulns)}")
    if banner:
        lines.append("  banner:\n    " + banner.replace("\n", "\n    "))

    return "\n".join(lines)


@register_tool("shodan_search")
async def shodan_search(
    query: str,
    limit: int = 5,
) -> str:
    """
    Search Shodan for exposed services, banners, and potential vulnerabilities.
    
    Requires SHODAN_API_KEY in the environment.
    
    Args:
        query: Shodan query (e.g., 'apache country:US port:80')
        limit: Maximum results to return (default 5, max 20)
        
    Returns:
        Formatted Shodan results
    """
    query = query.strip()
    if not query:
        return "Error: No query provided."

    limit = max(1, min(limit, 20))

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return (
            "Error: SHODAN_API_KEY environment variable is not set.\n"
            "Add SHODAN_API_KEY=your_key to .env to enable this tool."
        )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query},
            )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (401, 403):
            return "Error: Shodan rejected the request. Check SHODAN_API_KEY."
        if e.response.status_code == 402:
            return "Error: Shodan plan limit reached (status 402)."
        return f"Error: Shodan returned {e.response.status_code}."
    except httpx.TimeoutException:
        return "Error: Shodan search timed out."
    except Exception as e:
        return f"Error: Shodan search failed: {e}"

    matches = data.get("matches") or []
    total = data.get("total", 0)
    if not matches:
        return f"Shodan search: {query}\nNo results found. Total reported: {total}."

    results = [f"Shodan search: {query}", f"Total reported: {total}"]

    for match in matches[:limit]:
        results.append(_format_match(match))

    if total > limit:
        results.append(f"(Showing top {limit} of {total} results)")

    return "\n".join(results)
