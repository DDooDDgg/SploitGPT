"""Shodan search tool for SploitGPT."""

import asyncio
import os
from typing import Any

import httpx

from . import register_tool


def _coerce_str(value: Any) -> str:
    """Return a safe string representation, ignoring non-scalar types."""
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _format_banner(raw: Any, max_lines: int = 8, max_line_len: int = 160) -> str:
    if raw is None:
        return ""
    text = _coerce_str(raw)
    if not text:
        return ""
    lines = text.splitlines()
    formatted: list[str] = []
    for line in lines[:max_lines]:
        formatted.append(line[:max_line_len])
    if len(lines) > max_lines or any(len(l) > max_line_len for l in lines):
        formatted.append("...truncated...")
    return "\n".join(formatted).strip()


def _format_match(match: dict[str, Any]) -> str:
    """Format a single Shodan match for LLM consumption."""
    ip = _coerce_str(match.get("ip_str")) or "unknown"
    port = _coerce_str(match.get("port")) or "?"
    org = _coerce_str(match.get("org")) or _coerce_str(match.get("isp"))
    hostnames_list = match.get("hostnames") or []
    if isinstance(hostnames_list, (list, tuple)):
        hostnames = ", ".join(_coerce_str(h) for h in hostnames_list if _coerce_str(h))
    else:
        hostnames = _coerce_str(hostnames_list)
    location = match.get("location") or {}
    city = _coerce_str(location.get("city"))
    country = _coerce_str(location.get("country_name"))
    product = _coerce_str(match.get("product")) or _coerce_str(match.get("_shodan", {}).get("module", ""))

    banner = _format_banner(match.get("data"))

    vulns: list[str] = []
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

    # Basic retry for transient errors / rate limits
    max_attempts = 2
    for attempt in range(1, max_attempts + 1):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": api_key, "query": query},
                )
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, dict) and data.get("error"):
                    return f"Error: Shodan API error: {data['error']}"
                break
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status in (401, 403):
                return "Error: Shodan rejected the request. Check SHODAN_API_KEY."
            if status == 402:
                return "Error: Shodan plan limit reached (status 402)."
            if status == 429:
                if attempt < max_attempts:
                    await asyncio.sleep(1 * attempt)
                    continue
                return "Error: Shodan rate limited (HTTP 429). Try again later or reduce query frequency."
            # Other HTTP errors
            try:
                err_json = e.response.json()
                if isinstance(err_json, dict) and err_json.get("error"):
                    return f"Error: Shodan returned {status}: {err_json['error']}"
            except Exception:
                pass
            return f"Error: Shodan returned {status}."
        except httpx.TimeoutException:
            if attempt < max_attempts:
                await asyncio.sleep(1 * attempt)
                continue
            return "Error: Shodan search timed out."
        except Exception as e:
            return f"Error: Shodan search failed: {e}"
    else:
        return "Error: Shodan search failed after retries."

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
