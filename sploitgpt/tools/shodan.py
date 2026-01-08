"""Shodan search tool for SploitGPT."""

import asyncio
import json
import logging
import random
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from sploitgpt.core.config import get_settings

from . import register_tool

logger = logging.getLogger(__name__)

_OUTPUT_TEXT = "text"
_OUTPUT_JSON = "json"


def _strip_query_from_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except Exception:
        return None
    if not (0.0 <= seconds <= 300.0):
        return None
    return seconds


@lru_cache(maxsize=1)
def _load_embedded_queries() -> list[str]:
    """Load embedded Shodan dorks/queries from bundled knowledge sources."""
    base = Path(__file__).resolve().parent.parent
    sources = [
        base / "knowledge" / "sources" / "shodan_dorks.md",
        base / "knowledge" / "sources" / "awesome_shodan_queries.md",
    ]

    queries: list[str] = []
    seen: set[str] = set()

    for path in sources:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        in_block = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith("```"):
                in_block = not in_block
                continue
            if not line:
                continue
            if in_block:
                # Raw dork list in code blocks.
                val = line
            else:
                # Bullet format: - **Title** — `query`
                match = re.findall(r"`([^`]+)`", line)
                if match:
                    val = match[0]
                else:
                    continue

            val_norm = val.strip()
            if val_norm and val_norm not in seen:
                seen.add(val_norm)
                queries.append(val_norm)

    return queries


def _suggest_queries(user_query: str, limit: int = 5) -> list[str]:
    """Suggest locally-embedded queries that overlap with the user input."""
    tokens = [t for t in re.split(r"\s+", user_query.lower()) if t]
    if not tokens:
        return []

    scored: list[tuple[int, int, str]] = []
    for q in _load_embedded_queries():
        q_lower = q.lower()
        score = sum(1 for t in tokens if t in q_lower)
        if score > 0:
            scored.append((score, -len(q), q))

    scored.sort(reverse=True)
    return [q for _, __, q in scored[:limit]]


def _get_client(timeout: float = 30.0) -> httpx.AsyncClient:
    """Factory for the HTTP client (patched in tests)."""
    return httpx.AsyncClient(timeout=timeout)


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
        formatted.append(_coerce_str(line)[:max_line_len])
    if len(lines) > max_lines or any(len(line) > max_line_len for line in lines):
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
    product = _coerce_str(match.get("product")) or _coerce_str(
        match.get("_shodan", {}).get("module", "")
    )

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


def _match_to_json(match: dict[str, Any]) -> dict[str, Any]:
    ip = _coerce_str(match.get("ip_str")) or "unknown"
    port = _coerce_str(match.get("port")) or "?"
    org = _coerce_str(match.get("org")) or _coerce_str(match.get("isp"))
    hostnames_list = match.get("hostnames") or []
    if isinstance(hostnames_list, (list, tuple)):
        hostnames = [_coerce_str(h) for h in hostnames_list if _coerce_str(h)]
    else:
        hostnames = [_coerce_str(hostnames_list)] if _coerce_str(hostnames_list) else []
    location = match.get("location") or {}
    city = _coerce_str(location.get("city"))
    country = _coerce_str(location.get("country_name"))
    product = _coerce_str(match.get("product")) or _coerce_str(
        match.get("_shodan", {}).get("module", "")
    )

    banner = _format_banner(match.get("data"))

    vulns: list[str] = []
    if isinstance(match.get("vulns"), dict):
        vulns = list(match["vulns"].keys())[:10]

    return {
        "ip": ip,
        "port": port,
        "hostnames": hostnames,
        "org": org or None,
        "location": {"city": city or None, "country": country or None}
        if (city or country)
        else None,
        "service": product or None,
        "vulns": vulns or None,
        "banner": banner or None,
    }


@register_tool("shodan_search")
async def shodan_search(
    query: str,
    limit: int = 5,
    page: int = 1,
    facets: str | None = None,
    minify: bool = False,
    output: str = _OUTPUT_TEXT,
) -> str:
    """
    Search Shodan for exposed services, banners, and potential vulnerabilities.

    Requires SHODAN_API_KEY in the environment.

    Args:
        query: Shodan query (e.g., 'apache country:US port:80')
        limit: Maximum results to return (default 5, max 20)
        page: Shodan search page (default 1)
        facets: Optional comma-separated facets (e.g., 'org,port,country')
        minify: Reduce response payload (may omit banner details)
        output: 'text' or 'json'

    Returns:
        Formatted Shodan results
    """
    query = query.strip()
    if not query:
        return "Error: No query provided."

    limit = max(1, min(limit, 20))
    page = max(1, page)
    facets = facets.strip() if facets else None
    output = (output or _OUTPUT_TEXT).strip().lower()
    if output not in {_OUTPUT_TEXT, _OUTPUT_JSON}:
        return "Error: Invalid output format. Use 'text' or 'json'."

    suggestions = _suggest_queries(query, limit=5)

    # Get API key from credentials module (checks keyring, env, config)
    from sploitgpt.core.credentials import get_shodan_api_key

    api_key = get_shodan_api_key()
    if not api_key:
        return (
            "Error: Shodan API key is not set.\n"
            "Set with: sploitgpt --creds set shodan-key\n"
            "Or set SHODAN_API_KEY environment variable."
        )

    settings = get_settings()

    max_attempts = max(1, settings.shodan_max_attempts)
    backoff = max(0.1, settings.shodan_backoff_base)
    max_backoff = max(backoff, settings.shodan_backoff_max)
    last_error: str | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            params: dict[str, Any] = {"key": api_key, "query": query}
            if page != 1:
                params["page"] = page
            if facets:
                params["facets"] = facets
            if minify:
                params["minify"] = True

            async with _get_client(timeout=settings.shodan_timeout) as client:
                resp = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params=params,
                )
            status = resp.status_code
            retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            payload: dict[str, Any] = {}
            try:
                payload = resp.json() if resp.content else {}
            except Exception:
                payload = {}

            if status == 429:
                last_error = payload.get("error") or "Shodan rate limited (HTTP 429)."
                if attempt < max_attempts:
                    if retry_after is not None:
                        delay = retry_after
                    else:
                        delay = min(backoff, max_backoff)
                        delay += random.uniform(0.0, delay * 0.15)
                    await asyncio.sleep(delay)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                detail = f"{last_error} Try again later."
                if retry_after is not None:
                    detail += f" Retry-After: {retry_after:.0f}s."
                return f"Error: {detail}"

            if status == 401 or status == 403:
                return "Error: Shodan rejected the request. Check SHODAN_API_KEY."
            if status == 402:
                return "Error: Shodan plan limit reached (status 402)."
            if status in {408, 500, 502, 503, 504}:
                last_error = payload.get("error") or f"Shodan returned HTTP {status}."
                if attempt < max_attempts:
                    delay = min(backoff, max_backoff)
                    delay += random.uniform(0.0, delay * 0.15)
                    await asyncio.sleep(delay)
                    backoff = min(backoff * 2, max_backoff)
                    continue
                return f"Error: Shodan temporarily unavailable (HTTP {status}). Please retry later."
            if status >= 400:
                api_error = payload.get("error")
                if api_error:
                    return f"Error: Shodan returned {status}: {api_error}"
                return f"Error: Shodan returned HTTP {status}."

            if isinstance(payload, dict) and payload.get("error"):
                return f"Error: Shodan API error: {payload['error']}"

            data = payload
            break

        except httpx.TimeoutException:
            last_error = "timeout"
            if attempt < max_attempts:
                delay = min(backoff, max_backoff)
                delay += random.uniform(0.0, delay * 0.15)
                await asyncio.sleep(delay)
                backoff = min(backoff * 2, max_backoff)
                continue
            return "Error: Shodan search timed out."
        except httpx.RequestError as e:
            # Avoid logging exception/trace: it may include the request URL with the API key.
            safe_url = None
            try:
                if (
                    getattr(e, "request", None) is not None
                    and getattr(e.request, "url", None) is not None
                ):
                    safe_url = _strip_query_from_url(str(e.request.url))
            except Exception:
                safe_url = None
            last_error = f"{type(e).__name__}" + (f" ({safe_url})" if safe_url else "")
            logger.debug("Shodan network error (%s)", type(e).__name__)
            if attempt < max_attempts:
                delay = min(backoff, max_backoff)
                delay += random.uniform(0.0, delay * 0.15)
                await asyncio.sleep(delay)
                backoff = min(backoff * 2, max_backoff)
                continue
            return "Error: Shodan network error. Please check connectivity."
        except Exception as e:
            logger.exception("Shodan search failed")
            return f"Error: Shodan search failed: {e}"
    else:
        return f"Error: Shodan search failed after retries ({last_error})."

    matches = data.get("matches") or []
    total = data.get("total", 0)
    facets_data = data.get("facets") or {}

    if output == _OUTPUT_JSON:
        out: dict[str, Any] = {
            "query": query,
            "page": page,
            "total": total,
            "shown": min(limit, len(matches)),
            "suggestions": suggestions,
            "facets": facets_data or None,
            "matches": [_match_to_json(m) for m in matches[:limit]],
        }
        return json.dumps(out, indent=2, ensure_ascii=False)

    results: list[str] = []
    if suggestions:
        results.append("Suggested local queries (offline):")
        results.extend([f"- {s}" for s in suggestions])
        results.append("")

    results.append(f"Shodan search: {query}")
    results.append(f"Page: {page}")
    results.append(f"Total reported: {total}")
    if facets_data:
        results.append("Facets:")
        if isinstance(facets_data, dict):
            for facet_name, items in facets_data.items():
                if isinstance(items, list):
                    preview = ", ".join(
                        f"{_coerce_str(i.get('value'))}:{_coerce_str(i.get('count'))}"
                        for i in items[:8]
                        if isinstance(i, dict)
                    )
                else:
                    preview = _coerce_str(items)
                if preview:
                    results.append(f"- {facet_name}: {preview}")
        results.append("")
    if not matches:
        return "\n".join(results + ["No results found."])

    for match in matches[:limit]:
        results.append(_format_match(match))

    if total > limit:
        results.append(f"(Showing top {limit} of {total} results)")

    return "\n".join(results)
