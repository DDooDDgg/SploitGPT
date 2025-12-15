import asyncio
import types
import pytest

from sploitgpt.tools.shodan import shodan_search


class FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self) -> None:
        if 400 <= self.status_code:
            import httpx
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self) -> dict:
        return self._json


class FakeClient:
    def __init__(self, responses: list[FakeResponse]):
        self._responses = responses
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        if not self._responses:
            raise RuntimeError("No more fake responses")
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_shodan_success(monkeypatch):
    resp = FakeResponse(200, {"total": 1, "matches": [{"ip_str": "1.1.1.1", "port": 80, "data": "ok"}]})
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    monkeypatch.setattr("httpx.AsyncClient", lambda timeout=...: FakeClient([resp]))

    out = await shodan_search("test", limit=1)
    assert "Shodan search" in out
    assert "1.1.1.1" in out


@pytest.mark.asyncio
async def test_shodan_401(monkeypatch):
    resp = FakeResponse(401)
    monkeypatch.setenv("SHODAN_API_KEY", "bad")
    monkeypatch.setattr("httpx.AsyncClient", lambda timeout=...: FakeClient([resp]))

    out = await shodan_search("test", limit=1)
    assert "rejected" in out.lower()


@pytest.mark.asyncio
async def test_shodan_429_retry(monkeypatch):
    resp1 = FakeResponse(429)
    resp2 = FakeResponse(200, {"total": 0, "matches": []})
    monkeypatch.setenv("SHODAN_API_KEY", "test")
    shared = [resp1, resp2]
    monkeypatch.setattr("httpx.AsyncClient", lambda timeout=...: FakeClient(shared))

    out = await shodan_search("test", limit=1)
    assert "No results" in out or "no results" in out


@pytest.mark.asyncio
async def test_shodan_timeout(monkeypatch):
    class TimeoutClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, *args, **kwargs):
            import httpx
            raise httpx.TimeoutException("timeout")

    monkeypatch.setenv("SHODAN_API_KEY", "test")
    monkeypatch.setattr("httpx.AsyncClient", lambda timeout=...: TimeoutClient())

    out = await shodan_search("test", limit=1)
    assert "timed out" in out.lower()
