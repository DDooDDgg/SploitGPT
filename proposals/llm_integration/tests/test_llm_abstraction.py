import pytest
import asyncio
import httpx

from proposals.llm_integration.llm_abstraction import OpencodeAPIClient


@pytest.mark.asyncio
async def test_opencode_chat_and_health_check():
    # MockTransport to simulate the Opencode endpoints
    async def handler(request):
        if request.url.path.endswith("/api/v1/models"):
            return httpx.Response(200, json=[{"name": "qwen2.5:7b"}])
        if request.url.path.endswith("/api/v1/chat"):
            return httpx.Response(200, json={"message": {"content": "OK"}})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        obj = OpencodeAPIClient(base_url="http://opencode.test", model="qwen2.5:7b")
        # inject the mock client
        obj._client = client

        healthy = await obj.health_check()
        assert healthy is True

        resp = await obj.chat([{"role": "user", "content": "Hello"}], stream=False)
        assert isinstance(resp, dict)
        assert resp.get("message", {}).get("content") == "OK"
