"""Proposed LLM abstraction for SploitGPT (proposal only).

This file is a review-only sketch showing a clean, testable way to add
support for non-Ollama LLM providers (e.g., Opencode API) without
changing existing code. Do NOT import this file from production until
we decide to adopt it — it's placed under proposals/ for review.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncGenerator, List

import httpx

from sploitgpt.core.config import get_settings
from sploitgpt.core.ollama import OllamaClient


class BaseLLMClient(ABC):
    """Minimal interface used by Agent to interact with LLM backends."""

    @abstractmethod
    async def __aenter__(self):
        ...

    @abstractmethod
    async def __aexit__(self, exc_type, exc, tb):
        ...

    @abstractmethod
    async def chat(self, messages: List[dict[str, Any]], stream: bool = False, **kwargs: Any):
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        ...

    @abstractmethod
    async def list_models(self) -> list[str]:
        ...


class OllamaAdapter(BaseLLMClient):
    """Adapter that delegates to existing OllamaClient (no behavior change)."""

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self._client = OllamaClient(base_url=base_url, model=model)

    async def __aenter__(self):
        return self._client

    async def __aexit__(self, exc_type, exc, tb):
        await self._client.close()

    async def chat(self, messages: List[dict[str, Any]], stream: bool = False, **kwargs: Any):
        return await self._client.chat(messages, stream=stream, **kwargs)

    async def health_check(self) -> bool:
        return await self._client.health_check()

    async def list_models(self) -> list[str]:
        return await self._client.list_models()


class OpencodeAPIClient(BaseLLMClient):
    """Example client for an Opencode-like HTTP API.

    This is a simple implementation for review. Adjust endpoints/headers to
    the real provider's contract when ready to implement.
    """

    def __init__(self, base_url: str | None = None, model: str | None = None, api_key: str | None = None):
        settings = get_settings()
        self.base_url = base_url or settings.llm_api_host or settings.ollama_host
        self.model = model or settings.effective_model
        self.api_key = api_key or None
        self._client = httpx.AsyncClient(timeout=60.0)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self._client.aclose()

    async def chat(self, messages: List[dict[str, Any]], stream: bool = False, **kwargs: Any):
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            **kwargs,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        # NOTE: adapt the path to the provider's API. This is an illustrative path.
        resp = await self._client.post(f"{self.base_url}/api/v1/chat", json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        return resp.json()

    async def health_check(self) -> bool:
        try:
            r = await self._client.get(f"{self.base_url}/api/v1/models", timeout=6)
            if r.status_code == 200:
                data = r.json()
                # Provider may return different shapes; this is illustrative.
                if isinstance(data, list):
                    return any(self.model in (m.get("name") or "") for m in data)
        except Exception:
            return False
        return False

    async def list_models(self) -> list[str]:
        try:
            r = await self._client.get(f"{self.base_url}/api/v1/models", timeout=6)
            r.raise_for_status()
            data = r.json()
            if isinstance(data, list):
                return [m.get("name") or str(m) for m in data]
        except Exception:
            return []
        return []


def get_llm_client(backend: str | None = None, model: str | None = None) -> BaseLLMClient:
    settings = get_settings()
    backend = (backend or getattr(settings, "llm_backend", None) or "ollama").lower()
    if backend == "opencode":
        return OpencodeAPIClient(base_url=getattr(settings, "llm_api_host", None), model=model, api_key=getattr(settings, "llm_api_key", None))
    # default adapter wraps current OllamaClient
    return OllamaAdapter(model=model)
