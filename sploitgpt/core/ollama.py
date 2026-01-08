"""
Direct Ollama API Client

Lightweight, direct connection to Ollama optimized for pentesting workflows.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any, Literal, cast, overload

import httpx

from sploitgpt.core.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class OllamaMessage:
    """Represents a message in Ollama format."""

    role: str  # system, user, assistant
    content: str


@dataclass
class OllamaResponse:
    """Represents an Ollama response."""

    content: str
    done: bool = True
    total_duration: int | None = None
    eval_count: int | None = None


class OllamaClient:
    """Direct Ollama API client optimized for SploitGPT."""

    def __init__(self, base_url: str | None = None, model: str | None = None):
        settings = get_settings()
        self.base_url = base_url or settings.ollama_host
        self.model = model or settings.effective_model
        self.client = httpx.AsyncClient(timeout=300.0)

    async def __aenter__(self) -> OllamaClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()

    async def health_check(self) -> bool:
        """Check if Ollama is available and the model is loaded."""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            if response.status_code != 200:
                return False

            tags = response.json()
            model_names = [model["name"] for model in tags.get("models", [])]

            # Handle different model name formats (qwen2.5:32b vs qwen2.5:32b-instruct)
            model_available = any(
                self.model in name or name.startswith(self.model.split(":")[0])
                for name in model_names
            )

            if not model_available:
                logger.warning("Model %s not found. Available: %s", self.model, model_names)
                return False

            return True

        except Exception:
            logger.exception("Ollama health check failed")
            return False

    @overload
    async def chat(
        self,
        messages: list[dict[str, Any]],
        stream: Literal[False] = False,
        **kwargs: Any,
    ) -> dict[str, Any]: ...

    @overload
    async def chat(
        self,
        messages: list[dict[str, Any]],
        stream: Literal[True],
        **kwargs: Any,
    ) -> AsyncGenerator[OllamaResponse, None]: ...

    async def chat(
        self,
        messages: list[dict[str, Any]],
        stream: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any] | AsyncGenerator[OllamaResponse, None]:
        """Send a chat completion request to Ollama."""

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": stream,
            "options": {
                "temperature": kwargs.get("temperature", 0.1),
                "top_p": kwargs.get("top_p", 0.9),
                # Default context trimmed to reduce VRAM while staying usable.
                "num_ctx": kwargs.get("num_ctx", 3072),
            },
        }
        # TEMP DISABLED: v5 model doesn't support Ollama tool format
        # Tools are disabled for v5/v5.1 models which emit <tool_call> XML instead
        # of Ollama's native tools schema.
        # tools = kwargs.get("tools")
        # if tools:
        #     payload["tools"] = tools

        if stream:
            # For streaming, use httpx stream context manager
            return self._handle_stream_response(payload)
        else:
            try:
                response = await self.client.post(f"{self.base_url}/api/chat", json=payload)
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                logger.error(
                    f"Ollama API error. Status: {e.response.status_code}, Body: {e.response.text[:500]}"
                )
                logger.error(f"Request payload: {json.dumps(payload, indent=2)[:1000]}")
                raise
            return cast(dict[str, Any], response.json())

    def _handle_response(self, data: dict[str, Any]) -> OllamaResponse:
        """Parse Ollama response."""
        message = data.get("message", {})

        return OllamaResponse(
            content=message.get("content", ""),
            done=data.get("done", True),
            total_duration=data.get("total_duration"),
            eval_count=data.get("eval_count"),
        )

    async def _handle_stream_response(
        self, payload: dict[str, Any]
    ) -> AsyncGenerator[OllamaResponse, None]:
        """Handle streaming response from Ollama with basic buffering."""
        try:
            async with self.client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as response:
                response.raise_for_status()
                buffer = ""
                async for chunk in response.aiter_text():
                    buffer += chunk
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            # Incomplete JSON; prepend back to buffer and read more
                            buffer = line + "\n" + buffer
                            break
                        yield self._handle_response(data)
                        if data.get("done"):
                            return
        except httpx.HTTPStatusError as e:
            logger.error(f"Ollama streaming error. Status: {e.response.status_code}")
            logger.error(f"Request payload: {json.dumps(payload, indent=2)[:1000]}")
            raise

    async def list_models(self) -> list[str]:
        """List available models."""
        try:
            response = await self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            tags = response.json()
            return [model["name"] for model in tags.get("models", [])]
        except Exception:
            logger.exception("Error listing models")
            return []


async def test_ollama_connection() -> dict[str, Any]:
    """Test Ollama connection and return status info."""
    async with OllamaClient() as client:
        models = await client.list_models()
        healthy = await client.health_check()

        return {
            "connected": len(models) > 0,
            "healthy": healthy,
            "models": models,
            "target_model": client.model,
        }
