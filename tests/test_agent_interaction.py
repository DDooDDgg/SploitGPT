"""Agent interaction edge cases and LLM/tool call flows."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sploitgpt.agent.agent import Agent, PendingInteraction
from sploitgpt.core.boot import BootContext


def _stub_settings(tmp_path):
    settings = SimpleNamespace(
        sessions_dir=tmp_path / "sessions",
        data_dir=tmp_path / "data",
        loot_dir=tmp_path / "loot",
        effective_model="test-model",
        ollama_host="http://localhost:11434",
        confirm_actions=True,
    )
    settings.sessions_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.loot_dir.mkdir(parents=True, exist_ok=True)
    return settings


@pytest.mark.asyncio
async def test_agent_executes_codeblock_when_tools_not_supported(monkeypatch, tmp_path):
    """Models without tool calling should still execute parsed commands from code blocks."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    agent = Agent(BootContext())
    agent.autonomous = True  # skip confirmation gate

    # Simulate a model with no tool support emitting a bash block.
    monkeypatch.setattr(agent, "_supports_tools", lambda: False)
    monkeypatch.setattr(
        agent,
        "_call_llm",
        AsyncMock(
            side_effect=[
                {
                    "message": {
                        "content": "```bash\nwhoami\n```",
                        "tool_calls": [],
                    }
                },
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "finish",
                                    "arguments": {"summary": "done", "techniques_used": []},
                                }
                            }
                        ],
                    }
                },
            ]
        ),
    )

    exec_spy = AsyncMock(return_value="ok")
    monkeypatch.setattr(agent, "_execute_tool_call", exec_spy)

    outputs = [r async for r in agent.process("run whoami")]

    assert any(r.type == "command" and "whoami" in r.content for r in outputs)
    assert any(r.type == "result" and "ok" in r.content for r in outputs)
    assert exec_spy.await_count >= 1


@pytest.mark.asyncio
async def test_agent_invalid_choice_reprompts(monkeypatch, tmp_path):
    """Invalid selection while a choice is pending should error and re-ask."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    agent = Agent(BootContext())
    agent._pending = PendingInteraction(
        kind="ask_user",
        tool_name="ask_user",
        tool_args={"question": "Pick?", "options": ["A", "B"]},
        question="Pick?",
        options=["A", "B"],
    )

    outputs = [r async for r in agent.submit_choice("99")]

    assert any(r.type == "error" for r in outputs)
    assert any(r.type == "choice" for r in outputs)


@pytest.mark.asyncio
async def test_agent_finish_tool_returns_done(monkeypatch, tmp_path):
    """Finish tool should produce a done response."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    agent = Agent(BootContext())
    agent.autonomous = True

    monkeypatch.setattr(
        agent,
        "_call_llm",
        AsyncMock(
            return_value={
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "finish",
                                "arguments": {"summary": "all done", "techniques_used": ["T0001"]},
                            }
                        }
                    ],
                }
            }
        ),
    )

    outputs = [r async for r in agent.process("finish up")]

    assert any(r.type == "done" and "all done" in r.content for r in outputs)
