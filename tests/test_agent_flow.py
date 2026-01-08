"""Agent interaction flow tests.

These focus on the ask_user/confirm gating logic to ensure the agent
pauses for user input and resumes correctly without hitting real tools
or LLM endpoints.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from sploitgpt.agent.agent import Agent
from sploitgpt.core.boot import BootContext


def _stub_settings(tmp_path):
    """Create a minimal settings stub with isolated paths."""
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
async def test_agent_emits_choice_for_ask_user(monkeypatch, tmp_path):
    """Agent should surface ask_user tool calls as a choice."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    ask_user_response = {
        "message": {
            "content": "",
            "tool_calls": [
                {
                    "function": {
                        "name": "ask_user",
                        "arguments": {
                            "question": "Pick a path?",
                            "options": ["A", "B"],
                        },
                    }
                }
            ],
        }
    }

    monkeypatch.setattr(agent, "_call_llm", AsyncMock(return_value=ask_user_response))

    outputs = [r async for r in agent.process("enumerate 1.2.3.4")]

    assert any(r.type == "choice" for r in outputs)
    assert agent._pending is not None
    assert agent._pending.kind == "ask_user"


@pytest.mark.asyncio
async def test_agent_confirm_and_executes_tool(monkeypatch, tmp_path):
    """Agent should pause for confirmation, execute, then finish."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # LLM responses in order: initial tool call, then finish.
    responses = [
        {
            "message": {
                "content": "Running scan",
                "tool_calls": [
                    {
                        "function": {
                            "name": "terminal",
                            "arguments": {"command": "echo hi"},
                        }
                    }
                ],
            }
        },
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish",
                            "arguments": {"summary": "done", "techniques_used": ["T0000"]},
                        }
                    }
                ],
            }
        },
    ]

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    first_outputs = [r async for r in agent.process("scan 10.0.0.1")]
    assert any(r.type == "choice" for r in first_outputs)

    follow_up = [r async for r in agent.submit_choice("1")]

    assert any(r.type == "command" for r in follow_up)
    assert any(r.type == "result" for r in follow_up)
    assert any(r.type == "done" for r in follow_up)


@pytest.mark.asyncio
async def test_agent_parses_tool_call_xml_format(monkeypatch, tmp_path):
    """Agent should parse <tool_call> XML format from fine-tuned models."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # Response with <tool_call> XML format (as emitted by v3 model)
    # Using 'terminal' tool which requires confirmation
    xml_tool_call_response = {
        "message": {
            "content": 'I\'ll run nmap to scan for services.\n<tool_call>{"name": "terminal", "arguments": "{\\"command\\": \\"nmap -sV 10.0.0.1\\"}"}</tool_call>',
            "tool_calls": [],  # Empty - model uses XML format instead
        }
    }

    responses = [
        xml_tool_call_response,
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish",
                            "arguments": {"summary": "done", "techniques_used": ["T0000"]},
                        }
                    }
                ],
            }
        },
    ]

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    # Process the prompt
    first_outputs = [r async for r in agent.process("scan 10.0.0.1")]

    # Should have parsed the tool call and prompted for confirmation
    assert any(r.type == "choice" for r in first_outputs)
    assert agent._pending is not None
    assert agent._pending.tool_name == "terminal"


@pytest.mark.asyncio
async def test_agent_parses_tool_call_xml_with_dict_args(monkeypatch, tmp_path):
    """Agent should parse <tool_call> with arguments as dict (not string)."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # Response with arguments as dict directly
    xml_tool_call_response = {
        "message": {
            "content": 'Running nmap scan.\n<tool_call>{"name": "terminal", "arguments": {"command": "nmap -sV 192.168.1.1"}}</tool_call>',
            "tool_calls": [],
        }
    }

    responses = [
        xml_tool_call_response,
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "finish",
                            "arguments": {"summary": "done", "techniques_used": ["T0000"]},
                        }
                    }
                ],
            }
        },
    ]

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    first_outputs = [r async for r in agent.process("scan 192.168.1.1")]

    assert any(r.type == "choice" for r in first_outputs)
    assert agent._pending is not None
    assert agent._pending.tool_name == "terminal"


@pytest.mark.asyncio
async def test_agent_normalizes_execute_to_terminal(monkeypatch, tmp_path):
    """Agent should normalize 'execute' tool name to 'terminal'."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # Model emits 'execute' instead of 'terminal'
    xml_tool_call_response = {
        "message": {
            "content": 'Running scan.\n<tool_call>{"name": "execute", "arguments": {"command": "nmap 10.0.0.1"}}</tool_call>',
            "tool_calls": [],
        }
    }

    responses = [
        xml_tool_call_response,
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

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    first_outputs = [r async for r in agent.process("scan 10.0.0.1")]

    assert any(r.type == "choice" for r in first_outputs)
    assert agent._pending is not None
    assert agent._pending.tool_name == "terminal"


@pytest.mark.asyncio
async def test_agent_normalizes_nmap_tool(monkeypatch, tmp_path):
    """Agent should normalize 'nmap' tool name to 'terminal' and reconstruct command."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)

    # Model emits 'nmap' as tool name with target argument
    xml_tool_call_response = {
        "message": {
            "content": 'Scanning...\n<tool_call>{"name": "nmap", "arguments": {"target": "10.0.0.1", "options": "-sV -sC"}}</tool_call>',
            "tool_calls": [],
        }
    }

    responses = [
        xml_tool_call_response,
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

    async def fake_call_llm(_messages):
        return responses.pop(0)

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)
    monkeypatch.setattr(agent, "_execute_tool_call", AsyncMock(return_value="ok"))

    first_outputs = [r async for r in agent.process("nmap scan")]

    assert any(r.type == "choice" for r in first_outputs)
    assert agent._pending is not None
    assert agent._pending.tool_name == "terminal"
    # Command should be reconstructed
    assert "nmap" in agent._pending.tool_args.get("command", "")


@pytest.mark.asyncio
async def test_agent_loop_prevention_depth_limit(monkeypatch, tmp_path):
    """Agent should stop after max tool call depth."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)
    agent.autonomous = True  # Skip confirmation gate for loop testing
    agent._max_tool_depth = 3  # Low limit for testing
    agent._max_repeated_pattern = 100  # High so it doesn't trigger first

    # Mock LLM to always return a knowledge_search tool call
    def make_knowledge_response():
        return {
            "message": {
                "content": '<tool_call>{"name": "knowledge_search", "arguments": {"query": "test"}}</tool_call>',
                "tool_calls": [],
            }
        }

    async def fake_call_llm(_messages):
        return make_knowledge_response()

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)

    outputs = [r async for r in agent.process("test query")]

    # Should have hit the depth limit
    assert any(r.type == "error" and "depth" in r.content.lower() for r in outputs)


@pytest.mark.asyncio
async def test_agent_loop_prevention_repeated_tool(monkeypatch, tmp_path):
    """Agent should stop when same tool is called repeatedly."""
    settings = _stub_settings(tmp_path)
    monkeypatch.setattr("sploitgpt.agent.agent.get_settings", lambda: settings)

    ctx = BootContext()
    agent = Agent(ctx)
    agent.autonomous = True  # Skip confirmation gate for loop testing
    agent._max_repeated_pattern = 2  # Low limit for testing
    agent._max_tool_depth = 10

    # Mock LLM to always return same tool
    def make_response():
        return {
            "message": {
                "content": '<tool_call>{"name": "knowledge_search", "arguments": {"query": "test"}}</tool_call>',
                "tool_calls": [],
            }
        }

    async def fake_call_llm(_messages):
        return make_response()

    monkeypatch.setattr(agent, "_call_llm", fake_call_llm)

    outputs = [r async for r in agent.process("test")]

    # Should detect repeated pattern
    assert any(r.type == "error" and "times in a row" in r.content.lower() for r in outputs)
