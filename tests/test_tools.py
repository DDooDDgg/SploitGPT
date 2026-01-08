"""
Test tools module
"""

import pytest

from sploitgpt.tools import execute_tool, terminal


@pytest.mark.asyncio
async def test_terminal_echo():
    """Test terminal can run simple commands."""
    result = await terminal("echo 'hello world'")
    assert "hello world" in result


@pytest.mark.asyncio
async def test_terminal_timeout():
    """Test terminal handles timeouts."""
    result = await terminal("sleep 5", timeout=1)
    assert "timed out" in result.lower()


@pytest.mark.asyncio
async def test_execute_tool():
    """Test execute_tool routing."""
    result = await execute_tool("terminal", {"command": "whoami"})
    assert result  # Should return something


@pytest.mark.asyncio
async def test_unknown_tool():
    """Test unknown tool returns error."""
    result = await execute_tool("nonexistent_tool", {})
    assert "Unknown tool" in result


@pytest.mark.asyncio
async def test_knowledge_search_tool() -> None:
    """knowledge_search should return relevant snippets from bundled sources."""
    result = await execute_tool("knowledge_search", {"query": "gobuster dir", "top_k": 3})
    assert "gobuster" in result.lower()


@pytest.mark.asyncio
async def test_generate_wordlist_tool(monkeypatch, tmp_path):
    """generate_wordlist should run psudohash and write output."""

    # Point loot_dir to temp
    class DummySettings:
        def __init__(self, base):
            self.loot_dir = base
    dummy = DummySettings(tmp_path)
    monkeypatch.setattr("sploitgpt.tools.psudohash.get_settings", lambda: dummy)

    result = await execute_tool(
        "generate_wordlist",
        {"base": "acme", "extra_words": ["corp"], "years": None, "min_len": 4, "max_len": 8},
    )
    assert "psudohash generated wordlist" in result
    generated = list(tmp_path.glob("**/*.txt"))
    assert generated, "Expected wordlist file to be written"


@pytest.mark.asyncio
async def test_msf_info_and_sessions_tools_mocked(monkeypatch) -> None:
    """msf_info/msf_sessions should format output without requiring a real msfrpcd."""

    from sploitgpt.msf import MSFSession

    class FakeMSF:
        async def connect(self, *args, **kwargs):
            return True

        async def disconnect(self):
            return None

        async def get_module_info(self, module_type: str, module_name: str):
            assert module_type == "auxiliary"
            assert module_name == "scanner/portscan/tcp"
            return {
                "rank": "normal",
                "name": "TCP Port Scanner",
                "description": "Scans a host for open TCP ports.",
                "references": ["URL:https://example.invalid"],
            }

        async def get_module_options(self, module_type: str, module_name: str):
            return {
                "RHOSTS": {"required": True, "default": None, "desc": "Target address"},
                "PORTS": {"required": True, "default": None, "desc": "Ports to scan"},
                "THREADS": {"required": False, "default": 1, "desc": "Threads"},
            }

        async def list_sessions(self):
            return [
                MSFSession(
                    id=1,
                    type="shell",
                    tunnel_local="127.0.0.1:4444",
                    tunnel_peer="10.0.0.5:12345",
                    via_exploit="auxiliary/scanner/portscan/tcp",
                    via_payload="",
                    info="test",
                    workspace="default",
                )
            ]

    import sploitgpt.core.boot

    async def _fake_shared():
        return FakeMSF()

    monkeypatch.setattr(sploitgpt.core.boot, "get_shared_msf_client", _fake_shared)

    info = await execute_tool("msf_info", {"module": "auxiliary/scanner/portscan/tcp"})
    assert "Required options" in info
    assert "RHOSTS" in info

    sessions = await execute_tool("msf_sessions", {})
    assert "Active sessions" in sessions
    assert "#1" in sessions
