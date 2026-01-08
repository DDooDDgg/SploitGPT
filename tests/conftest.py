"""
Test configuration and shared fixtures.
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest

from sploitgpt.core.boot import BootContext
from sploitgpt.msf import MSFSession


@pytest.fixture
def mock_context() -> BootContext:
    """Create a mock boot context."""
    return BootContext(
        hostname="test-host",
        username="root",
        interfaces=[{"name": "eth0", "state": "UP", "addr": "10.0.0.100/24"}],
        available_tools=["nmap", "msfconsole", "sqlmap"],
        missing_tools=[],
        known_hosts=["10.0.0.1", "10.0.0.5"],
        open_ports={"10.0.0.1": [22, 80, 443]},
        msf_connected=True,
        ollama_connected=True,
        model_loaded=True,
    )


@pytest.fixture
def stub_settings(tmp_path: Path) -> SimpleNamespace:
    """Create a minimal settings stub with isolated paths for testing."""
    settings = SimpleNamespace(
        sessions_dir=tmp_path / "sessions",
        data_dir=tmp_path / "data",
        loot_dir=tmp_path / "loot",
        effective_model="test-model",
        ollama_host="http://localhost:11434",
        confirm_actions=True,
        msf_password="test_password",
        shodan_api_key=None,
        scope_targets="",
        scope_mode="warn",
        ask_threshold=0.7,
    )
    settings.sessions_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.loot_dir.mkdir(parents=True, exist_ok=True)
    return settings


@pytest.fixture
def mock_keyring() -> MagicMock:
    """Create a mock keyring for credential tests."""
    keyring = MagicMock()
    keyring.get_password.return_value = None
    keyring.set_password.return_value = None
    keyring.delete_password.return_value = None
    return keyring


class FakeMSF:
    """Fake Metasploit client for testing."""

    async def connect(self, *args: Any, **kwargs: Any) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def get_module_info(self, module_type: str, module_name: str) -> dict[str, Any]:
        return {
            "rank": "normal",
            "name": "Test Module",
            "description": "A test module.",
            "references": [],
        }

    async def get_module_options(self, module_type: str, module_name: str) -> dict[str, Any]:
        return {
            "RHOSTS": {"required": True, "default": None, "desc": "Target address"},
        }

    async def list_sessions(self) -> list[MSFSession]:
        return [
            MSFSession(
                id=1,
                type="shell",
                tunnel_local="127.0.0.1:4444",
                tunnel_peer="10.0.0.1:54321",
                via_exploit="exploit/test",
                via_payload="payload/test",
                desc="Test session",
                info="",
                workspace="default",
                session_host="10.0.0.1",
                session_port=0,
                target_host="10.0.0.1",
                username="root",
                uuid="test-uuid",
                exploit_uuid="test-exploit-uuid",
                routes=[],
                arch="x64",
                platform="linux",
            )
        ]


@pytest.fixture
def mock_msf() -> FakeMSF:
    """Create a mock Metasploit client."""
    return FakeMSF()
