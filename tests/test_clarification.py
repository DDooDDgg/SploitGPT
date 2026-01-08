"""
Tests for clarification/ask threshold functionality.

Tests the _should_clarify() method and clarification handling.
"""

from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.agent.agent import Agent
from sploitgpt.core.boot import BootContext


class TestShouldClarify:
    """Tests for _should_clarify() method."""

    @pytest.fixture
    def mock_settings(self, tmp_path):
        """Create mock settings with temp directory."""
        settings = MagicMock()
        settings.sessions_dir = tmp_path
        settings.ollama_model = "test-model"
        settings.effective_model = "test-model"
        settings.max_tokens = 4096
        settings.temperature = 0.7
        settings.confirm_commands = True
        settings.confirm_exploits = True
        settings.auto_confirm_safe = True
        settings.history_context_turns = 10
        settings.ask_threshold = 0.7
        return settings

    @pytest.fixture
    def mock_context(self):
        """Create a mock boot context."""
        context = MagicMock(spec=BootContext)
        context.ollama_client = MagicMock()
        context.msf_client = None
        context.msf_connected = False
        context.ollama_connected = True
        context.model_loaded = True
        context.known_hosts = []
        return context

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_no_clarify_for_simple_questions(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that simple questions don't trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)

        # Simple questions shouldn't trigger clarification
        assert agent._should_clarify("What is nmap?") is None
        assert agent._should_clarify("How do I use gobuster?") is None
        assert agent._should_clarify("Help me understand SQL injection") is None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_no_clarify_with_ip_in_input(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that requests with IP addresses don't trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)

        # Requests with IPs should proceed without clarification
        assert agent._should_clarify("Scan 10.0.0.1") is None
        assert agent._should_clarify("Exploit 192.168.1.100") is None
        assert agent._should_clarify("Attack 172.16.0.50 with nmap") is None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_no_clarify_with_hostname_in_input(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that requests with hostnames don't trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)

        # Requests with hostnames should proceed
        assert agent._should_clarify("Scan target.htb") is None
        assert agent._should_clarify("Attack box.local") is None
        assert agent._should_clarify("Enumerate server.thm") is None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_no_clarify_when_target_set(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that requests don't trigger clarification when target is already set."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)
        agent.target = "10.0.0.1"

        # With target set, even vague requests should proceed
        assert agent._should_clarify("Exploit the target") is None
        assert agent._should_clarify("Get a shell on the box") is None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_clarify_for_high_risk_operations(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that destructive operations trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)

        # High-risk operations should trigger clarification
        result = agent._should_clarify("Delete all files on the server")
        assert result is not None
        question, options = result
        assert "destructive" in question.lower()

        result = agent._should_clarify("Wipe the database")
        assert result is not None

        result = agent._should_clarify("rm -rf /var/www")
        assert result is not None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_clarify_for_exploit_without_target(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that exploit requests without target trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)
        agent.target = None

        # Explicit target reference without a target should trigger clarification
        result = agent._should_clarify("Exploit the target with EternalBlue")
        assert result is not None
        question, options = result
        assert "target" in question.lower()

        result = agent._should_clarify("Get a shell on the box")
        assert result is not None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_no_clarify_for_normal_scan(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that normal scan requests without explicit target don't trigger clarification."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        agent = Agent(mock_context)

        # Generic scan requests should let LLM handle ambiguity
        assert agent._should_clarify("scan with nmap") is None
        assert agent._should_clarify("run a port scan") is None
        assert agent._should_clarify("enumerate services") is None


class TestAskThresholdConfig:
    """Tests for ask_threshold configuration."""

    def test_ask_threshold_exists_in_settings(self):
        """Test that ask_threshold is defined in settings."""
        from sploitgpt.core.config import Settings

        settings = Settings()
        assert hasattr(settings, "ask_threshold")
        assert isinstance(settings.ask_threshold, float)

    def test_ask_threshold_default_value(self):
        """Test ask_threshold has a reasonable default."""
        from sploitgpt.core.config import Settings

        settings = Settings()
        # Should be between 0 and 1
        assert 0.0 <= settings.ask_threshold <= 1.0
        # Default should be 0.7 as specified
        assert settings.ask_threshold == 0.7
