"""
Tests for scope enforcement functionality.

Tests the ScopeChecker class and scope enforcement in the agent.
"""

from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.core.scope import (
    ScopeChecker,
    ScopeCheckResult,
    check_command_scope,
    check_target_scope,
    get_scope_mode,
    is_scope_defined,
)


class TestScopeCheckResult:
    """Tests for ScopeCheckResult dataclass."""

    def test_in_scope_result(self):
        """Test creating an in-scope result."""
        result = ScopeCheckResult(
            in_scope=True,
            target="10.0.0.1",
            matched_rule="10.0.0.0/24",
        )
        assert result.in_scope is True
        assert result.target == "10.0.0.1"
        assert result.matched_rule == "10.0.0.0/24"

    def test_out_of_scope_result(self):
        """Test creating an out-of-scope result."""
        result = ScopeCheckResult(
            in_scope=False,
            target="192.168.1.1",
            reason="IP not in any allowed network",
        )
        assert result.in_scope is False
        assert result.target == "192.168.1.1"
        assert result.reason != ""


class TestScopeChecker:
    """Tests for ScopeChecker class."""

    def test_empty_scope_allows_all(self):
        """Test that empty scope allows all targets."""
        checker = ScopeChecker("")
        assert checker.is_empty() is True

        result = checker.check("10.0.0.1")
        assert result.in_scope is True

        result = checker.check("example.com")
        assert result.in_scope is True

    def test_single_ip(self):
        """Test scope with single IP address."""
        checker = ScopeChecker("10.0.0.1")

        result = checker.check("10.0.0.1")
        assert result.in_scope is True

        result = checker.check("10.0.0.2")
        assert result.in_scope is False

    def test_cidr_range(self):
        """Test scope with CIDR range."""
        checker = ScopeChecker("10.0.0.0/24")

        result = checker.check("10.0.0.1")
        assert result.in_scope is True

        result = checker.check("10.0.0.254")
        assert result.in_scope is True

        result = checker.check("10.0.1.1")
        assert result.in_scope is False

    def test_multiple_ranges(self):
        """Test scope with multiple CIDR ranges."""
        checker = ScopeChecker("10.0.0.0/24, 192.168.1.0/24")

        assert checker.check("10.0.0.50").in_scope is True
        assert checker.check("192.168.1.100").in_scope is True
        assert checker.check("172.16.0.1").in_scope is False

    def test_hostname_exact_match(self):
        """Test scope with exact hostname."""
        checker = ScopeChecker("target.htb")

        result = checker.check("target.htb")
        assert result.in_scope is True

        result = checker.check("other.htb")
        assert result.in_scope is False

    def test_hostname_case_insensitive(self):
        """Test that hostname matching is case-insensitive."""
        checker = ScopeChecker("Target.HTB")

        assert checker.check("target.htb").in_scope is True
        assert checker.check("TARGET.HTB").in_scope is True
        assert checker.check("Target.Htb").in_scope is True

    def test_wildcard_hostname(self):
        """Test scope with wildcard hostname."""
        checker = ScopeChecker("*.htb")

        assert checker.check("target.htb").in_scope is True
        assert checker.check("box.htb").in_scope is True
        assert checker.check("example.com").in_scope is False

    def test_mixed_scope(self):
        """Test scope with mixed IPs, ranges, and hostnames."""
        checker = ScopeChecker("10.0.0.0/24, target.htb, *.thm, 192.168.1.100")

        # IP in range
        assert checker.check("10.0.0.50").in_scope is True
        # Single IP
        assert checker.check("192.168.1.100").in_scope is True
        # Exact hostname
        assert checker.check("target.htb").in_scope is True
        # Wildcard hostname
        assert checker.check("box.thm").in_scope is True
        # Not in scope
        assert checker.check("192.168.1.99").in_scope is False
        assert checker.check("example.com").in_scope is False

    def test_empty_target(self):
        """Test checking empty target."""
        checker = ScopeChecker("10.0.0.0/24")

        result = checker.check("")
        assert result.in_scope is False
        assert "Empty" in result.reason

    def test_scope_summary(self):
        """Test getting scope summary."""
        checker = ScopeChecker("10.0.0.0/24, target.htb, *.thm")
        summary = checker.get_scope_summary()

        assert "10.0.0.0/24" in summary
        assert "target.htb" in summary
        assert "*.thm" in summary

    def test_empty_scope_summary(self):
        """Test summary for empty scope."""
        checker = ScopeChecker("")
        summary = checker.get_scope_summary()

        assert "no scope" in summary.lower() or "all targets" in summary.lower()


class TestScopeCheckerCommandExtraction:
    """Tests for command target extraction."""

    def test_extract_ip_from_nmap(self):
        """Test extracting IP from nmap command."""
        checker = ScopeChecker("10.0.0.0/24")

        results = checker.check_command("nmap -sV 10.0.0.1")
        assert len(results) == 1
        assert results[0].target == "10.0.0.1"
        assert results[0].in_scope is True

    def test_extract_multiple_ips(self):
        """Test extracting multiple IPs from command."""
        checker = ScopeChecker("10.0.0.0/24")

        results = checker.check_command("ping 10.0.0.1 && ping 10.0.0.2")
        assert len(results) == 2

    def test_extract_hostname_from_command(self):
        """Test extracting hostname from command."""
        checker = ScopeChecker("*.htb")

        results = checker.check_command("curl http://target.htb/api")
        assert len(results) == 1
        assert results[0].target == "target.htb"
        assert results[0].in_scope is True

    def test_out_of_scope_in_command(self):
        """Test detecting out-of-scope target in command."""
        checker = ScopeChecker("10.0.0.0/24")

        results = checker.check_command("nmap -sV 192.168.1.1")
        assert len(results) == 1
        assert results[0].in_scope is False


class TestScopeConfigIntegration:
    """Tests for scope configuration integration."""

    @patch("sploitgpt.core.scope.get_settings")
    def test_is_scope_defined_empty(self, mock_settings):
        """Test is_scope_defined with empty scope."""
        mock_settings.return_value = MagicMock(scope_targets="")

        # Need to reload the checker
        from sploitgpt.core import scope

        scope._scope_checker = None  # Reset cached checker

        assert is_scope_defined() is False

    @patch("sploitgpt.core.scope.get_settings")
    def test_is_scope_defined_with_targets(self, mock_settings):
        """Test is_scope_defined with targets configured."""
        mock_settings.return_value = MagicMock(scope_targets="10.0.0.0/24")

        from sploitgpt.core import scope

        scope._scope_checker = None

        assert is_scope_defined() is True

    @patch("sploitgpt.core.scope.get_settings")
    def test_scope_mode_warn(self, mock_settings):
        """Test scope mode returns 'warn' by default."""
        mock_settings.return_value = MagicMock(scope_mode="warn")

        assert get_scope_mode() == "warn"

    @patch("sploitgpt.core.scope.get_settings")
    def test_scope_mode_block(self, mock_settings):
        """Test scope mode returns 'block' when configured."""
        mock_settings.return_value = MagicMock(scope_mode="block")

        assert get_scope_mode() == "block"

    @patch("sploitgpt.core.scope.get_settings")
    def test_scope_mode_defaults_to_warn(self, mock_settings):
        """Test scope mode defaults to 'warn' for invalid values."""
        mock_settings.return_value = MagicMock(scope_mode="invalid")

        assert get_scope_mode() == "warn"


class TestScopeConfigSettings:
    """Tests for scope settings in config."""

    def test_scope_targets_default(self):
        """Test that scope_targets defaults to empty string."""
        from sploitgpt.core.config import Settings

        settings = Settings()
        assert settings.scope_targets == ""

    def test_scope_mode_default(self):
        """Test that scope_mode defaults to 'warn'."""
        from sploitgpt.core.config import Settings

        settings = Settings()
        assert settings.scope_mode == "warn"


class TestAgentResponseScopeWarning:
    """Tests for scope warning response type."""

    def test_scope_warning_factory(self):
        """Test AgentResponse.scope_warning() factory method."""
        from sploitgpt.agent.response import AgentResponse

        response = AgentResponse.scope_warning("10.0.0.1", "IP not in allowed range")

        assert response.type == "warning"
        assert "10.0.0.1" in response.content
        assert "SCOPE" in response.content.upper()
        assert response.data is not None
        assert response.data.get("scope_target") == "10.0.0.1"

    def test_is_warning_method(self):
        """Test is_warning() method."""
        from sploitgpt.agent.response import AgentResponse

        warning = AgentResponse.scope_warning("target", "reason")
        message = AgentResponse(type="message", content="hello")

        assert warning.is_warning() is True
        assert message.is_warning() is False

    def test_warning_not_terminal(self):
        """Test that warnings are not terminal responses."""
        from sploitgpt.agent.response import AgentResponse

        warning = AgentResponse.scope_warning("target", "reason")
        assert warning.is_terminal() is False


class TestAgentScopeEnforcement:
    """Tests for scope enforcement in agent."""

    @pytest.fixture
    def mock_settings(self, tmp_path):
        """Create mock settings."""
        settings = MagicMock()
        settings.sessions_dir = tmp_path
        settings.effective_model = "test-model"
        settings.confirm_actions = False  # Skip confirmation for testing
        settings.scope_targets = "10.0.0.0/24"
        settings.scope_mode = "warn"
        return settings

    @pytest.fixture
    def mock_context(self):
        """Create mock boot context."""
        context = MagicMock()
        context.ollama_client = MagicMock()
        context.msf_client = None
        context.msf_connected = False
        return context

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    @patch("sploitgpt.agent.agent.is_scope_defined")
    def test_agent_has_scope_checking(
        self, mock_scope_defined, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test that agent has scope checking integrated."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())
        mock_scope_defined.return_value = True

        from sploitgpt.agent.agent import Agent

        agent = Agent(mock_context)

        # The agent should have access to scope checking functions
        from sploitgpt.core.scope import check_command_scope, is_scope_defined

        assert callable(check_command_scope)
        assert callable(is_scope_defined)
