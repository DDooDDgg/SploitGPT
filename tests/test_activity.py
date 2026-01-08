"""
Tests for activity tracking and real-time activity panel.

Tests the new activity response type and helper methods.
"""

import pytest

from sploitgpt.agent.response import AgentResponse


class TestActivityResponse:
    """Tests for activity response type and factory methods."""

    def test_activity_response_type(self):
        """Test basic activity response creation."""
        response = AgentResponse(
            type="activity",
            activity_type="start",
            tool_name="terminal",
            content="Running nmap...",
        )
        assert response.type == "activity"
        assert response.activity_type == "start"
        assert response.tool_name == "terminal"
        assert response.content == "Running nmap..."

    def test_is_activity_method(self):
        """Test is_activity() method."""
        activity = AgentResponse(type="activity", activity_type="start", tool_name="terminal")
        message = AgentResponse(type="message", content="Hello")

        assert activity.is_activity() is True
        assert message.is_activity() is False

    def test_activity_start_factory(self):
        """Test activity_start() factory method."""
        response = AgentResponse.activity_start("terminal", "Running nmap scan...")

        assert response.type == "activity"
        assert response.activity_type == "start"
        assert response.tool_name == "terminal"
        assert response.content == "Running nmap scan..."

    def test_activity_start_default_content(self):
        """Test activity_start() with default content."""
        response = AgentResponse.activity_start("msf_search")

        assert response.type == "activity"
        assert response.activity_type == "start"
        assert response.tool_name == "msf_search"
        assert "msf_search" in response.content

    def test_activity_complete_factory(self):
        """Test activity_complete() factory method."""
        response = AgentResponse.activity_complete("terminal", 5.5, "Scan finished")

        assert response.type == "activity"
        assert response.activity_type == "complete"
        assert response.tool_name == "terminal"
        assert response.elapsed_seconds == 5.5
        assert response.content == "Scan finished"

    def test_activity_complete_default_content(self):
        """Test activity_complete() with default content."""
        response = AgentResponse.activity_complete("terminal", 3.7)

        assert response.type == "activity"
        assert response.activity_type == "complete"
        assert response.elapsed_seconds == 3.7
        assert "terminal" in response.content
        assert "3.7" in response.content

    def test_activity_heartbeat_factory(self):
        """Test activity_heartbeat() factory method."""
        response = AgentResponse.activity_heartbeat("terminal", 30.0, "Still scanning...")

        assert response.type == "activity"
        assert response.activity_type == "heartbeat"
        assert response.tool_name == "terminal"
        assert response.elapsed_seconds == 30.0
        assert response.content == "Still scanning..."

    def test_activity_heartbeat_default_content(self):
        """Test activity_heartbeat() with default content."""
        response = AgentResponse.activity_heartbeat("terminal", 60.0)

        assert response.type == "activity"
        assert response.activity_type == "heartbeat"
        assert "terminal" in response.content
        assert "60" in response.content


class TestActivityResponseNotTerminal:
    """Tests for activity responses interaction with other methods."""

    def test_activity_is_not_terminal(self):
        """Test that activity responses are not terminal."""
        activity = AgentResponse.activity_start("terminal")
        assert activity.is_terminal() is False

        complete = AgentResponse.activity_complete("terminal", 1.0)
        assert complete.is_terminal() is False

    def test_activity_is_not_interactive(self):
        """Test that activity responses are not interactive."""
        activity = AgentResponse.activity_start("terminal")
        assert activity.is_interactive() is False

    def test_done_is_terminal(self):
        """Test that done responses are still terminal."""
        done = AgentResponse(type="done", content="Task complete")
        assert done.is_terminal() is True

    def test_error_is_terminal(self):
        """Test that error responses are still terminal."""
        error = AgentResponse(type="error", content="Failed")
        assert error.is_terminal() is True


class TestResponseTypeEnum:
    """Tests for the ResponseType literal."""

    def test_all_response_types_valid(self):
        """Test all documented response types are valid."""
        valid_types = [
            "message",
            "command",
            "result",
            "choice",
            "error",
            "done",
            "info",
            "activity",
        ]

        for response_type in valid_types:
            response = AgentResponse(type=response_type)  # type: ignore
            assert response.type == response_type


class TestHeartbeatConstant:
    """Tests for heartbeat configuration."""

    def test_heartbeat_interval_exists(self):
        """Test that HEARTBEAT_INTERVAL constant exists."""
        from sploitgpt.agent.agent import HEARTBEAT_INTERVAL

        assert HEARTBEAT_INTERVAL is not None
        assert isinstance(HEARTBEAT_INTERVAL, (int, float))

    def test_heartbeat_interval_reasonable(self):
        """Test that heartbeat interval is a reasonable value."""
        from sploitgpt.agent.agent import HEARTBEAT_INTERVAL

        # Should be between 5 seconds and 5 minutes
        assert HEARTBEAT_INTERVAL >= 5.0
        assert HEARTBEAT_INTERVAL <= 300.0

    def test_heartbeat_interval_is_30_seconds(self):
        """Test that heartbeat interval is 30 seconds as specified."""
        from sploitgpt.agent.agent import HEARTBEAT_INTERVAL

        assert HEARTBEAT_INTERVAL == 30.0


class TestActivityPanel:
    """Tests for ActivityPanel widget."""

    def test_activity_panel_import(self):
        """Test that ActivityPanel can be imported."""
        from sploitgpt.tui.app import ActivityPanel

        assert ActivityPanel is not None

    def test_activity_panel_creation(self):
        """Test creating an ActivityPanel instance."""
        from sploitgpt.tui.app import ActivityPanel

        panel = ActivityPanel()
        assert panel.activities is not None
        assert panel._current_tool is None
        assert panel._current_start is None

    def test_activity_panel_add_start(self):
        """Test adding a start activity."""
        from sploitgpt.tui.app import ActivityPanel

        panel = ActivityPanel()
        panel.add_activity("start", "terminal", "Running nmap...")

        assert panel._current_tool == "terminal"
        assert len(panel.activities) == 1
        assert panel.activities[0]["type"] == "start"
        assert panel.activities[0]["tool"] == "terminal"

    def test_activity_panel_add_complete(self):
        """Test adding a complete activity clears current tool."""
        from sploitgpt.tui.app import ActivityPanel

        panel = ActivityPanel()
        panel.add_activity("start", "terminal", "Running...")
        panel.add_activity("complete", "terminal", "Done", elapsed=5.5)

        assert panel._current_tool is None
        assert len(panel.activities) == 2
        assert panel.activities[1]["type"] == "complete"
        assert panel.activities[1]["elapsed"] == 5.5

    def test_activity_panel_add_heartbeat(self):
        """Test adding a heartbeat keeps current tool."""
        from sploitgpt.tui.app import ActivityPanel

        panel = ActivityPanel()
        panel.add_activity("start", "terminal", "Running...")
        panel.add_activity("heartbeat", "terminal", "Still running...", elapsed=30.0)

        # Heartbeat should not clear current tool
        assert panel._current_tool == "terminal"
        assert len(panel.activities) == 2
        assert panel.activities[1]["type"] == "heartbeat"

    def test_activity_panel_max_entries(self):
        """Test that activity panel respects max entries."""
        from sploitgpt.tui.app import ActivityPanel, MAX_ACTIVITY_ENTRIES

        panel = ActivityPanel()

        # Add more than max entries
        for i in range(MAX_ACTIVITY_ENTRIES + 10):
            panel.add_activity("start", f"tool_{i}", f"Running {i}...")
            panel.add_activity("complete", f"tool_{i}", f"Done {i}", elapsed=1.0)

        # Should only keep MAX_ACTIVITY_ENTRIES
        assert len(panel.activities) == MAX_ACTIVITY_ENTRIES

    def test_activity_panel_clear(self):
        """Test clearing activity panel."""
        from sploitgpt.tui.app import ActivityPanel

        panel = ActivityPanel()
        panel.add_activity("start", "terminal", "Running...")
        panel.add_activity("complete", "terminal", "Done", elapsed=1.0)

        panel.clear_activities()

        assert len(panel.activities) == 0
        assert panel._current_tool is None
        assert panel._current_start is None
