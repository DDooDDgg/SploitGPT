"""
Tests for session resume functionality.

Tests the new session state persistence and resume features.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.training.collector import (
    SessionCollector,
    SessionState,
    SessionSummary,
    SessionTurn,
)


class TestSessionState:
    """Tests for SessionState dataclass."""

    def test_session_state_defaults(self):
        """Test that SessionState has correct defaults."""
        state = SessionState(session_id="test-123")
        assert state.session_id == "test-123"
        assert state.target == ""
        assert state.lhost == ""
        assert state.current_phase == "recon"
        assert state.discovered_services == []
        assert state.discovered_hosts == []
        assert state.autonomous is False
        assert state.suid_binaries == []
        assert state.updated_at == ""

    def test_session_state_with_values(self):
        """Test SessionState with provided values."""
        state = SessionState(
            session_id="test-456",
            target="10.0.0.1",
            lhost="192.168.1.100",
            current_phase="exploit",
            discovered_services=["22/tcp ssh", "80/tcp http"],
            discovered_hosts=["10.0.0.1", "10.0.0.2"],
            autonomous=True,
            suid_binaries=["/usr/bin/find", "/usr/bin/vim"],
            updated_at="2026-01-07T12:00:00",
        )
        assert state.target == "10.0.0.1"
        assert state.lhost == "192.168.1.100"
        assert state.current_phase == "exploit"
        assert len(state.discovered_services) == 2
        assert len(state.discovered_hosts) == 2
        assert state.autonomous is True
        assert len(state.suid_binaries) == 2

    def test_session_state_none_lists_become_empty(self):
        """Test that None lists are converted to empty lists."""
        state = SessionState(
            session_id="test-789",
            discovered_services=None,
            discovered_hosts=None,
            suid_binaries=None,
        )
        assert state.discovered_services == []
        assert state.discovered_hosts == []
        assert state.suid_binaries == []


class TestSessionSummary:
    """Tests for SessionSummary dataclass."""

    def test_session_summary_creation(self):
        """Test SessionSummary creation."""
        summary = SessionSummary(
            id="sess-001",
            started_at="2026-01-07T10:00:00",
            ended_at="2026-01-07T11:00:00",
            task_description="Scan 10.0.0.1",
            successful=True,
            turn_count=15,
        )
        assert summary.id == "sess-001"
        assert summary.successful is True
        assert summary.turn_count == 15


class TestSessionCollectorResume:
    """Tests for session resume functionality in SessionCollector."""

    @pytest.fixture
    def collector(self, tmp_path):
        """Create a collector with temp database."""
        db_path = tmp_path / "test_sessions.db"
        return SessionCollector(db_path)

    def test_save_and_get_state(self, collector):
        """Test saving and retrieving session state."""
        # Start a session first
        session_id = collector.start_session("state-test", "Test state persistence")

        # Save state
        state = SessionState(
            session_id=session_id,
            target="192.168.1.10",
            lhost="192.168.1.100",
            current_phase="exploit",
            discovered_services=["22/tcp ssh", "80/tcp http", "443/tcp https"],
            discovered_hosts=["192.168.1.10"],
            autonomous=True,
            suid_binaries=["/usr/bin/find"],
        )
        collector.save_state(state)

        # Retrieve state
        retrieved = collector.get_state(session_id)
        assert retrieved is not None
        assert retrieved.session_id == session_id
        assert retrieved.target == "192.168.1.10"
        assert retrieved.lhost == "192.168.1.100"
        assert retrieved.current_phase == "exploit"
        assert retrieved.discovered_services == ["22/tcp ssh", "80/tcp http", "443/tcp https"]
        assert retrieved.discovered_hosts == ["192.168.1.10"]
        assert retrieved.autonomous is True
        assert retrieved.suid_binaries == ["/usr/bin/find"]
        assert retrieved.updated_at != ""

    def test_save_state_updates_existing(self, collector):
        """Test that saving state updates existing record."""
        session_id = collector.start_session("update-test", "Test state update")

        # Initial state
        state1 = SessionState(
            session_id=session_id,
            target="10.0.0.1",
            current_phase="recon",
        )
        collector.save_state(state1)

        # Updated state
        state2 = SessionState(
            session_id=session_id,
            target="10.0.0.1",
            current_phase="exploit",
            discovered_services=["22/tcp ssh"],
        )
        collector.save_state(state2)

        # Should have updated, not duplicated
        retrieved = collector.get_state(session_id)
        assert retrieved is not None
        assert retrieved.current_phase == "exploit"
        assert retrieved.discovered_services == ["22/tcp ssh"]

    def test_get_state_nonexistent(self, collector):
        """Test getting state for nonexistent session returns None."""
        result = collector.get_state("nonexistent-session")
        assert result is None

    def test_list_sessions_empty(self, collector):
        """Test listing sessions when none exist."""
        sessions = collector.list_sessions()
        assert sessions == []

    def test_list_sessions_returns_summaries(self, collector):
        """Test listing sessions returns SessionSummary objects."""
        # Create a few sessions
        for i in range(3):
            sid = collector.start_session(f"list-test-{i}", f"Task {i}")
            collector.add_turn(sid, SessionTurn(role="user", content=f"Message {i}"))
            collector.add_turn(sid, SessionTurn(role="assistant", content=f"Response {i}"))
            if i < 2:  # End first 2 sessions
                collector.end_session(sid, successful=(i == 0), rating=4)

        sessions = collector.list_sessions()
        assert len(sessions) == 3

        # Check structure
        for session in sessions:
            assert isinstance(session, SessionSummary)
            assert session.id.startswith("list-test-")
            assert session.started_at != ""
            assert session.turn_count == 2

    def test_list_sessions_ordered_by_recency(self, collector):
        """Test sessions are ordered most recent first."""
        # Create sessions with known order
        ids = []
        for i in range(3):
            sid = collector.start_session(f"order-{i}", f"Task {i}")
            ids.append(sid)
            collector.add_turn(sid, SessionTurn(role="user", content="test"))

        sessions = collector.list_sessions()
        # Most recent (order-2) should be first
        assert sessions[0].id == "order-2"
        assert sessions[1].id == "order-1"
        assert sessions[2].id == "order-0"

    def test_list_sessions_respects_limit(self, collector):
        """Test list_sessions respects limit parameter."""
        for i in range(10):
            sid = collector.start_session(f"limit-{i}", f"Task {i}")
            collector.add_turn(sid, SessionTurn(role="user", content="test"))

        sessions = collector.list_sessions(limit=5)
        assert len(sessions) == 5

    def test_resume_session_success(self, collector):
        """Test resuming a session clears ended_at."""
        session_id = collector.start_session("resume-test", "Test resume")
        collector.add_turn(session_id, SessionTurn(role="user", content="test"))
        collector.end_session(session_id, successful=False, rating=3)

        # Verify it's ended
        session = collector.get_session(session_id)
        assert session["session"]["ended_at"] is not None

        # Resume
        result = collector.resume_session(session_id)
        assert result is True

        # Verify ended_at is cleared
        session = collector.get_session(session_id)
        assert session["session"]["ended_at"] is None

    def test_resume_session_nonexistent(self, collector):
        """Test resuming nonexistent session returns False."""
        result = collector.resume_session("nonexistent-session")
        assert result is False

    def test_turns_to_conversation_user_messages(self, collector):
        """Test converting user turns to conversation format."""
        turns = [
            {"role": "user", "content": "Hello", "tool_calls": None, "tool_name": None},
            {"role": "user", "content": "Scan the target", "tool_calls": None, "tool_name": None},
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 2
        assert conversation[0] == {"role": "user", "content": "Hello"}
        assert conversation[1] == {"role": "user", "content": "Scan the target"}

    def test_turns_to_conversation_assistant_messages(self, collector):
        """Test converting assistant turns to conversation format."""
        turns = [
            {
                "role": "assistant",
                "content": "I'll scan the target.",
                "tool_calls": None,
                "tool_name": None,
            },
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 1
        assert conversation[0] == {"role": "assistant", "content": "I'll scan the target."}

    def test_turns_to_conversation_with_tool_calls(self, collector):
        """Test converting assistant turns with tool calls."""
        tool_calls = json.dumps([{"name": "terminal", "arguments": {"command": "nmap 10.0.0.1"}}])
        turns = [
            {"role": "assistant", "content": None, "tool_calls": tool_calls, "tool_name": None},
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 1
        assert conversation[0]["role"] == "assistant"
        assert conversation[0]["content"] is None
        assert "tool_calls" in conversation[0]
        assert conversation[0]["tool_calls"][0]["name"] == "terminal"

    def test_turns_to_conversation_tool_results(self, collector):
        """Test converting tool result turns."""
        turns = [
            {
                "role": "tool",
                "content": "PORT 22/tcp open ssh",
                "tool_calls": None,
                "tool_name": "terminal",
            },
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 1
        assert conversation[0] == {
            "role": "tool",
            "content": "PORT 22/tcp open ssh",
            "name": "terminal",
        }

    def test_turns_to_conversation_full_exchange(self, collector):
        """Test converting a full conversation exchange."""
        tool_calls = json.dumps(
            [{"name": "terminal", "arguments": {"command": "nmap -sV 10.0.0.1"}}]
        )
        turns = [
            {"role": "user", "content": "Scan 10.0.0.1", "tool_calls": None, "tool_name": None},
            {
                "role": "assistant",
                "content": "Running nmap...",
                "tool_calls": tool_calls,
                "tool_name": None,
            },
            {
                "role": "tool",
                "content": "22/tcp open ssh OpenSSH 8.2",
                "tool_calls": None,
                "tool_name": "terminal",
            },
            {
                "role": "assistant",
                "content": "Found SSH on port 22.",
                "tool_calls": None,
                "tool_name": None,
            },
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 4
        assert conversation[0]["role"] == "user"
        assert conversation[1]["role"] == "assistant"
        assert "tool_calls" in conversation[1]
        assert conversation[2]["role"] == "tool"
        assert conversation[3]["role"] == "assistant"
        assert "tool_calls" not in conversation[3]

    def test_turns_to_conversation_handles_empty_content(self, collector):
        """Test that empty content is handled correctly."""
        turns = [
            {"role": "user", "content": "", "tool_calls": None, "tool_name": None},
            {"role": "assistant", "content": None, "tool_calls": None, "tool_name": None},
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 2
        assert conversation[0]["content"] == ""
        assert conversation[1]["content"] == ""  # None becomes ""

    def test_turns_to_conversation_invalid_json_tool_calls(self, collector):
        """Test that invalid JSON in tool_calls is handled gracefully."""
        turns = [
            {
                "role": "assistant",
                "content": "test",
                "tool_calls": "invalid json",
                "tool_name": None,
            },
        ]

        conversation = collector.turns_to_conversation(turns)

        assert len(conversation) == 1
        assert conversation[0]["role"] == "assistant"
        assert conversation[0]["content"] == "test"
        # Should not have tool_calls since JSON parsing failed
        assert "tool_calls" not in conversation[0]


class TestAgentSessionResume:
    """Tests for Agent session resume functionality."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock boot context."""
        context = MagicMock()
        context.ollama_client = MagicMock()
        context.msf_client = None
        return context

    @pytest.fixture
    def mock_settings(self, tmp_path):
        """Create mock settings with temp directory."""
        settings = MagicMock()
        settings.sessions_dir = tmp_path
        settings.ollama_model = "test-model"
        settings.max_tokens = 4096
        settings.temperature = 0.7
        settings.confirm_commands = True
        settings.confirm_exploits = True
        settings.auto_confirm_safe = True
        settings.history_context_turns = 10
        return settings

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_agent_save_state(
        self, mock_builder, mock_get_settings, mock_context, mock_settings, tmp_path
    ):
        """Test Agent.save_state() persists state correctly."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        from sploitgpt.agent.agent import Agent

        agent = Agent(mock_context)
        agent.target = "10.0.0.5"
        agent.lhost = "192.168.1.50"
        agent.current_phase = "post-exploit"
        agent.discovered_services = ["22/tcp ssh", "80/tcp http"]
        agent.discovered_hosts = ["10.0.0.5", "10.0.0.6"]
        agent.autonomous = True

        # Save state
        agent.save_state()

        # Verify state was saved
        from sploitgpt.training.collector import SessionCollector

        collector = SessionCollector(tmp_path / "sessions.db")
        state = collector.get_state(agent.session_id)

        assert state is not None
        assert state.target == "10.0.0.5"
        assert state.lhost == "192.168.1.50"
        assert state.current_phase == "post-exploit"
        assert state.discovered_services == ["22/tcp ssh", "80/tcp http"]
        assert state.autonomous is True

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_agent_from_session_not_found(
        self, mock_builder, mock_get_settings, mock_context, mock_settings
    ):
        """Test Agent.from_session() returns None for nonexistent session."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        from sploitgpt.agent.agent import Agent

        result = Agent.from_session("nonexistent-id", mock_context)
        assert result is None

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_agent_from_session_restores_state(
        self, mock_builder, mock_get_settings, mock_context, mock_settings, tmp_path
    ):
        """Test Agent.from_session() restores agent state correctly."""
        mock_get_settings.return_value = mock_settings
        builder = MagicMock(suid_binaries=set())
        mock_builder.return_value = builder

        from sploitgpt.agent.agent import Agent
        from sploitgpt.training.collector import SessionCollector, SessionState, SessionTurn

        # Create a session with data
        collector = SessionCollector(tmp_path / "sessions.db")
        session_id = collector.start_session("restore-test", "Test restore")

        # Add some turns
        collector.add_turn(session_id, SessionTurn(role="user", content="Scan the target"))
        collector.add_turn(session_id, SessionTurn(role="assistant", content="Running nmap..."))

        # Save state
        state = SessionState(
            session_id=session_id,
            target="172.16.0.1",
            lhost="172.16.0.100",
            current_phase="exploit",
            discovered_services=["22/tcp ssh"],
            discovered_hosts=["172.16.0.1"],
            autonomous=False,
            suid_binaries=["/usr/bin/find"],
        )
        collector.save_state(state)
        collector.end_session(session_id, successful=False, rating=3)

        # Restore agent
        agent = Agent.from_session(session_id, mock_context)

        assert agent is not None
        assert agent.session_id == session_id
        assert agent.target == "172.16.0.1"
        assert agent.lhost == "172.16.0.100"
        assert agent.current_phase == "exploit"
        assert agent.discovered_services == ["22/tcp ssh"]
        assert agent.autonomous is False

        # Verify conversation was restored
        assert len(agent.conversation) == 2
        assert agent.conversation[0]["role"] == "user"
        assert agent.conversation[1]["role"] == "assistant"

    @patch("sploitgpt.agent.agent.get_settings")
    @patch("sploitgpt.agent.agent.get_context_builder")
    def test_agent_from_session_resumes_session(
        self, mock_builder, mock_get_settings, mock_context, mock_settings, tmp_path
    ):
        """Test Agent.from_session() marks session as active again."""
        mock_get_settings.return_value = mock_settings
        mock_builder.return_value = MagicMock(suid_binaries=set())

        from sploitgpt.agent.agent import Agent
        from sploitgpt.training.collector import SessionCollector, SessionTurn

        # Create and end a session
        collector = SessionCollector(tmp_path / "sessions.db")
        session_id = collector.start_session("resume-active-test", "Test")
        collector.add_turn(session_id, SessionTurn(role="user", content="test"))
        collector.end_session(session_id, successful=False, rating=3)

        # Verify ended
        session = collector.get_session(session_id)
        assert session["session"]["ended_at"] is not None

        # Restore agent
        agent = Agent.from_session(session_id, mock_context)
        assert agent is not None

        # Verify session is active again
        session = collector.get_session(session_id)
        assert session["session"]["ended_at"] is None
