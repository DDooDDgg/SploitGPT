"""
Tests for training data collection and export
"""

import json

import pytest

from sploitgpt.training.collector import SessionCollector, SessionTurn


class TestSessionCollector:
    """Tests for the session data collector."""
    
    @pytest.fixture
    def collector(self, tmp_path):
        """Create a collector with temp database."""
        db_path = tmp_path / "test_sessions.db"
        return SessionCollector(db_path)
    
    def test_start_session(self, collector):
        """Test starting a new session."""
        session_id = collector.start_session("test-123", "Test task")
        assert session_id == "test-123"
    
    def test_add_turns(self, collector):
        """Test adding turns to a session."""
        session_id = collector.start_session("test-turns", "Test turns")
        
        # Add user turn
        collector.add_turn(session_id, SessionTurn(
            role="user",
            content="Scan the target"
        ))
        
        # Add assistant turn with tool call
        collector.add_turn(session_id, SessionTurn(
            role="assistant",
            content="Running nmap...",
            tool_calls=[{"name": "terminal", "arguments": {"command": "nmap 10.0.0.1"}}]
        ))
        
        # Add tool result
        collector.add_turn(session_id, SessionTurn(
            role="tool",
            content="PORT 22/tcp open ssh",
            tool_name="terminal"
        ))
        
        # Retrieve session
        session = collector.get_session(session_id)
        assert session is not None
        assert len(session["turns"]) == 3
    
    def test_end_session_with_feedback(self, collector):
        """Test ending a session with feedback."""
        session_id = collector.start_session("test-feedback", "Test feedback")
        collector.add_turn(session_id, SessionTurn(role="user", content="Hello"))
        
        collector.end_session(session_id, successful=True, rating=5)
        
        session = collector.get_session(session_id)
        assert session["session"]["successful"] == 1
        assert session["session"]["rating"] == 5
    
    def test_export_training_data(self, collector, tmp_path):
        """Test exporting sessions as training data."""
        # Create a successful, high-rated session
        session_id = collector.start_session("test-export", "Export test")
        
        collector.add_turn(session_id, SessionTurn(
            role="user",
            content="Enumerate the target"
        ))
        collector.add_turn(session_id, SessionTurn(
            role="assistant",
            content="I'll run nmap to discover services.",
            tool_calls=[{"name": "terminal", "arguments": {"command": "nmap -sV 10.0.0.1"}}]
        ))
        collector.add_turn(session_id, SessionTurn(
            role="tool",
            content="22/tcp open ssh OpenSSH 8.2",
            tool_name="terminal"
        ))
        collector.add_turn(session_id, SessionTurn(
            role="assistant",
            content="Found SSH on port 22."
        ))
        
        collector.end_session(session_id, successful=True, rating=5)
        
        # Export
        output_path = tmp_path / "training.jsonl"
        count = collector.export_for_training(output_path, min_rating=4)
        
        assert count == 1
        assert output_path.exists()
        
        # Verify format
        with open(output_path) as f:
            data = json.loads(f.readline())
            assert "messages" in data
            assert len(data["messages"]) >= 4  # system + user + assistant + tool
    
    def test_low_rated_sessions_not_exported(self, collector, tmp_path):
        """Test that low-rated sessions are not exported."""
        session_id = collector.start_session("test-low-rated", "Low rated")
        collector.add_turn(session_id, SessionTurn(role="user", content="Bad session"))
        collector.end_session(session_id, successful=False, rating=2)
        
        output_path = tmp_path / "training.jsonl"
        count = collector.export_for_training(output_path, min_rating=4)
        
        assert count == 0
    
    def test_stats(self, collector):
        """Test getting collection stats."""
        # Create some sessions
        for i in range(5):
            sid = collector.start_session(f"stats-{i}", f"Session {i}")
            collector.add_turn(sid, SessionTurn(role="user", content=f"Message {i}"))
            collector.end_session(sid, successful=(i % 2 == 0), rating=3 + i % 3)
        
        stats = collector.get_stats()
        
        assert stats["total_sessions"] == 5
        assert stats["successful_sessions"] >= 2
        assert stats["total_turns"] == 5
