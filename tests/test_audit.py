"""
Tests for audit logging functionality.

Tests the AuditLogger class and audit event logging.
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.core.audit import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    clear_audit_context,
    get_audit_logger,
    reset_audit_logger,
    set_audit_context,
)


@pytest.fixture(autouse=True)
def reset_audit_singleton():
    """Reset the audit logger singleton before each test."""
    reset_audit_logger()
    clear_audit_context()
    yield
    reset_audit_logger()
    clear_audit_context()


class TestAuditEventType:
    """Tests for AuditEventType enum."""

    def test_event_types_exist(self):
        """Test that all expected event types exist."""
        assert AuditEventType.SESSION_START.value == "session_start"
        assert AuditEventType.SESSION_END.value == "session_end"
        assert AuditEventType.TOOL_CALL.value == "tool_call"
        assert AuditEventType.TOOL_RESULT.value == "tool_result"
        assert AuditEventType.SCOPE_WARNING.value == "scope_warning"
        assert AuditEventType.SCOPE_VIOLATION.value == "scope_violation"
        assert AuditEventType.LLM_CALL.value == "llm_call"
        assert AuditEventType.CREDENTIAL_ACCESS.value == "credential_access"
        assert AuditEventType.ERROR.value == "error"


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_audit_event_creation(self):
        """Test creating an AuditEvent."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            tool_name="terminal",
            args={"command": "nmap -sV 10.0.0.1"},
            session_id="test-123",
        )
        assert event.event_type == AuditEventType.TOOL_CALL
        assert event.tool_name == "terminal"
        assert event.session_id == "test-123"
        assert event.timestamp is not None

    def test_audit_event_to_dict(self):
        """Test converting AuditEvent to dictionary."""
        event = AuditEvent(
            event_type=AuditEventType.TOOL_CALL,
            tool_name="terminal",
            session_id="test-123",
        )
        d = event.to_dict()
        assert d["event_type"] == "tool_call"
        assert d["tool_name"] == "terminal"
        assert d["session_id"] == "test-123"
        # None values should be excluded
        assert "result_preview" not in d
        assert "error" not in d

    def test_audit_event_to_json(self):
        """Test converting AuditEvent to JSON."""
        event = AuditEvent(
            event_type=AuditEventType.ERROR,
            error="Something went wrong",
        )
        json_str = event.to_json()
        parsed = json.loads(json_str)
        assert parsed["event_type"] == "error"
        assert parsed["error"] == "Something went wrong"


class TestAuditLogger:
    """Tests for AuditLogger class."""

    def test_audit_logger_singleton(self, tmp_path):
        """Test that AuditLogger is a singleton."""
        db_path = tmp_path / "audit.db"
        logger1 = AuditLogger(db_path=db_path, enabled=True)
        logger2 = AuditLogger(db_path=db_path, enabled=True)
        assert logger1 is logger2

    def test_audit_logger_disabled(self, tmp_path):
        """Test that disabled logger doesn't write."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=False)
        logger.log_tool_call("terminal", {"command": "ls"})
        # DB should not be created when disabled
        assert not db_path.exists() or logger._db_conn is None

    def test_audit_logger_writes_to_db(self, tmp_path):
        """Test that logger writes to SQLite database."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_call("terminal", {"command": "whoami"}, session_id="sess-001")

        # Query the database directly
        conn = sqlite3.connect(str(db_path))
        cursor = conn.execute("SELECT * FROM audit_log")
        rows = cursor.fetchall()
        conn.close()

        assert len(rows) == 1
        # Check column values (order: id, timestamp, event_type, session_id, tool_name, ...)
        assert rows[0][2] == "tool_call"  # event_type
        assert rows[0][3] == "sess-001"  # session_id
        assert rows[0][4] == "terminal"  # tool_name

    def test_audit_logger_writes_to_file(self, tmp_path):
        """Test that logger writes to file when configured."""
        db_path = tmp_path / "audit.db"
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            db_path=db_path,
            log_file=log_file,
            enabled=True,
            log_format="json",
        )

        logger.log_tool_call("terminal", {"command": "ls"}, session_id="sess-001")
        logger._file_handle.flush()

        content = log_file.read_text()
        assert "tool_call" in content
        assert "terminal" in content

    def test_audit_logger_text_format(self, tmp_path):
        """Test text format output."""
        db_path = tmp_path / "audit.db"
        log_file = tmp_path / "audit.log"
        logger = AuditLogger(
            db_path=db_path,
            log_file=log_file,
            enabled=True,
            log_format="text",
        )

        logger.log_tool_call("terminal", {"command": "ls"}, session_id="sess-001")
        logger._file_handle.flush()

        content = log_file.read_text()
        assert "TOOL_CALL" in content
        assert "terminal" in content


class TestAuditLoggerMethods:
    """Tests for specific AuditLogger logging methods."""

    def test_log_tool_call(self, tmp_path):
        """Test log_tool_call method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_call(
            tool_name="nmap_scan",
            args={"target": "10.0.0.1", "ports": "1-1000"},
            session_id="sess-001",
            target="10.0.0.1",
            phase="enumeration",
        )

        events = logger.get_events(session_id="sess-001")
        assert len(events) == 1
        assert events[0]["tool_name"] == "nmap_scan"
        assert events[0]["target"] == "10.0.0.1"
        assert events[0]["phase"] == "enumeration"

    def test_log_tool_result_success(self, tmp_path):
        """Test log_tool_result for successful execution."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_result(
            tool_name="terminal",
            success=True,
            result="root",
            execution_time_ms=150,
            session_id="sess-001",
        )

        events = logger.get_events(event_type=AuditEventType.TOOL_RESULT)
        assert len(events) == 1
        assert events[0]["success"] == 1
        assert events[0]["execution_time_ms"] == 150

    def test_log_tool_result_failure(self, tmp_path):
        """Test log_tool_result for failed execution."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_result(
            tool_name="terminal",
            success=False,
            error="Command not found",
            execution_time_ms=50,
        )

        events = logger.get_events(event_type=AuditEventType.TOOL_RESULT)
        assert len(events) == 1
        assert events[0]["success"] == 0
        assert events[0]["error"] == "Command not found"

    def test_log_scope_warning(self, tmp_path):
        """Test log_scope_warning method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_scope_warning(
            target="192.168.1.1",
            reason="IP not in allowed scope",
            command="nmap 192.168.1.1",
            session_id="sess-001",
        )

        events = logger.get_events(event_type=AuditEventType.SCOPE_WARNING)
        assert len(events) == 1
        assert events[0]["target"] == "192.168.1.1"
        extra = json.loads(events[0]["extra_json"])
        assert extra["reason"] == "IP not in allowed scope"
        assert extra["command"] == "nmap 192.168.1.1"

    def test_log_scope_violation(self, tmp_path):
        """Test log_scope_violation method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_scope_violation(
            target="192.168.1.1",
            reason="IP blocked by scope",
            command="nmap 192.168.1.1",
            session_id="sess-001",
        )

        events = logger.get_events(event_type=AuditEventType.SCOPE_VIOLATION)
        assert len(events) == 1
        extra = json.loads(events[0]["extra_json"])
        assert extra["action"] == "blocked"

    def test_log_session_start(self, tmp_path):
        """Test log_session_start method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_session_start(
            session_id="sess-001",
            target="10.0.0.1",
            task="Enumerate target",
        )

        events = logger.get_events(event_type=AuditEventType.SESSION_START)
        assert len(events) == 1
        assert events[0]["session_id"] == "sess-001"
        assert events[0]["target"] == "10.0.0.1"

    def test_log_session_end(self, tmp_path):
        """Test log_session_end method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_session_end(
            session_id="sess-001",
            successful=True,
            techniques_used=["nmap", "gobuster", "sqlmap"],
        )

        events = logger.get_events(event_type=AuditEventType.SESSION_END)
        assert len(events) == 1
        assert events[0]["success"] == 1
        extra = json.loads(events[0]["extra_json"])
        assert "nmap" in extra["techniques_used"]

    def test_log_error(self, tmp_path):
        """Test log_error method."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_error(
            error="Connection timeout",
            context="MSF RPC connection",
            session_id="sess-001",
        )

        events = logger.get_events(event_type=AuditEventType.ERROR)
        assert len(events) == 1
        assert events[0]["error"] == "Connection timeout"


class TestAuditLoggerSanitization:
    """Tests for argument sanitization in AuditLogger."""

    def test_sanitize_password(self, tmp_path):
        """Test that passwords are redacted."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        sanitized = logger._sanitize_args({"password": "secret123", "host": "10.0.0.1"})

        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["host"] == "10.0.0.1"

    def test_sanitize_api_key(self, tmp_path):
        """Test that API keys are redacted."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        sanitized = logger._sanitize_args({"api_key": "sk-1234567890"})

        assert sanitized["api_key"] == "[REDACTED]"

    def test_sanitize_long_values(self, tmp_path):
        """Test that long values are truncated."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        long_value = "x" * 2000
        sanitized = logger._sanitize_args({"output": long_value})

        assert len(sanitized["output"]) < 2000
        assert sanitized["output"].endswith("...[truncated]")


class TestAuditContext:
    """Tests for audit context management."""

    def test_set_and_get_context(self, tmp_path):
        """Test setting and using audit context."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        set_audit_context(
            session_id="ctx-sess-001",
            target="10.0.0.1",
            phase="exploitation",
        )

        # Log without explicit session_id - should use context
        logger.log_tool_call("terminal", {"command": "id"})

        events = logger.get_events()
        assert len(events) == 1
        assert events[0]["session_id"] == "ctx-sess-001"
        assert events[0]["target"] == "10.0.0.1"
        assert events[0]["phase"] == "exploitation"

    def test_explicit_overrides_context(self, tmp_path):
        """Test that explicit values override context."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        set_audit_context(session_id="ctx-sess-001")

        # Log with explicit session_id - should override context
        logger.log_tool_call("terminal", {"command": "id"}, session_id="explicit-sess")

        events = logger.get_events()
        assert events[0]["session_id"] == "explicit-sess"

    def test_clear_context(self, tmp_path):
        """Test clearing audit context."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        set_audit_context(session_id="ctx-sess-001")
        clear_audit_context()

        logger.log_tool_call("terminal", {"command": "id"})

        events = logger.get_events()
        assert events[0]["session_id"] is None


class TestGetAuditLogger:
    """Tests for get_audit_logger function."""

    def test_get_audit_logger_with_settings(self, tmp_path, monkeypatch):
        """Test get_audit_logger creates logger from settings."""
        mock_settings = MagicMock()
        mock_settings.audit_log_enabled = True
        mock_settings.audit_log_file = None
        mock_settings.audit_log_format = "json"
        mock_settings.data_dir = tmp_path

        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        logger = get_audit_logger()

        assert logger is not None
        assert logger.enabled is True

    def test_get_audit_logger_disabled(self, tmp_path, monkeypatch):
        """Test get_audit_logger when disabled in settings."""
        mock_settings = MagicMock()
        mock_settings.audit_log_enabled = False
        mock_settings.audit_log_file = None
        mock_settings.audit_log_format = "json"
        mock_settings.data_dir = tmp_path

        monkeypatch.setattr("sploitgpt.core.config.get_settings", lambda: mock_settings)

        logger = get_audit_logger()

        assert logger.enabled is False


class TestAuditLoggerQueries:
    """Tests for querying audit events."""

    def test_get_events_by_session(self, tmp_path):
        """Test filtering events by session_id."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_call("terminal", {"command": "ls"}, session_id="sess-001")
        logger.log_tool_call("terminal", {"command": "pwd"}, session_id="sess-002")
        logger.log_tool_call("terminal", {"command": "id"}, session_id="sess-001")

        events = logger.get_events(session_id="sess-001")
        assert len(events) == 2

    def test_get_events_by_type(self, tmp_path):
        """Test filtering events by event_type."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_call("terminal", {"command": "ls"})
        logger.log_tool_result("terminal", success=True, result="output")
        logger.log_error("Something failed")

        events = logger.get_events(event_type=AuditEventType.TOOL_CALL)
        assert len(events) == 1
        assert events[0]["event_type"] == "tool_call"

    def test_get_events_with_limit(self, tmp_path):
        """Test limiting number of returned events."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        for i in range(10):
            logger.log_tool_call("terminal", {"command": f"cmd{i}"})

        events = logger.get_events(limit=5)
        assert len(events) == 5

    def test_get_events_ordered_by_timestamp(self, tmp_path):
        """Test that events are ordered by timestamp descending."""
        db_path = tmp_path / "audit.db"
        logger = AuditLogger(db_path=db_path, enabled=True)

        logger.log_tool_call("terminal", {"command": "first"})
        logger.log_tool_call("terminal", {"command": "second"})
        logger.log_tool_call("terminal", {"command": "third"})

        events = logger.get_events()
        # Most recent first
        args = json.loads(events[0]["args_json"])
        assert args["command"] == "third"
