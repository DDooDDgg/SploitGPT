"""
Audit Logging Module

Provides comprehensive audit logging for all tool executions, scope violations,
and security-relevant events in SploitGPT.
"""

import json
import logging
import sqlite3
import threading
from contextvars import ContextVar
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Context variable for tracking current session
_current_session: ContextVar[str | None] = ContextVar("current_session", default=None)
_current_target: ContextVar[str | None] = ContextVar("current_target", default=None)
_current_phase: ContextVar[str | None] = ContextVar("current_phase", default=None)


class AuditEventType(str, Enum):
    """Types of audit events."""

    SESSION_START = "session_start"
    SESSION_END = "session_end"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    SCOPE_WARNING = "scope_warning"
    SCOPE_VIOLATION = "scope_violation"
    LLM_CALL = "llm_call"
    CREDENTIAL_ACCESS = "credential_access"
    ERROR = "error"


@dataclass
class AuditEvent:
    """Represents an audit log event."""

    event_type: AuditEventType
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    session_id: str | None = None
    tool_name: str | None = None
    args: dict[str, Any] | None = None
    result_preview: str | None = None
    success: bool | None = None
    error: str | None = None
    target: str | None = None
    phase: str | None = None
    execution_time_ms: int | None = None
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return {k: v for k, v in d.items() if v is not None}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)


class AuditLogger:
    """
    Audit logger that writes security-relevant events to both
    SQLite database and optionally to a file/stdout.
    """

    _instance: "AuditLogger | None" = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern for audit logger."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(
        self,
        db_path: Path | None = None,
        log_file: Path | None = None,
        enabled: bool = True,
        log_format: str = "json",
    ):
        """
        Initialize the audit logger.

        Args:
            db_path: Path to SQLite database for audit logs
            log_file: Optional file path for text/JSON logs (None = no file output)
            enabled: Whether audit logging is enabled
            log_format: Output format ("json" or "text")
        """
        if self._initialized:
            return

        self.enabled = enabled
        self.log_format = log_format
        self.log_file = log_file
        self.db_path = db_path
        self._db_conn: sqlite3.Connection | None = None
        self._file_handle = None

        if self.enabled and self.db_path:
            self._init_db()

        if self.enabled and self.log_file:
            self._init_file()

        self._initialized = True

    def _init_db(self) -> None:
        """Initialize the SQLite database for audit logs."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db_conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._db_conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT,
                    tool_name TEXT,
                    args_json TEXT,
                    result_preview TEXT,
                    success INTEGER,
                    error TEXT,
                    target TEXT,
                    phase TEXT,
                    execution_time_ms INTEGER,
                    extra_json TEXT
                )
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_session
                ON audit_log(session_id)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp)
            """)
            self._db_conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_log(event_type)
            """)
            self._db_conn.commit()
            logger.debug(f"Audit database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            self._db_conn = None

    def _init_file(self) -> None:
        """Initialize the file output for audit logs."""
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(self.log_file, "a", encoding="utf-8")
            logger.debug(f"Audit file initialized at {self.log_file}")
        except Exception as e:
            logger.error(f"Failed to initialize audit file: {e}")
            self._file_handle = None

    def _write_to_db(self, event: AuditEvent) -> None:
        """Write event to SQLite database."""
        if not self._db_conn:
            return

        try:
            self._db_conn.execute(
                """
                INSERT INTO audit_log (
                    timestamp, event_type, session_id, tool_name, args_json,
                    result_preview, success, error, target, phase,
                    execution_time_ms, extra_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp,
                    event.event_type.value,
                    event.session_id,
                    event.tool_name,
                    json.dumps(event.args) if event.args else None,
                    event.result_preview,
                    1 if event.success else (0 if event.success is False else None),
                    event.error,
                    event.target,
                    event.phase,
                    event.execution_time_ms,
                    json.dumps(event.extra) if event.extra else None,
                ),
            )
            self._db_conn.commit()
        except Exception as e:
            logger.error(f"Failed to write audit event to database: {e}")

    def _write_to_file(self, event: AuditEvent) -> None:
        """Write event to file."""
        if not self._file_handle:
            return

        try:
            if self.log_format == "json":
                line = event.to_json() + "\n"
            else:
                # Text format
                parts = [f"[{event.timestamp}]", event.event_type.value.upper()]
                if event.session_id:
                    parts.append(f"session={event.session_id[:8]}")
                if event.tool_name:
                    parts.append(f"tool={event.tool_name}")
                if event.target:
                    parts.append(f"target={event.target}")
                if event.success is not None:
                    parts.append(f"success={event.success}")
                if event.error:
                    parts.append(f"error={event.error}")
                line = " ".join(parts) + "\n"

            self._file_handle.write(line)
            self._file_handle.flush()
        except Exception as e:
            logger.error(f"Failed to write audit event to file: {e}")

    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        if not self.enabled:
            return

        # Enrich with context if not provided
        if event.session_id is None:
            event.session_id = _current_session.get()
        if event.target is None:
            event.target = _current_target.get()
        if event.phase is None:
            event.phase = _current_phase.get()

        self._write_to_db(event)
        self._write_to_file(event)

    def log_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any],
        session_id: str | None = None,
        target: str | None = None,
        phase: str | None = None,
    ) -> None:
        """Log a tool call event."""
        # Sanitize sensitive args
        sanitized_args = self._sanitize_args(args)

        self.log(
            AuditEvent(
                event_type=AuditEventType.TOOL_CALL,
                tool_name=tool_name,
                args=sanitized_args,
                session_id=session_id,
                target=target,
                phase=phase,
            )
        )

    def log_tool_result(
        self,
        tool_name: str,
        success: bool,
        result: str | None = None,
        error: str | None = None,
        execution_time_ms: int | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log a tool result event."""
        # Truncate result preview
        result_preview = None
        if result:
            result_preview = result[:500] + "..." if len(result) > 500 else result

        self.log(
            AuditEvent(
                event_type=AuditEventType.TOOL_RESULT,
                tool_name=tool_name,
                success=success,
                result_preview=result_preview,
                error=error,
                execution_time_ms=execution_time_ms,
                session_id=session_id,
            )
        )

    def log_scope_warning(
        self,
        target: str,
        reason: str,
        command: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log a scope warning event."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.SCOPE_WARNING,
                target=target,
                extra={"reason": reason, "command": command},
                session_id=session_id,
            )
        )

    def log_scope_violation(
        self,
        target: str,
        reason: str,
        command: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log a scope violation (blocked action) event."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.SCOPE_VIOLATION,
                target=target,
                extra={"reason": reason, "command": command, "action": "blocked"},
                session_id=session_id,
            )
        )

    def log_session_start(
        self,
        session_id: str,
        target: str | None = None,
        task: str | None = None,
    ) -> None:
        """Log session start event."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.SESSION_START,
                session_id=session_id,
                target=target,
                extra={"task": task} if task else None,
            )
        )

    def log_session_end(
        self,
        session_id: str,
        successful: bool | None = None,
        techniques_used: list[str] | None = None,
    ) -> None:
        """Log session end event."""
        extra = {}
        if successful is not None:
            extra["successful"] = successful
        if techniques_used:
            extra["techniques_used"] = techniques_used

        self.log(
            AuditEvent(
                event_type=AuditEventType.SESSION_END,
                session_id=session_id,
                success=successful,
                extra=extra if extra else None,
            )
        )

    def log_error(
        self,
        error: str,
        context: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Log an error event."""
        self.log(
            AuditEvent(
                event_type=AuditEventType.ERROR,
                error=error,
                extra={"context": context} if context else None,
                session_id=session_id,
            )
        )

    def _sanitize_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive information from arguments."""
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "credential",
            "auth",
        }
        sanitized = {}
        for key, value in args.items():
            key_lower = key.lower()
            if any(s in key_lower for s in sensitive_keys):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = value[:1000] + "...[truncated]"
            else:
                sanitized[key] = value
        return sanitized

    def get_events(
        self,
        session_id: str | None = None,
        event_type: AuditEventType | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Query audit events from the database.

        Args:
            session_id: Filter by session ID
            event_type: Filter by event type
            since: Filter events after this ISO timestamp
            limit: Maximum number of events to return

        Returns:
            List of audit event dictionaries
        """
        if not self._db_conn:
            return []

        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []

        if session_id:
            query += " AND session_id = ?"
            params.append(session_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        if since:
            query += " AND timestamp > ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            cursor = self._db_conn.execute(query, params)
            columns = [description[0] for description in cursor.description]
            rows = cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]
        except Exception as e:
            logger.error(f"Failed to query audit events: {e}")
            return []

    def close(self) -> None:
        """Close database connection and file handle."""
        if self._db_conn:
            self._db_conn.close()
            self._db_conn = None
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None


# Context management functions
def set_audit_context(
    session_id: str | None = None,
    target: str | None = None,
    phase: str | None = None,
) -> None:
    """Set the current audit context."""
    if session_id is not None:
        _current_session.set(session_id)
    if target is not None:
        _current_target.set(target)
    if phase is not None:
        _current_phase.set(phase)


def clear_audit_context() -> None:
    """Clear the current audit context."""
    _current_session.set(None)
    _current_target.set(None)
    _current_phase.set(None)


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        from sploitgpt.core.config import get_settings

        settings = get_settings()
        db_path = settings.data_dir / "audit.db" if settings.audit_log_enabled else None
        log_file = Path(settings.audit_log_file) if settings.audit_log_file else None

        _audit_logger = AuditLogger(
            db_path=db_path,
            log_file=log_file,
            enabled=settings.audit_log_enabled,
            log_format=settings.audit_log_format,
        )
    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global audit logger (for testing)."""
    global _audit_logger
    if _audit_logger:
        _audit_logger.close()
    _audit_logger = None
    # Reset singleton
    AuditLogger._instance = None
