"""
Agent Response Types
"""

from dataclasses import dataclass, field
from typing import Any, Literal

ResponseType = Literal[
    "message",  # Text message from agent
    "command",  # Command being executed
    "result",  # Result of command execution
    "choice",  # Awaiting user choice
    "error",  # Error occurred
    "done",  # Task complete
    "info",  # Informational message
    "activity",  # Real-time activity status update
    "warning",  # Warning (e.g., scope violation)
]


@dataclass
class AgentResponse:
    """Response from the agent."""

    type: ResponseType
    content: str = ""
    question: str = ""  # For choice type
    options: list[str] = field(default_factory=list)  # For choice type
    data: dict[str, Any] | None = None  # Additional structured data

    # Activity-specific fields
    activity_type: Literal["start", "complete", "progress", "heartbeat"] | None = None
    tool_name: str | None = None  # Name of tool for activity events
    elapsed_seconds: float | None = None  # Elapsed time for activity events

    def is_terminal(self) -> bool:
        """Check if this is a terminal response (done or error)."""
        return self.type in ("done", "error")

    def is_interactive(self) -> bool:
        """Check if this requires user interaction."""
        return self.type == "choice"

    def is_activity(self) -> bool:
        """Check if this is an activity update."""
        return self.type == "activity"

    @classmethod
    def activity_start(cls, tool_name: str, content: str = "") -> "AgentResponse":
        """Create an activity start event."""
        return cls(
            type="activity",
            activity_type="start",
            tool_name=tool_name,
            content=content or f"Starting {tool_name}...",
        )

    @classmethod
    def activity_complete(
        cls, tool_name: str, elapsed_seconds: float, content: str = ""
    ) -> "AgentResponse":
        """Create an activity complete event."""
        return cls(
            type="activity",
            activity_type="complete",
            tool_name=tool_name,
            elapsed_seconds=elapsed_seconds,
            content=content or f"{tool_name} completed in {elapsed_seconds:.1f}s",
        )

    @classmethod
    def activity_heartbeat(
        cls, tool_name: str, elapsed_seconds: float, content: str = ""
    ) -> "AgentResponse":
        """Create a heartbeat event for long-running operations."""
        return cls(
            type="activity",
            activity_type="heartbeat",
            tool_name=tool_name,
            elapsed_seconds=elapsed_seconds,
            content=content or f"{tool_name} still running ({elapsed_seconds:.0f}s)...",
        )

    @classmethod
    def scope_warning(cls, target: str, reason: str = "") -> "AgentResponse":
        """Create a scope violation warning."""
        content = f"⚠️ SCOPE WARNING: Target '{target}' is out of scope"
        if reason:
            content += f" - {reason}"
        return cls(
            type="warning",
            content=content,
            data={"scope_target": target, "scope_reason": reason},
        )

    def is_warning(self) -> bool:
        """Check if this is a warning response."""
        return self.type == "warning"
