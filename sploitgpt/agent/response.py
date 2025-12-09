"""
Agent Response Types
"""

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass
class AgentResponse:
    """Response from the agent."""
    
    type: Literal["message", "command", "result", "choice", "error", "done", "info"]
    content: str = ""
    question: str = ""  # For choice type
    options: list[str] = field(default_factory=list)  # For choice type
    data: Optional[dict[str, Any]] = None  # Additional structured data
    
    def is_terminal(self) -> bool:
        """Check if this is a terminal response (done or error)."""
        return self.type in ("done", "error")
    
    def is_interactive(self) -> bool:
        """Check if this requires user interaction."""
        return self.type == "choice"
