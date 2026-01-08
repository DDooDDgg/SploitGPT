"""
Core module for SploitGPT
"""

from sploitgpt.core.boot import boot_sequence
from sploitgpt.core.config import Settings
from sploitgpt.core.errors import (
    CommandTimeoutError,
    ConfigurationError,
    DatabaseError,
    ExecutionError,
    MetasploitError,
    NetworkError,
    OllamaError,
    SploitGPTError,
)
from sploitgpt.core.ollama import OllamaClient, OllamaMessage, OllamaResponse

__all__ = [
    "CommandTimeoutError",
    "ConfigurationError",
    "DatabaseError",
    "ExecutionError",
    "MetasploitError",
    "NetworkError",
    "OllamaClient",
    "OllamaError",
    "OllamaMessage",
    "OllamaResponse",
    "Settings",
    "SploitGPTError",
    "boot_sequence",
]
