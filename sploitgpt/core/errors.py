"""
SploitGPT Error Classes

Simple, focused exception hierarchy for better error handling.
"""

from __future__ import annotations


class SploitGPTError(Exception):
    """Base exception for SploitGPT errors."""


class ConfigurationError(SploitGPTError):
    """Invalid or missing configuration."""
    def __init__(self, message: str, key: str | None = None):
        super().__init__(message)
        self.key = key


class NetworkError(SploitGPTError):
    """Network operation failed."""
    def __init__(self, message: str, host: str | None = None, port: int | None = None):
        super().__init__(message)
        self.host = host
        self.port = port


class ExecutionError(SploitGPTError):
    """Command execution failed."""
    def __init__(self, message: str, command: str | None = None, exit_code: int | None = None):
        super().__init__(message)
        self.command = command
        self.exit_code = exit_code


class CommandTimeoutError(SploitGPTError):
    """Operation timed out."""
    def __init__(self, message: str, timeout_seconds: float | None = None):
        super().__init__(message)
        self.timeout_seconds = timeout_seconds


class DatabaseError(SploitGPTError):
    """Database operation failed."""
    def __init__(self, message: str, query: str | None = None):
        super().__init__(message)
        self.query = query


class OllamaError(SploitGPTError):
    """Ollama/LLM operation failed."""
    def __init__(self, message: str, model: str | None = None):
        super().__init__(message)
        self.model = model


class MetasploitError(SploitGPTError):
    """Metasploit RPC operation failed."""
    def __init__(self, message: str, module: str | None = None):
        super().__init__(message)
        self.module = module
