"""
SploitGPT Configuration
"""

import os
import subprocess
import threading
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def get_default_base_dir() -> Path:
    """Get the default base directory based on environment."""
    # Inside container
    if Path("/app").exists() and os.access("/app", os.W_OK):
        return Path("/app")

    # Development - use project directory
    project_dir = Path(__file__).parent.parent.parent
    if (project_dir / "pyproject.toml").exists():
        return project_dir

    # Fallback to home directory
    return Path.home() / ".sploitgpt"


def get_container_bridge_ip() -> str:
    """Auto-detect container bridge IP for Ollama connection (best-effort)."""
    try:
        # Try common Podman bridge interfaces.
        for iface in ("podman0", "cni-podman0", "docker0"):
            result = subprocess.run(
                ["ip", "addr", "show", iface], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "inet " in line:
                        # Extract IP from "inet 172.17.0.1/16 ..."
                        ip = line.strip().split()[1].split("/")[0]
                        return ip

        # Fallback: original docker0 behavior
        result = subprocess.run(
            ["ip", "addr", "show", "docker0"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "inet " in line:
                    # Extract IP from "inet 172.17.0.1/16 ..."
                    ip = line.strip().split()[1].split("/")[0]
                    return ip
    except Exception as e:
        import logging

        logging.getLogger(__name__).debug(f"Failed to detect container bridge IP: {e}")

    # Default fallback
    return "172.17.0.1"


def get_docker_bridge_ip() -> str:
    """Backward-compatible alias for older configs."""
    return get_container_bridge_ip()


def get_default_ollama_host() -> str:
    """Get the default Ollama host URL."""
    # Hardcoded targets to eliminate host guessing:
    # - Inside container: always talk to the bundled service name.
    # - Outside container: localhost.
    if Path("/app").exists():
        return "http://ollama:11434"
    return "http://localhost:11434"


class Settings(BaseSettings):
    """Application settings loaded from environment."""

    model_config = SettingsConfigDict(
        env_prefix="SPLOITGPT_",
        env_file=".env",
        extra="ignore",
    )

    # Ollama / LLM settings
    ollama_host: str = get_default_ollama_host()
    # Default to the packaged SploitGPT 7B v5.10e model; override via SPLOITGPT_MODEL.
    model: str = "sploitgpt-7b-v5.10e:q5"
    # Optional canonical form (e.g., "ollama/qwen2.5:7b"); if set, overrides `model`.
    llm_model: str | None = None

    # Listener guidance (ports are only open when tools bind to them)
    lport: int = 4444
    listener_ports: str = "40000-40100"

    # Metasploit RPC
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "sploitgpt"
    msf_ssl: bool = False
    msf_verify_ssl: bool = True
    msf_viewer_enabled: bool = True  # Open msfconsole in separate terminal window

    # Paths - dynamically set based on environment
    base_dir: Path = get_default_base_dir()

    @property
    def loot_dir(self) -> Path:
        return self.base_dir / "loot"

    @property
    def sessions_dir(self) -> Path:
        return self.base_dir / "sessions"

    @property
    def data_dir(self) -> Path:
        return self.base_dir / "data"

    # Behavior
    ask_threshold: float = 0.7  # Confidence below this triggers clarifying question
    max_retries: int = 3
    command_timeout: int = 300  # 5 minutes
    confirm_actions: bool = True  # Require confirmation before executing tools

    # Scope enforcement
    # Comma-separated list of allowed targets: IPs, CIDR ranges, or hostnames
    # Example: "10.0.0.0/24,192.168.1.100,target.htb"
    scope_targets: str = ""
    # "warn" = emit warning but allow, "block" = prevent out-of-scope actions
    scope_mode: str = "warn"

    # Debug
    debug: bool = False
    log_level: str = "INFO"

    # Audit logging
    audit_log_enabled: bool = True
    audit_log_file: str | None = None  # None = no file output, path = write to file
    audit_log_format: str = "json"  # "json" or "text"

    # Optional API keys / integrations
    shodan_api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("SHODAN_API_KEY", "SPLOITGPT_SHODAN_API_KEY"),
    )
    shodan_timeout: float = 30.0
    shodan_max_attempts: int = 3
    shodan_backoff_base: float = 1.0
    shodan_backoff_max: float = 60.0

    def model_post_init(self, __context: Any) -> None:
        """Normalize settings after load."""
        # Always keep Metasploit RPC bound to loopback for local-only control.
        if self.msf_host not in ("127.0.0.1", "localhost", "::1"):
            self.msf_host = "127.0.0.1"

    def ensure_dirs(self) -> None:
        """Create required directories."""
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def effective_model(self) -> str:
        """Return the normalized model name to use for LLM calls."""
        raw = (self.llm_model or self.model or "").strip()
        # Accept both "ollama/foo" and "foo"
        if raw.lower().startswith("ollama/"):
            raw = raw.split("/", 1)[1]
        return raw or "qwen2.5:7b"


# Singleton with thread-safe initialization
_settings: Settings | None = None
_settings_lock = threading.Lock()


def get_settings(reload: bool = False) -> Settings:
    """Get application settings (thread-safe)."""
    global _settings
    if reload or _settings is None:
        with _settings_lock:
            # Double-check inside lock
            if reload or _settings is None:
                _settings = Settings()
                _settings.ensure_dirs()
    return _settings
