"""
SploitGPT Configuration
"""

import os
import subprocess
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


def get_default_base_dir() -> Path:
    """Get the default base directory based on environment."""
    # Inside Docker container
    if Path('/app').exists() and os.access('/app', os.W_OK):
        return Path('/app')
    
    # Development - use project directory
    project_dir = Path(__file__).parent.parent.parent
    if (project_dir / 'pyproject.toml').exists():
        return project_dir
    
    # Fallback to home directory
    return Path.home() / '.sploitgpt'


def get_docker_bridge_ip() -> str:
    """Auto-detect Docker bridge IP for Ollama connection."""
    try:
        # Try to get docker0 IP
        result = subprocess.run(
            ["ip", "addr", "show", "docker0"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    # Extract IP from "inet 172.17.0.1/16 ..."
                    ip = line.strip().split()[1].split('/')[0]
                    return ip
    except Exception:
        pass
    
    # Default fallback
    return "172.17.0.1"


def get_default_ollama_host() -> str:
    """Get the default Ollama host URL."""
    # Check environment first
    env_host = os.environ.get("SPLOITGPT_OLLAMA_HOST")
    if env_host:
        return env_host

    # In-container default: connect to host via Docker bridge
    if Path("/app").exists():
        bridge_ip = get_docker_bridge_ip()
        return f"http://{bridge_ip}:11434"

    # Local dev default
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
    # Sensible default for ~12GB VRAM GPUs (can be overridden via SPLOITGPT_MODEL)
    model: str = "qwen2.5:7b"
    # Optional canonical form (e.g., "ollama/qwen2.5:7b"); if set, overrides `model`.
    llm_model: Optional[str] = None
    
    # Metasploit RPC
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "sploitgpt"
    msf_ssl: bool = False
    msf_verify_ssl: bool = True
    
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
    auto_train: bool = True  # Train on new session data at boot
    ask_threshold: float = 0.7  # Confidence below this triggers clarifying question
    max_retries: int = 3
    command_timeout: int = 300  # 5 minutes

    # Cloud GPU defaults (feature disabled by default)
    cloud_gpu_enabled: bool = False
    cloud_gpu_default_wordlists: Path = Path("~/.sploitgpt/wordlists").expanduser()
    cloud_gpu_remote_base: str = "~/sploitgpt/hashcat_wordlists"
    
    # Debug
    debug: bool = False
    log_level: str = "INFO"
    
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


# Singleton
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get application settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings
