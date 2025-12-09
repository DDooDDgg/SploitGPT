"""
SploitGPT Configuration
"""

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


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


class Settings(BaseSettings):
    """Application settings loaded from environment."""
    
    # Ollama / LLM settings
    ollama_host: str = "http://localhost:11434"
    model: str = "qwen2.5:32b"
    llm_model: str = "ollama/qwen2.5:32b"
    
    # Metasploit RPC
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "sploitgpt"
    msf_ssl: bool = False
    
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
    
    # Debug
    debug: bool = False
    log_level: str = "INFO"
    
    class Config:
        env_prefix = "SPLOITGPT_"
        env_file = ".env"
        extra = "ignore"
    
    def ensure_dirs(self) -> None:
        """Create required directories."""
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)


# Singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get application settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings
