"""
Tests for configuration normalization.
"""

import importlib


def test_msf_host_forced_loopback(monkeypatch):
    """msf_host should always normalize to loopback, even if env overrides."""
    monkeypatch.setenv("SPLOITGPT_MSF_HOST", "10.0.0.5")
    import sploitgpt.core.config as cfg

    importlib.reload(cfg)  # reset singleton/cache
    settings = cfg.get_settings()

    assert settings.msf_host == "127.0.0.1"

    # Clean up singleton for other tests
    cfg._settings = None
