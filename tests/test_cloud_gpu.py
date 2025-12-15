import asyncio

import pytest

from sploitgpt.tools import execute_tool


@pytest.mark.asyncio
async def test_cloud_gpu_sync_requires_consent():
    res = await execute_tool("cloud_gpu_sync", {"ssh_host": "1.2.3.4"})
    assert "requires explicit consent" in res


@pytest.mark.asyncio
async def test_cloud_gpu_sync_dry_run(monkeypatch):
    # Mock the CloudGPU.sync_wordlists to avoid real ssh
    class Dummy:
        def __init__(self, **kwargs):
            pass

        def sync_wordlists(self, local_dir):
            return True

    monkeypatch.setattr("sploitgpt.tools.cloud_gpu.CloudGPU", Dummy)

    res = await execute_tool("cloud_gpu_sync", {"ssh_host": "1.2.3.4", "consent": True, "dry_run": True})
    assert res.startswith("OK")


@pytest.mark.asyncio
async def test_cloud_gpu_status(monkeypatch):
    # Mock connectivity check
    class Dummy:
        def __init__(self, **kwargs):
            pass

        def verify_connectivity(self):
            return True

    monkeypatch.setattr("sploitgpt.tools.cloud_gpu.CloudGPU", Dummy)
    res = await execute_tool("cloud_gpu_status", {"ssh_host": "1.2.3.4"})
    assert "OK" in res
