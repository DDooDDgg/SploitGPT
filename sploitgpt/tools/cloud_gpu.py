"""Cloud GPU tooling for SploitGPT.

Production-ready wrapper around SSH-based workflows to prepare and manage remote
GPU instances for offloading heavy workloads (e.g., hashcat).

Design goals:
- Safe-by-default: require explicit consent before performing actions.
- Dry-run mode to preview commands.
- Prefer Paramiko for SSH when available; fall back to system `ssh`/`rsync`/`scp`.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict

LOG = logging.getLogger(__name__)


try:  # pragma: no cover - optional import
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
except Exception:  # pragma: no cover - tests will mock
    paramiko = None  # type: ignore
    _HAS_PARAMIKO = False


class CloudGPUError(Exception):
    pass


@dataclass
class CloudGPU:
    ssh_user: str
    ssh_host: str
    ssh_port: int = 22
    ssh_key_path: Optional[str] = None
    remote_base: str = "~/sploitgpt/hashcat_wordlists"
    dry_run: bool = False
    timeout: int = 20

    def _ssh_base(self) -> list[str]:
        base = ["ssh", "-o", "BatchMode=yes", "-p", str(self.ssh_port)]
        if self.ssh_key_path:
            base.extend(["-i", str(self.ssh_key_path)])
        base.append(f"{self.ssh_user}@{self.ssh_host}")
        return base

    def verify_connectivity(self) -> bool:
        """Verify basic SSH connectivity to the remote host."""
        if self.dry_run:
            LOG.info("[dry-run] would verify connectivity to %s", self.ssh_host)
            return True

        if _HAS_PARAMIKO:
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                p = self.ssh_key_path
                kwargs = {}
                if p:
                    kwargs["key_filename"] = str(p)
                client.connect(self.ssh_host, port=self.ssh_port, username=self.ssh_user, timeout=self.timeout, **kwargs)
                client.close()
                return True
            except Exception as e:
                LOG.debug("Paramiko connectivity failed: %s", e)
                return False

        cmd = self._ssh_base() + ["echo", "connected"]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout)
            return True
        except subprocess.CalledProcessError:
            LOG.exception("SSH verification failed")
            return False
        except subprocess.TimeoutExpired:
            LOG.exception("SSH verification timed out")
            return False

    def _compute_checksums(self, local: Path) -> Dict[str, str]:
        checks: Dict[str, str] = {}
        for p in sorted(local.iterdir()):
            if not p.is_file():
                continue
            h = hashlib.sha256()
            with p.open("rb") as fh:
                while True:
                    chunk = fh.read(8192)
                    if not chunk:
                        break
                    h.update(chunk)
            checks[p.name] = h.hexdigest()
        return checks

    def sync_wordlists(self, local_dir: str) -> bool:
        """Sync local_dir to remote_base and verify checksums.

        Returns True on success, False on failure.
        """
        local = Path(local_dir).expanduser()
        if not local.exists() or not local.is_dir():
            raise CloudGPUError(f"Local wordlist directory {local} does not exist")

        if self.dry_run:
            LOG.info("[dry-run] would sync %s to %s@%s:%s", local, self.ssh_user, self.ssh_host, self.remote_base)
            return True

        # Prefer rsync when available
        if shutil.which("rsync"):
            rsync_cmd = ["rsync", "-aAX", "--delete", str(local) + "/", f"{self.ssh_user}@{self.ssh_host}:{self.remote_base}/", "-e", "ssh -p %s" % self.ssh_port]
            if self.ssh_key_path:
                rsync_cmd[-1] = rsync_cmd[-1] + f" -i {shlex.quote(str(self.ssh_key_path))}"
            try:
                subprocess.run(rsync_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            except Exception as e:
                LOG.exception("rsync failed: %s", e)
                return False
        else:
            # Fallback to scp recursive
            scp_cmd = ["scp", "-r", "-P", str(self.ssh_port)]
            if self.ssh_key_path:
                scp_cmd.extend(["-i", str(self.ssh_key_path)])
            scp_cmd.extend([str(local) + "/", f"{self.ssh_user}@{self.ssh_host}:{self.remote_base}/"])
            try:
                subprocess.run(scp_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
            except Exception as e:
                LOG.exception("scp failed: %s", e)
                return False

        # Compute local checksums
        local_checks = self._compute_checksums(local)

        # Ask remote to compute checksums for files we transferred
        names = " ".join(shlex.quote(str(self.remote_base + '/' + name)) for name in local_checks.keys())
        remote_cmd = f"cd {shlex.quote(self.remote_base)} && sha256sum {' '.join(shlex.quote(name) for name in local_checks.keys())} || true"
        ssh_cmd = self._ssh_base() + [remote_cmd]
        try:
            proc = subprocess.run(ssh_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
            out = proc.stdout
        except Exception as e:
            LOG.exception("remote checksum invocation failed: %s", e)
            return False

        remote_checks: Dict[str, str] = {}
        for line in out.splitlines():
            if not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 2:
                checksum, fname = parts[0], parts[1]
                remote_checks[Path(fname).name] = checksum

        # Compare
        for name, local_sum in local_checks.items():
            rsum = remote_checks.get(name)
            if rsum != local_sum:
                LOG.error("Checksum mismatch for %s: local=%s remote=%s", name, local_sum, rsum)
                return False

        return True

    def run_remote_command(self, cmd: str, timeout: Optional[int] = None) -> tuple[int, str, str]:
        """Run a command on the remote host and return (rc, stdout, stderr)."""
        if self.dry_run:
            LOG.info("[dry-run] would run on %s: %s", self.ssh_host, cmd)
            return 0, "(dry-run)", ""

        if _HAS_PARAMIKO:
            try:
                client = paramiko.SSHClient()
                client.load_system_host_keys()
                client.set_missing_host_key_policy(paramiko.WarningPolicy())
                kwargs = {}
                if self.ssh_key_path:
                    kwargs["key_filename"] = str(self.ssh_key_path)
                client.connect(self.ssh_host, port=self.ssh_port, username=self.ssh_user, timeout=self.timeout, **kwargs)
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout or self.timeout)
                out = stdout.read().decode()
                err = stderr.read().decode()
                rc = stdout.channel.recv_exit_status()
                client.close()
                return rc, out, err
            except Exception as e:
                LOG.exception("paramiko exec failed: %s", e)
                return 1, "", str(e)

        ssh_cmd = self._ssh_base() + [cmd]
        try:
            proc = subprocess.run(ssh_cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout or self.timeout)
            return proc.returncode, proc.stdout, proc.stderr
        except Exception as e:
            LOG.exception("ssh exec failed: %s", e)
            return 1, "", str(e)
