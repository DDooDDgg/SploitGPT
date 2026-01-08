"""
Tests for MSF Visual Terminal Viewer (PTY-based)

These tests verify the viewer module without actually opening terminals
or spawning msfconsole.
"""

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from sploitgpt.msf.viewer import (
    _build_terminal_command,
    _find_terminal,
    _get_desktop_terminal,
    _has_display,
    _rpc_to_console,
    close_msf_viewer,
    echo_output,
    echo_rpc_call,
    ensure_viewer_open,
    is_viewer_open,
    is_viewer_ready,
    open_msf_viewer,
    send_to_viewer,
)


class TestViewerHelpers:
    """Tests for viewer helper functions."""

    def test_find_terminal_returns_string_or_none(self):
        """Test that _find_terminal returns a string or None."""
        result = _find_terminal()
        assert result is None or isinstance(result, str)

    def test_build_terminal_command_gnome(self):
        """Test command building for gnome-terminal with PTY."""
        cmd = _build_terminal_command("gnome-terminal", "/dev/pts/99")
        assert cmd[0] == "gnome-terminal"
        assert "--title=SploitGPT MSF Viewer" in cmd
        assert any("msfconsole" in arg for arg in cmd)
        assert any("/dev/pts/99" in arg for arg in cmd)

    def test_build_terminal_command_konsole(self):
        """Test command building for konsole with PTY."""
        cmd = _build_terminal_command("konsole", "/dev/pts/99")
        assert cmd[0] == "konsole"
        assert any("msfconsole" in arg for arg in cmd)

    def test_build_terminal_command_xterm(self):
        """Test command building for xterm (fallback) with PTY."""
        cmd = _build_terminal_command("xterm", "/dev/pts/99")
        assert cmd[0] == "xterm"
        assert any("msfconsole" in arg for arg in cmd)

    def test_build_terminal_command_alacritty(self):
        """Test command building for alacritty with PTY."""
        cmd = _build_terminal_command("alacritty", "/dev/pts/99")
        assert cmd[0] == "alacritty"
        assert any("msfconsole" in arg for arg in cmd)


class TestDisplayDetection:
    """Tests for display and desktop environment detection."""

    @patch.dict("os.environ", {"DISPLAY": ":0"}, clear=True)
    def test_has_display_with_x11(self):
        """Test display detection with X11."""
        assert _has_display() is True

    @patch.dict("os.environ", {"WAYLAND_DISPLAY": "wayland-0"}, clear=True)
    def test_has_display_with_wayland(self):
        """Test display detection with Wayland."""
        assert _has_display() is True

    @patch.dict("os.environ", {}, clear=True)
    def test_has_display_headless(self):
        """Test display detection in headless environment."""
        assert _has_display() is False

    @patch("sploitgpt.msf.viewer.shutil.which")
    @patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "GNOME"}, clear=True)
    def test_get_desktop_terminal_gnome(self, mock_which):
        """Test desktop terminal detection for GNOME."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        assert _get_desktop_terminal() == "gnome-terminal"

    @patch("sploitgpt.msf.viewer.shutil.which")
    @patch.dict("os.environ", {"XDG_CURRENT_DESKTOP": "KDE"}, clear=True)
    def test_get_desktop_terminal_kde(self, mock_which):
        """Test desktop terminal detection for KDE."""
        mock_which.return_value = "/usr/bin/konsole"
        assert _get_desktop_terminal() == "konsole"

    @patch.dict("os.environ", {}, clear=True)
    def test_get_desktop_terminal_unknown(self):
        """Test desktop terminal returns None for unknown desktop."""
        assert _get_desktop_terminal() is None


class TestViewerState:
    """Tests for viewer state management."""

    def test_is_viewer_open_false_initially(self):
        """Test that viewer reports closed when not opened."""
        # Reset module state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None

        assert is_viewer_open() is False

    def test_is_viewer_ready_false_initially(self):
        """Test that viewer reports not ready when not opened."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_ready = False

        assert is_viewer_ready() is False

    def test_close_viewer_when_not_open(self):
        """Test closing viewer when it's not open returns False."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None

        assert close_msf_viewer() is False


class TestOpenViewer:
    """Tests for open_msf_viewer function."""

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_fails_without_terminal(self, mock_which, mock_display):
        """Test that open fails gracefully when no terminal is found."""
        mock_which.return_value = None

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()
        assert result is False

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_fails_without_msfconsole(self, mock_which, mock_display):
        """Test that open fails when msfconsole is not found."""

        # Return terminal but not msfconsole
        def which_side_effect(cmd):
            if cmd == "gnome-terminal":
                return "/usr/bin/gnome-terminal"
            if cmd == "msfconsole":
                return None
            return None

        mock_which.side_effect = which_side_effect

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()
        assert result is False

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.pty.openpty")
    @patch("sploitgpt.msf.viewer.os.ttyname")
    @patch("sploitgpt.msf.viewer.os.close")
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_succeeds_with_terminal_and_msfconsole(
        self, mock_which, mock_popen, mock_os_close, mock_ttyname, mock_openpty, mock_display
    ):
        """Test successful viewer opening with PTY."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        mock_openpty.return_value = (10, 11)  # master_fd, slave_fd
        mock_ttyname.return_value = "/dev/pts/99"
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process still running
        mock_popen.return_value = mock_process

        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False
        viewer_module._pty_master_fd = None
        viewer_module._viewer_ready = False

        result = open_msf_viewer()

        assert result is True
        assert mock_popen.called
        assert mock_openpty.called
        assert viewer_module._viewer_opened_once is True

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_open_skips_when_already_opened(self, mock_which, mock_popen, mock_display):
        """Test that viewer doesn't reopen after user closes it."""
        mock_which.return_value = "/usr/bin/gnome-terminal"

        # Simulate: was opened, user closed it
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = True

        result = open_msf_viewer()  # Should skip

        assert result is False
        assert not mock_popen.called  # Didn't try to open

    @patch("sploitgpt.msf.viewer._has_display", return_value=True)
    @patch("sploitgpt.msf.viewer.pty.openpty")
    @patch("sploitgpt.msf.viewer.os.ttyname")
    @patch("sploitgpt.msf.viewer.os.close")
    @patch("sploitgpt.msf.viewer.subprocess.Popen")
    @patch("sploitgpt.msf.viewer.shutil.which")
    def test_force_reopen(
        self, mock_which, mock_popen, mock_os_close, mock_ttyname, mock_openpty, mock_display
    ):
        """Test force reopening after user closed viewer."""
        mock_which.return_value = "/usr/bin/gnome-terminal"
        mock_openpty.return_value = (10, 11)
        mock_ttyname.return_value = "/dev/pts/99"
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_popen.return_value = mock_process

        # Simulate: was opened, user closed it
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = True
        viewer_module._pty_master_fd = None

        result = open_msf_viewer(force=True)  # Force reopen

        assert result is True
        assert mock_popen.called

    @patch("sploitgpt.msf.viewer._has_display", return_value=False)
    def test_open_skips_without_display(self, mock_display):
        """Test that viewer skips opening in headless environment."""
        # Reset state
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_process = None
        viewer_module._viewer_opened_once = False

        result = open_msf_viewer()

        assert result is False


class TestSendToViewer:
    """Tests for send_to_viewer function."""

    def test_send_fails_when_not_ready(self):
        """Test that send_to_viewer returns False when viewer not ready."""
        import sploitgpt.msf.viewer as viewer_module

        viewer_module._viewer_ready = False
        viewer_module._viewer_process = None

        result = send_to_viewer("sessions")
        assert result is False

    @patch("sploitgpt.msf.viewer.os.write")
    def test_send_succeeds_when_ready(self, mock_write):
        """Test that send_to_viewer writes to PTY when ready."""
        import sploitgpt.msf.viewer as viewer_module

        # Simulate ready state
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Still running
        viewer_module._viewer_process = mock_process
        viewer_module._viewer_ready = True
        viewer_module._pty_master_fd = 10

        result = send_to_viewer("sessions")

        assert result is True
        mock_write.assert_called_once()
        # Check that the command + newline was written
        call_args = mock_write.call_args
        assert call_args[0][0] == 10  # fd
        assert b"sessions\n" == call_args[0][1]


class TestRpcToConsoleMapping:
    """Tests for RPC-to-console command mapping."""

    def test_module_search(self):
        """Test module.search maps to search command."""
        cmd = _rpc_to_console("module.search", ["vsftpd type:exploit"])
        assert cmd == "search vsftpd type:exploit"

    def test_module_search_empty(self):
        """Test module.search with empty params returns None."""
        cmd = _rpc_to_console("module.search", [])
        assert cmd is None

    def test_session_list(self):
        """Test session.list maps to sessions command."""
        cmd = _rpc_to_console("session.list", [])
        assert cmd == "sessions"

    def test_job_list(self):
        """Test job.list maps to jobs command."""
        cmd = _rpc_to_console("job.list", [])
        assert cmd == "jobs"

    def test_job_stop(self):
        """Test job.stop maps to jobs -k command."""
        cmd = _rpc_to_console("job.stop", [5])
        assert cmd == "jobs -k 5"

    def test_session_stop(self):
        """Test session.stop maps to sessions -k command."""
        cmd = _rpc_to_console("session.stop", [3])
        assert cmd == "sessions -k 3"

    def test_module_execute_exploit(self):
        """Test module.execute for exploit type."""
        cmd = _rpc_to_console(
            "module.execute",
            [
                "exploit",
                "exploit/unix/ftp/vsftpd_234_backdoor",
                {"RHOSTS": "10.0.0.5", "RPORT": "21"},
            ],
        )
        assert isinstance(cmd, list)
        assert "use exploit/unix/ftp/vsftpd_234_backdoor" in cmd
        assert "set RHOSTS 10.0.0.5" in cmd
        assert "set RPORT 21" in cmd
        assert "exploit" in cmd

    def test_module_execute_auxiliary(self):
        """Test module.execute for auxiliary type uses 'run' instead of 'exploit'."""
        cmd = _rpc_to_console(
            "module.execute",
            ["auxiliary", "auxiliary/scanner/portscan/tcp", {"RHOSTS": "10.0.0.0/24"}],
        )
        assert isinstance(cmd, list)
        assert "run" in cmd
        assert "exploit" not in cmd

    def test_module_info(self):
        """Test module.info maps to use + info commands."""
        cmd = _rpc_to_console("module.info", ["exploit", "exploit/test/module"])
        assert isinstance(cmd, list)
        assert "use exploit/test/module" in cmd
        assert "info" in cmd

    def test_module_options(self):
        """Test module.options maps to use + show options commands."""
        cmd = _rpc_to_console("module.options", ["exploit", "exploit/test/module"])
        assert isinstance(cmd, list)
        assert "use exploit/test/module" in cmd
        assert "show options" in cmd

    def test_session_shell_write(self):
        """Test session.shell_write shows command sent to session."""
        cmd = _rpc_to_console("session.shell_write", [1, "whoami\n"])
        assert cmd == "# Session 1: whoami"

    def test_console_write(self):
        """Test console.write passes through the command."""
        cmd = _rpc_to_console("console.write", [0, "search apache\n"])
        assert cmd == "search apache"

    def test_auth_methods_skipped(self):
        """Test auth methods return None (not echoed)."""
        assert _rpc_to_console("auth.login", ["user", "pass"]) is None
        assert _rpc_to_console("auth.logout", []) is None

    def test_console_management_skipped(self):
        """Test console management methods return None."""
        assert _rpc_to_console("console.create", []) is None
        assert _rpc_to_console("console.read", [0]) is None
        assert _rpc_to_console("console.destroy", [0]) is None


class TestEchoRpcCall:
    """Tests for echo_rpc_call function."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_single_command(self, mock_send):
        """Test echo_rpc_call sends single command."""
        mock_send.return_value = True
        echo_rpc_call("session.list", [])
        mock_send.assert_called_with("sessions")

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.time.sleep")
    def test_echo_rpc_call_multi_command(self, mock_sleep, mock_send):
        """Test echo_rpc_call sends multiple commands for module.execute."""
        mock_send.return_value = True
        echo_rpc_call(
            "module.execute",
            ["exploit", "exploit/test", {"RHOSTS": "10.0.0.1"}],
        )
        # Should send: use, set RHOSTS, exploit
        assert mock_send.call_count >= 3

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_skips_auth(self, mock_send):
        """Test echo_rpc_call doesn't send auth commands."""
        echo_rpc_call("auth.login", ["user", "pass"])
        mock_send.assert_not_called()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    def test_echo_rpc_call_skips_console_read(self, mock_send):
        """Test echo_rpc_call doesn't send console.read commands."""
        echo_rpc_call("console.read", [0])
        mock_send.assert_not_called()


class TestEchoOutput:
    """Tests for echo_output function."""

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_sends_prefixed_lines(self, mock_ready, mock_send):
        """Test echo_output sends lines prefixed with # >>."""
        mock_send.return_value = True
        echo_output("Line 1\nLine 2")
        assert mock_send.call_count == 2
        # Check first call
        first_call = mock_send.call_args_list[0][0][0]
        assert first_call.startswith("# >> ")

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=False)
    def test_echo_output_skips_when_not_ready(self, mock_ready, mock_send):
        """Test echo_output does nothing when viewer not ready."""
        echo_output("Some output")
        mock_send.assert_not_called()

    @patch("sploitgpt.msf.viewer.send_to_viewer")
    @patch("sploitgpt.msf.viewer.is_viewer_ready", return_value=True)
    def test_echo_output_skips_empty(self, mock_ready, mock_send):
        """Test echo_output does nothing for empty output."""
        echo_output("")
        mock_send.assert_not_called()
        echo_output("   ")
        mock_send.assert_not_called()


class TestEnsureViewerOpen:
    """Tests for ensure_viewer_open function."""

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=True)
    def test_ensure_returns_true_if_already_open(self, mock_open):
        """Test ensure_viewer_open returns True if already open."""
        result = ensure_viewer_open()
        assert result is True

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=False)
    @patch("sploitgpt.msf.viewer.open_msf_viewer", return_value=True)
    @patch("sploitgpt.core.config.get_settings")
    def test_ensure_opens_if_enabled(self, mock_settings, mock_open, mock_is_open):
        """Test ensure_viewer_open opens viewer if enabled in settings."""
        mock_settings.return_value.msf_viewer_enabled = True
        result = ensure_viewer_open()
        assert result is True
        mock_open.assert_called_once()

    @patch("sploitgpt.msf.viewer.is_viewer_open", return_value=False)
    @patch("sploitgpt.msf.viewer.open_msf_viewer")
    @patch("sploitgpt.core.config.get_settings")
    def test_ensure_skips_if_disabled(self, mock_settings, mock_open, mock_is_open):
        """Test ensure_viewer_open skips if disabled in settings."""
        mock_settings.return_value.msf_viewer_enabled = False
        result = ensure_viewer_open()
        assert result is False
        mock_open.assert_not_called()
