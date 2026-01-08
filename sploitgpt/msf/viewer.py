"""
MSF Visual Terminal Viewer (PTY-based)

Opens msfconsole in a separate terminal window and echoes commands
that the LLM executes via RPC, so users can watch/verify in real-time.

Workflow:
1. User confirms action in SploitGPT TUI
2. LLM executes via MSF RPC
3. Viewer shows equivalent msfconsole command + output

This is an optional add-on feature. To disable:
  - Set SPLOITGPT_MSF_VIEWER_ENABLED=false in .env
  - Or set msf_viewer_enabled=False in config

To remove entirely:
  - Delete this file
  - Remove msf_viewer_enabled from config.py
  - Remove the open_msf_viewer() call from boot.py
"""

import logging
import os
import pty
import shutil
import subprocess
import threading
import time

logger = logging.getLogger(__name__)

# Module-level state
_viewer_process: subprocess.Popen | None = None
_viewer_opened_once: bool = False
_pty_master_fd: int | None = None
_viewer_ready: bool = False
_viewer_lock = threading.Lock()


def _has_display() -> bool:
    """Check if a display server is available (X11 or Wayland)."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _get_desktop_terminal() -> str | None:
    """Get the preferred terminal for the current desktop environment."""
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()

    # Map desktop environments to their native terminals
    if "gnome" in desktop or "unity" in desktop:
        if shutil.which("gnome-terminal"):
            return "gnome-terminal"
    elif "kde" in desktop or "plasma" in desktop:
        if shutil.which("konsole"):
            return "konsole"
    elif "xfce" in desktop:
        if shutil.which("xfce4-terminal"):
            return "xfce4-terminal"
    elif "mate" in desktop:
        if shutil.which("mate-terminal"):
            return "mate-terminal"

    return None  # Fall back to generic detection


def _find_terminal() -> str | None:
    """Find an available terminal emulator on the system."""
    # First, try the desktop-native terminal
    desktop_term = _get_desktop_terminal()
    if desktop_term:
        return desktop_term

    # Fallback: scan common terminals in preference order
    terminals = [
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "tilix",
        "terminator",
        "alacritty",
        "kitty",
        "xterm",  # Fallback, available on most X11 systems
    ]

    for term in terminals:
        if shutil.which(term):
            return term

    return None


def _build_terminal_command(terminal: str, slave_name: str) -> list[str]:
    """Build the command to open a terminal connected to our PTY slave.

    The terminal runs msfconsole with stdin connected to our PTY slave,
    allowing us to inject commands from the parent process. The user sees
    both the injected commands and msfconsole's output in the terminal window.
    """
    title = "SploitGPT MSF Viewer"

    # Connect terminal stdin to PTY slave so we can inject commands.
    # stdout/stderr stay connected to the terminal for display.
    # The `cat` at the end keeps the terminal open even if msfconsole exits.
    connect_cmd = f"msfconsole -q < {slave_name}; echo '[MSF Viewer] msfconsole exited'; cat"

    # Each terminal has slightly different CLI syntax
    if terminal == "gnome-terminal":
        return ["gnome-terminal", f"--title={title}", "--", "bash", "-c", connect_cmd]

    elif terminal == "konsole":
        return ["konsole", f"--title={title}", "-e", "bash", "-c", connect_cmd]

    elif terminal == "xfce4-terminal":
        # xfce4-terminal -e takes a single command string, not shell
        return ["xfce4-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "mate-terminal":
        # mate-terminal -e also takes a single command
        return ["mate-terminal", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "tilix":
        return ["tilix", f"--title={title}", "-e", "bash", "-c", connect_cmd]

    elif terminal == "terminator":
        # terminator -e takes a single command string
        return ["terminator", f"--title={title}", "-x", "bash", "-c", connect_cmd]

    elif terminal == "alacritty":
        return ["alacritty", "--title", title, "-e", "bash", "-c", connect_cmd]

    elif terminal == "kitty":
        return ["kitty", "--title", title, "bash", "-c", connect_cmd]

    else:  # xterm and others
        return ["xterm", "-title", title, "-e", "bash", "-c", connect_cmd]


def is_viewer_open() -> bool:
    """Check if the MSF viewer terminal is currently open."""
    global _viewer_process

    if _viewer_process is None:
        return False

    # Check if process is still running
    return _viewer_process.poll() is None


def is_viewer_ready() -> bool:
    """Check if the viewer is ready to receive commands."""
    return _viewer_ready and is_viewer_open()


def open_msf_viewer(*, force: bool = False) -> bool:
    """
    Open msfconsole in a new terminal window with PTY control.

    Args:
        force: If True, open even if already opened once this session.
               By default, only opens on the first MSF RPC connection.

    Returns:
        True if viewer was opened (or already open), False on failure.
    """
    global _viewer_process, _viewer_opened_once, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        # Already open - nothing to do
        if is_viewer_open():
            logger.debug("MSF viewer already open")
            return True

        # Only auto-open once per session (unless forced)
        if _viewer_opened_once and not force:
            logger.debug("MSF viewer was closed by user, not reopening")
            return False

        # Check for display server (skip in headless/container environments)
        if not _has_display():
            logger.debug("No display available (headless mode), skipping MSF viewer")
            return False

        # Find a terminal emulator
        terminal = _find_terminal()
        if not terminal:
            logger.warning(
                "No terminal emulator found for MSF viewer. "
                "Install gnome-terminal, konsole, xfce4-terminal, or xterm."
            )
            return False

        # Check if msfconsole is available
        if not shutil.which("msfconsole"):
            logger.warning("msfconsole not found in PATH, cannot open MSF viewer")
            return False

        # Create PTY pair
        try:
            master_fd, slave_fd = pty.openpty()
            slave_name = os.ttyname(slave_fd)

            # Keep slave_fd open until terminal process starts - it needs to
            # be able to open the slave device by name
            _pty_master_fd = master_fd

            # Store slave_fd to close after terminal starts
            _slave_fd_temp = slave_fd

        except Exception as e:
            logger.error(f"Failed to create PTY: {e}")
            return False

        # Build and run the command
        cmd = _build_terminal_command(terminal, slave_name)

        try:
            logger.info(f"Opening MSF viewer with {terminal}")
            _viewer_process = subprocess.Popen(
                cmd,
                start_new_session=True,  # Detach from parent process
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _viewer_opened_once = True

            # Close slave_fd in parent after terminal has started
            # Terminal will open the slave device by name
            try:
                os.close(_slave_fd_temp)
            except Exception:
                pass

            # Start a thread to wait for msfconsole prompt
            def _wait_for_ready():
                global _viewer_ready
                # Give msfconsole time to start up (it can be slow)
                time.sleep(5)
                _viewer_ready = True
                logger.debug("MSF viewer ready for commands")

            threading.Thread(target=_wait_for_ready, daemon=True).start()

            return True

        except FileNotFoundError:
            logger.error(f"Terminal {terminal} not found")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False

        except PermissionError:
            logger.error(f"Permission denied running {terminal}")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False

        except Exception as e:
            logger.error(f"Failed to open MSF viewer: {e}")
            if _pty_master_fd:
                os.close(_pty_master_fd)
                _pty_master_fd = None
            return False


def send_to_viewer(command: str) -> bool:
    """
    Send a command to the MSF viewer terminal.

    The command will be typed into msfconsole and executed,
    allowing the user to see both the command and its output.

    Args:
        command: The msfconsole command to execute (without trailing newline)

    Returns:
        True if sent successfully, False if viewer not available.
    """
    global _pty_master_fd

    if not is_viewer_ready():
        logger.debug(f"Viewer not ready, skipping command: {command[:50]}...")
        return False

    if _pty_master_fd is None:
        return False

    try:
        # Write command + newline to PTY
        cmd_bytes = (command + "\n").encode("utf-8")
        os.write(_pty_master_fd, cmd_bytes)
        logger.debug(f"Sent to viewer: {command}")
        return True

    except OSError as e:
        logger.debug(f"Failed to write to viewer PTY: {e}")
        return False
    except Exception as e:
        logger.debug(f"Error sending to viewer: {e}")
        return False


def close_msf_viewer() -> bool:
    """
    Close the MSF viewer terminal if open.

    Returns:
        True if closed, False if wasn't open.
    """
    global _viewer_process, _pty_master_fd, _viewer_ready

    with _viewer_lock:
        if not is_viewer_open():
            return False

        _viewer_ready = False

        # Close PTY master
        if _pty_master_fd is not None:
            try:
                os.close(_pty_master_fd)
            except Exception:
                pass
            _pty_master_fd = None

        try:
            _viewer_process.terminate()
            _viewer_process.wait(timeout=5)
            _viewer_process = None
            return True
        except Exception as e:
            logger.warning(f"Error closing MSF viewer: {e}")
            # Force kill if terminate didn't work
            try:
                _viewer_process.kill()
                _viewer_process = None
            except Exception:
                pass
            return True


# =============================================================================
# RPC-to-Console Command Mapping (Auto-echo)
# =============================================================================

# Track current module context for multi-step commands
_current_module: str | None = None


def ensure_viewer_open() -> bool:
    """
    Ensure the MSF viewer is open if enabled in settings.

    Called automatically when MSF RPC calls are made.
    Returns True if viewer is open/ready, False otherwise.
    """
    if is_viewer_open():
        return True

    try:
        from sploitgpt.core.config import get_settings

        settings = get_settings()
        if not getattr(settings, "msf_viewer_enabled", False):
            return False
    except Exception:
        return False

    return open_msf_viewer()


def echo_rpc_call(method: str, params: list) -> None:
    """
    Auto-echo any MSF RPC call as the equivalent msfconsole command.

    This is called from MetasploitRPC._call() so ALL RPC operations
    are automatically shown in the viewer.

    Args:
        method: RPC method name (e.g., "module.search", "session.list")
        params: RPC parameters (token already stripped)
    """
    global _current_module

    # Skip internal/auth methods before trying to open viewer
    if method in ("auth.login", "auth.logout", "console.create", "console.read", "console.destroy"):
        return

    # Try to ensure viewer is open for meaningful commands
    ensure_viewer_open()

    cmd = _rpc_to_console(method, params)
    if cmd:
        # Handle multi-command sequences (e.g., module.execute)
        if isinstance(cmd, list):
            for c in cmd:
                send_to_viewer(c)
                time.sleep(0.05)  # Small delay for readability
        else:
            send_to_viewer(cmd)

        # Track module context
        if method == "module.execute" and len(params) >= 2:
            _current_module = params[1]  # module name


def _rpc_to_console(method: str, params: list) -> str | list[str] | None:
    """
    Map an RPC method + params to equivalent msfconsole command(s).

    Returns None for methods that don't have a console equivalent
    or that we don't want to echo (like auth).
    """
    global _current_module

    # Module operations
    if method == "module.search":
        return f"search {params[0]}" if params else None

    if method == "module.info":
        # params: [type, name]
        if len(params) >= 2:
            _current_module = params[1]
            return [f"use {params[1]}", "info"]
        return None

    if method == "module.options":
        # params: [type, name]
        if len(params) >= 2:
            _current_module = params[1]
            return [f"use {params[1]}", "show options"]
        return None

    if method == "module.execute":
        # params: [type, name, options_dict]
        if len(params) >= 3:
            module_name = params[1]
            options = params[2] if isinstance(params[2], dict) else {}
            cmds = [f"use {module_name}"]
            for k, v in options.items():
                cmds.append(f"set {k} {v}")
            cmds.append("exploit" if params[0] == "exploit" else "run")
            return cmds
        return None

    # Session operations
    if method == "session.list":
        return "sessions"

    if method == "session.shell_write":
        # params: [session_id, data]
        if len(params) >= 2:
            # Show the command being sent to the session
            data = params[1].strip()
            if data:
                return f"# Session {params[0]}: {data}"
        return None

    if method == "session.stop":
        # params: [session_id]
        if params:
            return f"sessions -k {params[0]}"
        return None

    # Job operations
    if method == "job.list":
        return "jobs"

    if method == "job.stop":
        # params: [job_id]
        if params:
            return f"jobs -k {params[0]}"
        return None

    # Console operations (these are already console commands)
    if method == "console.write":
        # params: [console_id, command]
        if len(params) >= 2:
            return params[1].strip()
        return None

    # Skip auth, console management, and other internal methods
    # auth.login, auth.logout, console.create, console.destroy
    # Note: console.read is intentionally skipped - output appears in the viewer terminal
    return None


def echo_output(output: str) -> None:
    """
    Echo output/results to the viewer as a comment.

    This can be called after receiving MSF RPC results to show
    what was returned, helping users correlate commands with results.

    Args:
        output: The output text to display (will be prefixed with #)
    """
    if not output or not output.strip():
        return

    if not is_viewer_ready():
        return

    # Show first few lines of output as comments
    lines = output.strip().split("\n")[:5]
    for line in lines:
        if line.strip():
            send_to_viewer(f"# >> {line.strip()[:80]}")

    if len(output.strip().split("\n")) > 5:
        send_to_viewer("# >> ... (truncated)")
