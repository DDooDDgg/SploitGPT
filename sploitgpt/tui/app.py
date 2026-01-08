"""SploitGPT TUI Application."""

import asyncio
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Input, RichLog, Static

from sploitgpt.agent import Agent
from sploitgpt.core.boot import BootContext
from sploitgpt.core.config import get_settings
from sploitgpt.design_assets import get_banner_styled, get_phase_style

# Maximum number of activity entries to keep
MAX_ACTIVITY_ENTRIES = 50


class TerminalSession:
    """Lightweight persistent shell session with cwd tracking."""

    def __init__(self, start_dir: str | Path | None = None) -> None:
        self.cwd = Path(start_dir or Path.cwd())

    async def run(self, command: str) -> str:
        """Run a command with simple built-ins (currently just `cd`)."""
        cmd = command.strip()
        if not cmd:
            return ""

        # Handle cd locally to preserve state across commands.
        if cmd.startswith("cd"):
            parts = cmd.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else str(Path.home())
            target_path = (self.cwd / target).expanduser().resolve()
            if not target_path.exists():
                return f"cd: no such file or directory: {target}"
            self.cwd = target_path
            return ""

        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=str(self.cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode() if stdout else "(no output)"


class PromptInput(Input):
    """Custom input for the command prompt."""

    BINDINGS = [
        Binding("up", "history_prev", "Previous command", show=False),
        Binding("down", "history_next", "Next command", show=False),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.history: list[str] = []
        self.history_index: int = -1

    def action_history_prev(self) -> None:
        """Go to previous command in history."""
        if self.history and self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.value = self.history[-(self.history_index + 1)]

    def action_history_next(self) -> None:
        """Go to next command in history."""
        if self.history_index > 0:
            self.history_index -= 1
            self.value = self.history[-(self.history_index + 1)]
        elif self.history_index == 0:
            self.history_index = -1
            self.value = ""


class StatusBar(Static):
    """Status bar showing current state."""

    def __init__(self, context: BootContext):
        super().__init__()
        self.context = context

    def compose(self) -> ComposeResult:
        msf = "[green]MSF[/]" if self.context.msf_connected else "[red]MSF[/]"
        llm = "[green]LLM[/]" if self.context.ollama_connected else "[red]LLM[/]"
        hosts = f"[cyan]{len(self.context.known_hosts)}[/] hosts"

        yield Static(f" {msf} | {llm} | {hosts} ")


class ActivityPanel(Static):
    """Real-time activity panel showing tool execution status."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.activities: deque[dict[str, Any]] = deque(maxlen=MAX_ACTIVITY_ENTRIES)
        self._current_tool: str | None = None
        self._current_start: float | None = None

    def on_mount(self) -> None:
        """Called when widget is mounted."""
        self._refresh_display()

    def add_activity(
        self,
        activity_type: str,
        tool_name: str,
        content: str,
        elapsed: float | None = None,
    ) -> None:
        """Add an activity entry."""
        entry = {
            "type": activity_type,
            "tool": tool_name,
            "content": content,
            "elapsed": elapsed,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
        self.activities.append(entry)

        if activity_type == "start":
            self._current_tool = tool_name
            import time

            self._current_start = time.monotonic()
        elif activity_type == "heartbeat":
            # Keep current tool running, just refresh to show updated time
            pass
        elif activity_type in ("complete", "error"):
            self._current_tool = None
            self._current_start = None

        self._refresh_display()

    def _refresh_display(self) -> None:
        """Refresh the panel display."""
        lines = ["[bold cyan]Activity[/bold cyan]", ""]

        # Show current running tool if any
        if self._current_tool:
            import time

            if self._current_start:
                elapsed = time.monotonic() - self._current_start
                lines.append(f"[yellow]◐[/yellow] {self._current_tool} ({elapsed:.0f}s)")
            else:
                lines.append(f"[yellow]◐[/yellow] {self._current_tool}")
            lines.append("")

        # Show recent activity (last 10 entries)
        recent = list(self.activities)[-10:]
        for entry in reversed(recent):
            if entry["type"] == "start":
                icon = "[yellow]▶[/yellow]"
            elif entry["type"] == "complete":
                icon = "[green]✓[/green]"
            elif entry["type"] == "heartbeat":
                icon = "[cyan]♥[/cyan]"
            else:
                icon = "[dim]·[/dim]"

            elapsed_str = f" ({entry['elapsed']:.1f}s)" if entry.get("elapsed") else ""
            lines.append(f"{icon} {entry['timestamp']} {entry['tool']}{elapsed_str}")

        if not self.activities and not self._current_tool:
            lines.append("[dim]No activity yet[/dim]")

        self.update("\n".join(lines))

    def clear_activities(self) -> None:
        """Clear all activity entries."""
        self.activities.clear()
        self._current_tool = None
        self._current_start = None
        self._refresh_display()


class SploitGPTApp(App[Any]):
    """Main SploitGPT TUI Application."""

    TITLE = "SploitGPT"
    SUB_TITLE = "Autonomous AI Penetration Testing"

    CSS = """
    Screen {
        background: $surface;
    }
    
    #main-container {
        layout: horizontal;
        height: 1fr;
    }
    
    #left-panel {
        width: 1fr;
    }
    
    #output {
        height: 1fr;
        border: solid $primary;
        padding: 0 1;
    }
    
    #input-container {
        height: 3;
        padding: 0 1;
    }
    
    #prompt-label {
        width: auto;
        color: $success;
        padding: 0 1 0 0;
    }
    
    #prompt-input {
        width: 1fr;
    }
    
    #activity-panel {
        width: 30;
        border: solid $secondary;
        padding: 0 1;
        background: $surface-darken-1;
    }
    
    #activity-panel.hidden {
        display: none;
    }
    
    #status-bar {
        height: 1;
        dock: bottom;
        background: $surface-darken-1;
    }
    
    .choice-button {
        margin: 0 1;
    }
    """

    BINDINGS = [
        Binding("ctrl+c", "quit", "Quit"),
        Binding("ctrl+l", "clear", "Clear"),
        Binding("ctrl+t", "toggle_shell_mode", "Shell mode"),
        Binding("ctrl+a", "toggle_activity", "Activity"),
    ]

    def __init__(self, context: BootContext):
        super().__init__()
        self.context = context
        self.settings = get_settings()
        self.agent = Agent(context)
        self.awaiting_choice = False
        self.choice_callback = None
        self.shell = TerminalSession()
        self.shell_mode = False
        self.activity_visible = True  # Activity panel visible by default

    def compose(self) -> ComposeResult:
        yield Header()
        yield Horizontal(
            Vertical(
                RichLog(id="output", highlight=True, markup=True),
                Horizontal(
                    Static("sploitgpt > ", id="prompt-label"),
                    PromptInput(id="prompt-input", placeholder="Enter command or /help"),
                    id="input-container",
                ),
                id="left-panel",
            ),
            ActivityPanel(id="activity-panel"),
            id="main-container",
        )
        yield Footer()

    async def on_mount(self) -> None:
        """Called when app is mounted."""
        output = self.query_one("#output", RichLog)

        # Welcome message with styled banner
        welcome_banner = get_banner_styled("main")
        output.write(welcome_banner)
        output.write("[bold cyan]TUI Build: conversational-by-default, !cmd for shell[/]")
        output.write("")

        model_name = self.settings.effective_model
        if self.context.ollama_connected and self.context.model_loaded:
            output.write(f"[green]✓[/] LLM connected; model loaded: [bold]{model_name}[/]")
        elif self.context.ollama_connected:
            output.write(f"[yellow]⚠[/] LLM reachable but model not loaded: [bold]{model_name}[/]")
            output.write("Run `ollama pull <model>` or start the model.")
        else:
            output.write("[yellow]⚠[/] LLM not connected - run 'ollama serve' on host")

        if self.context.msf_connected:
            output.write("[green]✓[/] Metasploit RPC connected")
        else:
            output.write("[yellow]⚠[/] Metasploit RPC not available")

        if self.context.known_hosts:
            output.write(f"[cyan]ℹ[/] {len(self.context.known_hosts)} known hosts from prior recon")

        output.write("")
        output.write(
            "[bold]How to use:[/] just type what you want (AI). Use !cmd for shell. /help for commands."
        )
        output.write(
            "[dim]Type /banner <phase> for a fresh banner (phases: main, recon, enumeration,"
        )
        output.write("[dim]vulnerability, exploitation, post_exploitation, privilege_escalation,")
        output.write("[dim]lateral_movement, persistence, exfiltration).[/]")

        # Focus input
        self.query_one("#prompt-input", PromptInput).focus()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command submission."""
        if event.input.id != "prompt-input":
            return

        command = event.value.strip()
        if not command:
            return

        # Add to history
        prompt_input = self.query_one("#prompt-input", PromptInput)
        prompt_input.history.append(command)
        prompt_input.history_index = -1
        prompt_input.value = ""

        output = self.query_one("#output", RichLog)
        output.write(f"[bold green]>[/] {command}")

        # If we're waiting for an interactive choice, route input to the agent.
        if self.awaiting_choice:
            await self.handle_choice_input(command)
            return

        # Bang-prefix always forces shell execution.
        if command.startswith("!"):
            await self.handle_shell_command(command[1:].strip() or "")
            return

        # Shell mode routes everything to shell unless explicitly /command
        if self.shell_mode and not command.startswith("/"):
            await self.handle_shell_command(command)
            return

        # Slash-prefix is an explicit agent/system command.
        if command.startswith("/"):
            await self.handle_agent_command(command[1:].strip())
            return

        # Default: send to the agent (conversational).
        await self.handle_agent_command(command)

    async def handle_shell_command(self, command: str) -> None:
        """Execute a direct shell command."""
        output = self.query_one("#output", RichLog)

        try:
            result = await self.shell.run(command)
            if result:
                for line in result.split("\n"):
                    output.write(line)
        except Exception as e:
            output.write(f"[red]Error running shell command:[/] {e}")

    def _render_agent_response(self, response: Any) -> None:
        """Render an AgentResponse to the output log."""
        output = self.query_one("#output", RichLog)

        if response.type == "message":
            output.write(response.content)

        elif response.type == "command":
            output.write(f"[cyan]$[/] {response.content}")

        elif response.type == "result":
            for line in (response.content or "").split("\n"):
                output.write(f"  {line}")

        elif response.type == "info":
            output.write(response.content)

        elif response.type == "done":
            output.write(f"[bold green]✓[/] {response.content}")

        elif response.type == "choice":
            # Enter interactive mode
            self.awaiting_choice = True
            output.write("")
            output.write(f"[bold yellow]{response.question}[/]")
            for i, option in enumerate(response.options, 1):
                output.write(f"  [bold][{i}][/] {option}")
            output.write("[dim]Enter the option number.[/]")
            output.write("")

        elif response.type == "error":
            output.write(f"[red]Error:[/] {response.content}")

        elif response.type == "warning":
            # Display scope/other warnings prominently
            output.write(f"[bold yellow]{response.content}[/]")

        elif response.type == "activity":
            # Update the activity panel
            activity_panel = self.query_one("#activity-panel", ActivityPanel)
            activity_panel.add_activity(
                activity_type=response.activity_type or "info",
                tool_name=response.tool_name or "unknown",
                content=response.content,
                elapsed=response.elapsed_seconds,
            )

    async def handle_choice_input(self, user_input: str) -> None:
        """Handle user input when the agent is waiting on a choice/confirmation."""
        output = self.query_one("#output", RichLog)

        # Allow users to type choices with a leading '/' out of habit.
        if user_input.startswith("/"):
            user_input = user_input[1:]

        if not self.context.ollama_connected:
            output.write("[red]Error:[/] LLM not connected. Start Ollama first.")
            self.awaiting_choice = False
            return

        # Assume we'll exit choice mode unless the agent asks another question
        self.awaiting_choice = False

        try:
            async for response in self.agent.submit_choice(user_input):
                self._render_agent_response(response)
                if response.type == "choice":
                    # Agent needs more input
                    return
        except Exception as e:
            import traceback

            output.write(f"[red]Agent error:[/] {e}")
            output.write(f"[dim]{traceback.format_exc()}[/]")

    async def handle_agent_command(self, command: str) -> None:
        """Handle an AI-assisted command."""
        output = self.query_one("#output", RichLog)

        if command.lower() == "help":
            output.write("")
            output.write("[bold cyan]SploitGPT Commands[/]")
            output.write("")
            output.write("  [bold]/scan[/] <target>     - Scan a target")
            output.write("  [bold]/enumerate[/] <target> - Enumerate services")
            output.write("  [bold]/exploit[/] <target>   - Find and run exploits")
            output.write("  [bold]/privesc[/]            - Privilege escalation")
            output.write("  [bold]/banner[/] <phase>     - Display ASCII banner for attack phase")
            output.write(
                "  [bold]/auto[/] on|off        - Toggle autonomous execution confirmations"
            )
            output.write(
                "  [bold]/shell[/] on|off       - Route input to a local shell (Ctrl+T toggles)"
            )
            output.write(
                "  [bold]!<cmd>[/]              - Run a single shell command (e.g., !ls -la)"
            )
            output.write("")
            output.write(
                "[bold]Default behavior:[/] plain input goes to the AI; use !cmd for shell."
            )
            output.write("  [bold]/help[/]               - Show this help")
            output.write("")
            output.write("[bold]Available banner phases:[/]")
            output.write("  recon, enumeration, vulnerability, exploitation,")
            output.write("  post_exploitation, privilege_escalation, lateral_movement,")
            output.write("  persistence, exfiltration")
            output.write("")
            output.write("[dim]Or just describe what you want in natural language:[/]")
            output.write("[dim]  /find sql injection vulnerabilities on 10.0.0.1[/]")
            output.write("")
            return

        # Handle autonomous mode toggle
        if command.lower().startswith("auto"):
            parts = command.split(maxsplit=1)
            if not self.agent:
                output.write("[red]Error:[/] Agent not initialized")
                return

            if len(parts) == 1:
                state = "ON" if self.agent.autonomous else "OFF"
                output.write(f"Autonomous mode is [bold]{state}[/]. Use /auto on or /auto off.")
                return

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                self.agent.autonomous = True
            elif value in ("off", "false", "0"):
                self.agent.autonomous = False
            elif value in ("toggle",):
                self.agent.autonomous = not self.agent.autonomous
            else:
                output.write("[red]Error:[/] Usage: /auto on|off")
                return

            state = "ON" if self.agent.autonomous else "OFF"
            output.write(f"Autonomous mode is now [bold]{state}[/].")
            return

        # Handle shell mode toggle
        if command.lower().startswith("shell"):
            parts = command.split(maxsplit=1)
            if len(parts) == 1:
                state = "ON" if self.shell_mode else "OFF"
                output.write(f"Shell passthrough is [bold]{state}[/]. Use /shell on or /shell off.")
                return

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                self.shell_mode = True
            elif value in ("off", "false", "0"):
                self.shell_mode = False
            elif value in ("toggle",):
                self.shell_mode = not self.shell_mode
            else:
                output.write("[red]Error:[/] Usage: /shell on|off")
                return

            state = "ON" if self.shell_mode else "OFF"
            self._update_prompt_label()
            output.write(f"Shell passthrough is now [bold]{state}[/].")
            return

        # Handle banner command
        if command.lower().startswith("banner"):
            parts = command.split(maxsplit=1)
            phase = parts[1].lower() if len(parts) > 1 else "main"

            # Display the banner
            try:
                banner_text = get_banner_styled(phase)
                output.write("")
                output.write(banner_text)
                output.write("")

                # Show phase information if it's a specific phase
                if phase != "main":
                    style = get_phase_style(phase)
                    output.write(f"[{style['color']}]{style['icon']} Phase: {style['short']}[/]")
                    output.write("")

            except Exception as e:
                output.write(f"[red]Error displaying banner:[/] {e}")
                output.write(
                    "[dim]Available phases: main, recon, enumeration, vulnerability, exploitation, post_exploitation, privilege_escalation, lateral_movement, persistence, exfiltration[/]"
                )

            return

        # Handle save command
        if command.lower() == "save":
            self.agent.save_state()
            output.write(f"[green]Session {self.agent.session_id} state saved.[/green]")
            return

        # Handle resume command
        if command.lower().startswith("resume"):
            await self._handle_resume_command(command)
            return

        if not self.context.ollama_connected:
            output.write("[red]Error:[/] LLM not connected. Start Ollama first.")
            return

        output.write("[dim]Thinking...[/]")

        # Process with agent
        try:
            async for response in self.agent.process(command):
                self._render_agent_response(response)
                if response.type == "choice":
                    # Agent is pausing for user input
                    return
        except Exception as e:
            import traceback

            output.write(f"[red]Agent error:[/] {e}")
            output.write(f"[dim]{traceback.format_exc()}[/]")

    def action_clear(self) -> None:
        """Clear the output."""
        self.query_one("#output", RichLog).clear()

    def action_toggle_shell_mode(self) -> None:
        """Toggle shell passthrough mode via keybinding."""
        self.shell_mode = not self.shell_mode
        self._update_prompt_label()
        state = "ON" if self.shell_mode else "OFF"
        output = self.query_one("#output", RichLog)
        output.write(f"[dim]Shell passthrough is now {state} (Ctrl+T).[/]")

    def action_toggle_activity(self) -> None:
        """Toggle the activity panel visibility."""
        self.activity_visible = not self.activity_visible
        activity_panel = self.query_one("#activity-panel", ActivityPanel)
        if self.activity_visible:
            activity_panel.remove_class("hidden")
        else:
            activity_panel.add_class("hidden")
        state = "visible" if self.activity_visible else "hidden"
        output = self.query_one("#output", RichLog)
        output.write(f"[dim]Activity panel is now {state} (Ctrl+A).[/]")

    async def action_quit(self) -> None:
        """Quit the application."""
        try:
            await self.agent.aclose()
        except Exception:
            pass
        self.exit()

    def _update_prompt_label(self) -> None:
        """Refresh the prompt label to reflect current mode."""
        label = self.query_one("#prompt-label", Static)
        label.update("shell > " if self.shell_mode else "sploitgpt > ")

    async def _handle_resume_command(self, command: str) -> None:
        """Handle the /resume command."""
        from sploitgpt.training.collector import SessionCollector

        output = self.query_one("#output", RichLog)
        parts = command.split(maxsplit=1)

        collector = SessionCollector(self.settings.sessions_dir / "sessions.db")

        if len(parts) > 1:
            # Direct session ID provided
            session_id = parts[1].strip()
        else:
            # Show session list
            sessions = collector.list_sessions(limit=10)

            if not sessions:
                output.write("[yellow]No previous sessions found.[/yellow]")
                return

            output.write("")
            output.write("[bold cyan]Recent Sessions[/bold cyan]")
            output.write("")

            for i, session in enumerate(sessions, 1):
                # Format date nicely
                try:
                    from datetime import datetime

                    started = datetime.fromisoformat(session.started_at)
                    date_str = started.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    date_str = session.started_at[:16] if session.started_at else "Unknown"

                # Status indicator
                if session.ended_at:
                    status = "[green]✓[/green]" if session.successful else "[yellow]○[/yellow]"
                else:
                    status = "[cyan]◐[/cyan]"  # In progress

                # Task description (truncate if long)
                task = session.task_description
                if len(task) > 40:
                    task = task[:40] + "..."
                if not task:
                    task = "(no task)"

                output.write(
                    f"  [{i}] {status} {session.id} | {date_str} | {session.turn_count}t | {task}"
                )

            output.write("")
            output.write(
                "[dim]Use /resume <session_id> or /resume <number> to resume a session.[/dim]"
            )

            # Store sessions for potential numeric selection
            self._resume_sessions = sessions
            return

        # Check if it's a numeric selection from previous list
        if hasattr(self, "_resume_sessions") and session_id.isdigit():
            idx = int(session_id) - 1
            if 0 <= idx < len(self._resume_sessions):
                session_id = self._resume_sessions[idx].id
            else:
                output.write("[red]Invalid selection.[/red]")
                return

        # Try to resume the session
        output.write(f"[cyan]Resuming session:[/cyan] {session_id}")

        new_agent = Agent.from_session(session_id, self.context)
        if not new_agent:
            output.write(f"[red]Error:[/red] Session '{session_id}' not found.")
            return

        # Save current session state before switching
        self.agent.save_state()

        # Switch to the new agent
        self.agent = new_agent

        output.write(f"[green]Resumed session {session_id}[/green]")
        output.write(
            f"[dim]Target: {self.agent.target or 'Not set'} | Phase: {self.agent.current_phase}[/dim]"
        )
        output.write(
            f"[dim]Services: {len(self.agent.discovered_services)} | Turns: {len(self.agent.conversation)}[/dim]"
        )
        output.write("")
