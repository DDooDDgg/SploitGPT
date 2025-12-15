"""
SploitGPT CLI Entry Point
"""

import argparse
import asyncio
import sys
from collections.abc import AsyncGenerator
from typing import Any

from rich.console import Console

from sploitgpt.core.boot import boot_sequence
from sploitgpt.design_assets import get_banner_styled

console = Console()


async def _run_agent_stream(
    agent: Any,
    stream: AsyncGenerator[Any, None],
    *,
    auto_choice: bool = False,
    require_finish: bool = False,
) -> int:
    """Render an agent response stream, handling interactive choices."""
    saw_done = False
    async for response in stream:
        if response.type == "message":
            console.print(response.content)

        elif response.type == "command":
            console.print(f"[cyan]$[/cyan] {response.content}")

        elif response.type == "result":
            console.print(response.content)

        elif response.type == "error":
            console.print(f"[red]Error:[/red] {response.content}")
            return 1

        elif response.type == "done":
            saw_done = True
            console.print(f"\n[green]✓[/green] {response.content}")
            return 0

        elif response.type == "choice":
            console.print(f"\n[yellow]{response.question}[/yellow]")
            for i, opt in enumerate(response.options, 1):
                console.print(f"  [{i}] {opt}")

            if auto_choice:
                # Prefer enabling autonomous confirmations when offered.
                chosen_idx = 1
                for i, opt in enumerate(response.options, 1):
                    if "autonomous" in str(opt).lower():
                        chosen_idx = i
                        break
                selection = str(chosen_idx)
            else:
                selection = console.input("[bold yellow]Choice>[/bold yellow] ").strip()

            # Resume via submit_choice; this may itself yield nested choices.
            return await _run_agent_stream(
                agent,
                agent.submit_choice(selection),
                auto_choice=auto_choice,
                require_finish=require_finish,
            )

    if require_finish and not saw_done:
        return 2
    return 0


def print_banner() -> None:
    """Print the SploitGPT banner."""
    banner = get_banner_styled("main")
    console.print(banner)


async def run_headless(context: Any, task: str, *, autonomous: bool, auto_choice: bool) -> int:
    """Run a single task without TUI."""
    from sploitgpt.agent import Agent

    if not context.ollama_connected:
        console.print("[red]Error: LLM not available. Start Ollama first.[/red]")
        return 1

    agent = Agent(context)
    agent.autonomous = autonomous

    console.print(f"\n[cyan]Task:[/cyan] {task}\n")

    prompt = task
    for _attempt in range(1, 4):
        rc = await _run_agent_stream(
            agent,
            agent.process(prompt),
            auto_choice=auto_choice,
            require_finish=auto_choice,
        )
        if rc != 2:
            return rc

        # If we're in non-interactive mode and the model didn't call finish, nudge it.
        prompt = (
            "Call the finish tool now for the previous task. Do not ask follow-up questions. "
            "Provide a concise one-line summary."
        )

    console.print("[red]Error:[/red] Task did not terminate with finish.")
    return 1


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""
    
    # For TUI mode, we need minimal output before Textual takes over
    is_tui_mode = not args.task and not args.cli
    
    if not is_tui_mode:
        print_banner()
        console.print("\n[bold cyan]Initializing SploitGPT...[/]\n")
    
    # Run boot sequence (with quiet mode for TUI)
    try:
        context = await boot_sequence(quiet=is_tui_mode)
    except Exception as e:
        console.print(f"[bold red]Boot failed:[/] {e}")
        return 1
    
    # Headless mode with task
    if args.task:
        return await run_headless(
            context,
            args.task,
            autonomous=bool(getattr(args, "autonomous", False) or getattr(args, "yes", False)),
            auto_choice=bool(getattr(args, "yes", False)),
        )
    
    # CLI mode
    if args.cli:
        return await run_cli_loop(
            context,
            autonomous=bool(getattr(args, "autonomous", False)),
        )
    
    # Default: TUI mode - clear screen first to avoid artifacts
    import os
    os.system('clear' if os.name != 'nt' else 'cls')
    
    from sploitgpt.tui.app import SploitGPTApp
    app = SploitGPTApp(context=context)
    await app.run_async()
    
    return 0


async def run_cli_loop(context: Any, *, autonomous: bool) -> int:
    """Run interactive CLI loop (no TUI)."""
    from sploitgpt.agent import Agent
    
    agent = Agent(context)
    agent.autonomous = autonomous

    def _sanitize_prompt_input(value: str) -> str:
        # Drop leading control characters and whitespace.
        # This prevents e.g. stray \x01 from causing '/scan' to be treated as a shell command.
        i = 0
        while i < len(value):
            ch = value[i]
            if ch.isspace() or ord(ch) < 32:
                i += 1
                continue
            break
        return value[i:]
    
    console.print("[dim]Type commands or '/help' for AI assistance. Ctrl+C to exit.[/dim]\n")
    
    while True:
        try:
            user_input = console.input("[bold green]sploitgpt>[/bold green] ")
        except EOFError:
            break

        user_input = _sanitize_prompt_input(user_input)

        if not user_input:
            continue
        
        if user_input.strip().lower() in ("exit", "quit", "q"):
            break

        # If we're waiting on a choice/confirmation, treat any input as the answer.
        if getattr(agent, "_pending", None) is not None:
            await _run_agent_stream(agent, agent.process(user_input))
            console.print()
            continue
        
        # Direct shell command
        if not user_input.startswith("/"):
            from sploitgpt.tools import execute_tool

            # No timeout for explicit user-typed shell commands.
            result = await execute_tool("terminal", {"command": user_input, "timeout": 0})
            if result:
                console.print(result)
            continue
        
        # AI command
        task = user_input[1:].strip()
        if task.lower() == "help":
            console.print("""
[bold cyan]SploitGPT Commands[/bold cyan]

  [bold]/scan[/bold] <target>       Scan a target
  [bold]/enumerate[/bold] <svc>    Enumerate a service
  [bold]/exploit[/bold] <target>   Find and exploit vulnerabilities
  [bold]/privesc[/bold]            Privilege escalation techniques
  [bold]/banner[/bold] <phase>     Display ASCII banner for attack phase
  [bold]/auto[/bold] on|off        Toggle autonomous execution confirmations
  
Banner phases: recon, enumeration, vulnerability, exploitation,
post_exploitation, privilege_escalation, lateral_movement, persistence, exfiltration
  
Or describe any task in natural language:
  /find sql injection on 10.0.0.1
  /brute force ssh on 192.168.1.1
""")
            continue
        
        # Handle autonomous mode toggle
        if task.lower().startswith("auto"):
            parts = task.split(maxsplit=1)
            if len(parts) == 1:
                state = "ON" if agent.autonomous else "OFF"
                console.print(f"Autonomous mode is [bold]{state}[/]. Use /auto on or /auto off.")
                continue

            value = parts[1].strip().lower()
            if value in ("on", "true", "1"):
                agent.autonomous = True
            elif value in ("off", "false", "0"):
                agent.autonomous = False
            elif value in ("toggle",):
                agent.autonomous = not agent.autonomous
            else:
                console.print("[red]Error:[/red] Usage: /auto on|off")
                continue

            state = "ON" if agent.autonomous else "OFF"
            console.print(f"Autonomous mode is now [bold]{state}[/].")
            continue

        # Handle banner command in CLI
        if task.lower().startswith("banner"):
            parts = task.split(maxsplit=1)
            phase = parts[1].lower() if len(parts) > 1 else "main"
            try:
                banner_text = get_banner_styled(phase)
                console.print("")
                console.print(banner_text)
                console.print("")
            except Exception as e:
                console.print(f"[red]Error:[/red] {e}")
                console.print("[dim]Available phases: main, recon, enumeration, vulnerability, exploitation, post_exploitation, privilege_escalation, lateral_movement, persistence, exfiltration[/dim]")
            continue
        
        if not context.ollama_connected:
            console.print("[yellow]LLM not available. Start Ollama first.[/yellow]")
            continue
        
        await _run_agent_stream(agent, agent.process(task))
        
        console.print()
    
    console.print("[dim]Goodbye.[/dim]")
    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SploitGPT - Autonomous AI Penetration Testing"
    )
    parser.add_argument(
        "--cli", "-c",
        action="store_true",
        help="Run in CLI mode (no TUI)"
    )
    parser.add_argument(
        "--task", "-t",
        type=str,
        help="Run a single task and exit"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version="SploitGPT 0.1.0"
    )
    parser.add_argument(
        "--autonomous", "-a",
        action="store_true",
        help="Auto-approve execution tools (skip confirmation prompts)"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Non-interactive mode for --task: auto-approve tools and auto-select the first option"
    )
    
    args = parser.parse_args()
    
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
