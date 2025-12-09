"""
SploitGPT CLI Entry Point
"""

import argparse
import asyncio
import sys

from rich.console import Console

from sploitgpt.core.boot import boot_sequence

console = Console()


def print_banner() -> None:
    """Print the SploitGPT banner."""
    banner = """
[bold red] ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗[/]
[bold red] ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝[/]
[bold red] ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   [/]
[bold red] ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   [/]
[bold red] ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   [/]
[bold red] ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   [/]
                                                                         
[dim]            [ Autonomous AI Penetration Testing Framework ][/]
"""
    console.print(banner)


async def run_headless(task: str) -> int:
    """Run a single task without TUI."""
    from sploitgpt.agent import Agent
    
    context = await boot_sequence()
    
    if not context.ollama_connected:
        console.print("[red]Error: LLM not available. Start Ollama first.[/red]")
        return 1
    
    agent = Agent(context)
    
    console.print(f"\n[cyan]Task:[/cyan] {task}\n")
    
    async for response in agent.process(task):
        if response.type == "message":
            console.print(response.content)
        elif response.type == "command":
            console.print(f"[cyan]$[/cyan] {response.content}")
        elif response.type == "result":
            console.print(response.content)
        elif response.type == "error":
            console.print(f"[red]Error:[/red] {response.content}")
        elif response.type == "done":
            console.print(f"\n[green]✓[/green] {response.content}")
    
    return 0


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""
    print_banner()
    
    # Run boot sequence
    console.print("\n[bold cyan]Initializing SploitGPT...[/]\n")
    
    try:
        context = await boot_sequence()
    except Exception as e:
        console.print(f"[bold red]Boot failed:[/] {e}")
        return 1
    
    # Headless mode with task
    if args.task:
        return await run_headless(args.task)
    
    # CLI mode
    if args.cli:
        return await run_cli_loop(context)
    
    # Default: TUI mode
    from sploitgpt.tui.app import SploitGPTApp
    app = SploitGPTApp(context=context)
    await app.run_async()
    
    return 0


async def run_cli_loop(context) -> int:
    """Run interactive CLI loop (no TUI)."""
    from sploitgpt.agent import Agent
    
    agent = Agent(context)
    
    console.print("[dim]Type commands or '/help' for AI assistance. Ctrl+C to exit.[/dim]\n")
    
    while True:
        try:
            user_input = console.input("[bold green]sploitgpt>[/bold green] ")
        except EOFError:
            break
        
        if not user_input.strip():
            continue
        
        if user_input.strip().lower() in ("exit", "quit", "q"):
            break
        
        # Direct shell command
        if not user_input.startswith("/"):
            import asyncio
            proc = await asyncio.create_subprocess_shell(
                user_input,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            if stdout:
                console.print(stdout.decode())
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
  
Or describe any task in natural language:
  /find sql injection on 10.0.0.1
  /brute force ssh on 192.168.1.1
""")
            continue
        
        if not context.ollama_connected:
            console.print("[yellow]LLM not available. Start Ollama first.[/yellow]")
            continue
        
        async for response in agent.process(task):
            if response.type == "message":
                console.print(response.content)
            elif response.type == "command":
                console.print(f"[cyan]$[/cyan] {response.content}")
            elif response.type == "result":
                console.print(response.content)
            elif response.type == "choice":
                console.print(f"\n[yellow]{response.question}[/yellow]")
                for i, opt in enumerate(response.options, 1):
                    console.print(f"  [{i}] {opt}")
            elif response.type == "error":
                console.print(f"[red]Error:[/red] {response.content}")
            elif response.type == "done":
                console.print(f"\n[green]✓[/green] {response.content}")
        
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
    
    args = parser.parse_args()
    
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[dim]Goodbye.[/]")
        return 0


if __name__ == "__main__":
    sys.exit(main())
