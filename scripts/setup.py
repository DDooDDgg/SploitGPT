#!/usr/bin/env python3
"""
SploitGPT First-Run Setup

Runs on first install to:
1. Check system requirements
2. Download knowledge bases (ATT&CK, Atomic Red Team)
3. Build training data
4. Fine-tune the model (if GPU available)
5. Register model with Ollama
"""

import asyncio
import subprocess
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm, Prompt

console = Console()


BANNER = """
[bold red] ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗[/]
[bold red] ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝[/]
[bold red] ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   [/]
[bold red] ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   [/]
[bold red] ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   [/]
[bold red] ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   [/]
"""


def check_python_version() -> bool:
    """Check Python version is 3.11+"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 11:
        return True
    return False


def check_ollama() -> tuple[bool, str]:
    """Check if Ollama is installed and running."""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, "Ollama not responding"
    except FileNotFoundError:
        return False, "Ollama not installed"
    except subprocess.TimeoutExpired:
        return False, "Ollama not running (timeout)"
    except Exception as e:
        return False, str(e)


def check_gpu() -> dict:
    """Check GPU availability."""
    try:
        import torch
        
        if not torch.cuda.is_available():
            return {"available": False, "reason": "CUDA not available"}
        
        gpu_name = torch.cuda.get_device_name(0)
        gpu_memory = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        
        return {
            "available": True,
            "name": gpu_name,
            "memory_gb": round(gpu_memory, 1),
        }
    except ImportError:
        return {"available": False, "reason": "PyTorch not installed"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def check_docker() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


async def download_knowledge_bases(progress: Progress) -> dict:
    """Download ATT&CK and other knowledge bases."""
    from sploitgpt.knowledge import sync_attack_data
    from sploitgpt.knowledge.atomic import download_atomic_test
    
    results = {}
    
    # Download ATT&CK
    task = progress.add_task("[cyan]Downloading MITRE ATT&CK...", total=None)
    try:
        count = await sync_attack_data(force=True)
        results["attack"] = {"success": True, "techniques": count}
        progress.update(task, completed=True)
    except Exception as e:
        results["attack"] = {"success": False, "error": str(e)}
        progress.update(task, completed=True)
    
    # Download sample Atomic tests
    task = progress.add_task("[cyan]Fetching Atomic Red Team samples...", total=None)
    try:
        # Just test a few technique downloads
        sample_techniques = ["T1046", "T1190", "T1110", "T1021"]
        for tech in sample_techniques:
            await download_atomic_test(tech)
        results["atomic"] = {"success": True, "samples": len(sample_techniques)}
        progress.update(task, completed=True)
    except Exception as e:
        results["atomic"] = {"success": False, "error": str(e)}
        progress.update(task, completed=True)
    
    return results


async def build_training_data(progress: Progress) -> Path:
    """Build the training dataset."""
    from scripts.build_training_data import build_training_data as build_data
    
    output_path = Path("data/training/sploitgpt_train.jsonl")
    
    task = progress.add_task("[cyan]Building training data...", total=None)
    
    try:
        await build_data(output_path)
        progress.update(task, completed=True)
        return output_path
    except Exception:
        progress.update(task, completed=True)
        raise


def download_base_model(model: str) -> bool:
    """Download base model via Ollama."""
    console.print(f"\n[cyan]Downloading base model: {model}[/]")
    console.print("[dim]This may take a while depending on your connection...[/]\n")
    
    try:
        result = subprocess.run(
            ["ollama", "pull", model],
            check=True,
        )
        return result.returncode == 0
    except Exception as e:
        console.print(f"[red]Failed to download model:[/] {e}")
        return False


async def run_setup():
    """Main setup flow."""
    console.print(BANNER)
    console.print("[bold]First-Time Setup[/]\n")
    console.print("[yellow]⚠ This script is deprecated. Use ./install.sh (scripts/install.py) instead.[/yellow]\n")
    
    # Step 1: Check requirements
    console.print("[bold cyan]Step 1: Checking Requirements[/]\n")
    
    checks = []
    
    # Python
    if check_python_version():
        checks.append(("[green]✓[/]", "Python 3.11+"))
    else:
        checks.append(("[red]✗[/]", "Python 3.11+ required"))
    
    # Ollama
    ollama_ok, ollama_msg = check_ollama()
    if ollama_ok:
        checks.append(("[green]✓[/]", "Ollama installed and running"))
    else:
        checks.append(("[yellow]⚠[/]", f"Ollama: {ollama_msg}"))
    
    # GPU
    gpu_info = check_gpu()
    if gpu_info["available"]:
        checks.append(("[green]✓[/]", f"GPU: {gpu_info['name']} ({gpu_info['memory_gb']} GB)"))
    else:
        checks.append(("[yellow]⚠[/]", f"No GPU: {gpu_info['reason']} (fine-tuning disabled)"))
    
    # Docker
    if check_docker():
        checks.append(("[green]✓[/]", "Docker available"))
    else:
        checks.append(("[yellow]⚠[/]", "Docker not available (will run locally)"))
    
    for status, msg in checks:
        console.print(f"  {status} {msg}")
    
    console.print()
    
    # Step 2: Choose setup mode
    console.print("[bold cyan]Step 2: Choose Setup Mode[/]\n")
    
    if gpu_info["available"] and gpu_info.get("memory_gb", 0) >= 8:
        console.print("  [bold][1][/] Full Setup (recommended)")
        console.print("      - Download knowledge bases")
        console.print("      - Build training data")
        console.print("      - Fine-tune model (~30 min)")
        console.print()
        console.print("  [bold][2][/] Quick Setup")
        console.print("      - Download knowledge bases")
        console.print("      - Use base model (no fine-tuning)")
        console.print()
        console.print("  [bold][3][/] Skip Setup")
        console.print("      - Use existing model")
        console.print()
        
        choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")
    else:
        console.print("  [dim]GPU not available - fine-tuning disabled[/]")
        console.print()
        console.print("  [bold][1][/] Download knowledge bases + use base model")
        console.print("  [bold][2][/] Skip setup")
        console.print()
        
        choice = Prompt.ask("Choose", choices=["1", "2"], default="1")
        if choice == "1":
            choice = "2"  # Map to Quick Setup
        else:
            choice = "3"  # Map to Skip
    
    if choice == "3":
        console.print("\n[yellow]Skipping setup. Run 'sploitgpt setup' later to complete.[/]")
        return
    
    # Step 3: Download knowledge
    console.print("\n[bold cyan]Step 3: Downloading Knowledge Bases[/]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        kb_results = await download_knowledge_bases(progress)
    
    if kb_results.get("attack", {}).get("success"):
        console.print(f"  [green]✓[/] MITRE ATT&CK: {kb_results['attack']['techniques']} techniques")
    else:
        console.print(f"  [red]✗[/] ATT&CK: {kb_results['attack'].get('error', 'unknown error')}")
    
    if kb_results.get("atomic", {}).get("success"):
        console.print("  [green]✓[/] Atomic Red Team samples loaded")
    
    # Step 4: Build training data (if full setup)
    if choice == "1":
        console.print("\n[bold cyan]Step 4: Building Training Data[/]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            try:
                training_path = await build_training_data(progress)
                console.print(f"  [green]✓[/] Training data: {training_path}")
            except Exception as e:
                console.print(f"  [red]✗[/] Failed to build training data: {e}")
                choice = "2"  # Fall back to quick setup
    
    # Step 5: Model setup
    console.print("\n[bold cyan]Step 5: Model Setup[/]\n")
    
    # Determine which base model to use
    if gpu_info.get("memory_gb", 0) >= 24:
        base_model = "qwen2.5:32b"
    elif gpu_info.get("memory_gb", 0) >= 16:
        base_model = "qwen2.5:14b"
    elif gpu_info.get("memory_gb", 0) >= 8:
        base_model = "qwen2.5:7b"
    else:
        base_model = "qwen2.5:3b"
    
    console.print(f"  Recommended model: [bold]{base_model}[/]")
    
    if not ollama_ok:
        console.print("\n  [yellow]⚠ Ollama not running. Start it with: ollama serve[/]")
        console.print(f"  [dim]Then run: ollama pull {base_model}[/]")
    else:
        if Confirm.ask(f"  Download {base_model} now?", default=True):
            download_base_model(base_model)
    
    # Step 6: Fine-tuning (if full setup)
    if choice == "1" and gpu_info["available"]:
        console.print("\n[bold cyan]Step 6: Fine-Tuning Model[/]\n")
        
        console.print("  This will take approximately 30 minutes.")
        console.print("  Your GPU will be at full utilization.\n")
        
        if Confirm.ask("  Start fine-tuning now?", default=True):
            console.print("\n  [cyan]Starting fine-tuning...[/]")
            console.print("  [dim]Check sploitgpt/training/finetune.py for details[/]\n")
            
            # Import and run fine-tuning
            try:
                from sploitgpt.training.finetune import run_finetuning
                
                success = run_finetuning(
                    training_data=Path("data/training/sploitgpt_train.jsonl"),
                    output_dir=Path("models/sploitgpt"),
                )
                
                if success:
                    console.print("\n  [green]✓ Fine-tuning complete![/]")
                else:
                    console.print("\n  [red]✗ Fine-tuning failed[/]")
            except Exception as e:
                console.print(f"\n  [red]✗ Fine-tuning error: {e}[/]")
        else:
            console.print("\n  [dim]Skipping fine-tuning. Run later with:[/]")
            console.print("  [dim]  python -m sploitgpt.training.finetune[/]")
    
    # Done!
    console.print("\n" + "=" * 60)
    console.print("\n[bold green]Setup Complete![/]\n")
    console.print("Start SploitGPT with:")
    console.print("  [bold]sploitgpt[/]")
    console.print()
    console.print("Or run in Docker:")
    console.print("  [bold]docker compose up -d --build[/]")
    console.print("  [bold]./sploitgpt.sh[/]")
    console.print()


def main():
    """Entry point."""
    try:
        asyncio.run(run_setup())
    except KeyboardInterrupt:
        console.print("\n[dim]Setup cancelled.[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
