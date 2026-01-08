#!/usr/bin/env python3
"""
SploitGPT Installation Script

This script:
1. Checks system requirements
2. Downloads Ollama and required model
3. Syncs knowledge bases (MITRE ATT&CK, GTFOBins)
4. Builds training data from security sources
5. Runs install-time fine-tuning (optional)
6. Sets up Podman environment
"""

import asyncio
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

# Rich for pretty output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt
except ImportError:
    print("Installing rich for pretty output...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "-q"], check=True)
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Confirm, Prompt


console = Console()


def is_in_container() -> bool:
    """Detect if we're running inside a container."""
    # Common container markers
    if Path("/.dockerenv").exists():
        return True
    if Path("/run/.containerenv").exists():
        return True
    # Check for container cgroup
    try:
        with open("/proc/1/cgroup") as f:
            data = f.read()
            return (
                ("docker" in data)
                or ("lxc" in data)
                or ("libpod" in data)
                or ("containerd" in data)
            )
    except OSError:
        return False


BANNER = """
[bold red]
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   
[/bold red]
[dim]Autonomous AI Pentesting Agent with Self-Improving Capabilities[/dim]
"""


def check_gpu() -> dict:
    """Check for GPU availability."""
    result = {
        "has_nvidia": False,
        "has_amd": False,
        "vram_gb": 0,
        "recommended_model": "qwen2.5:7b",
    }

    # Check NVIDIA
    try:
        output = (
            subprocess.check_output(
                ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
                stderr=subprocess.DEVNULL,
            )
            .decode()
            .strip()
        )

        if output:
            vram_mb = int(output.split("\n")[0])
            result["has_nvidia"] = True
            result["vram_gb"] = vram_mb / 1024

            # Recommend model based on VRAM
            if result["vram_gb"] >= 24:
                result["recommended_model"] = "qwen2.5:32b"
            elif result["vram_gb"] >= 12:
                result["recommended_model"] = "qwen2.5:14b"
            elif result["vram_gb"] >= 8:
                result["recommended_model"] = "qwen2.5:7b"
            else:
                result["recommended_model"] = "qwen2.5:3b"

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    # Check AMD (ROCm)
    try:
        output = subprocess.check_output(
            ["rocm-smi", "--showmeminfo", "vram"], stderr=subprocess.DEVNULL
        )
        if b"Total" in output:
            result["has_amd"] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return result


def check_podman() -> bool:
    """Check if Podman is installed and usable."""
    try:
        subprocess.run(["podman", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def check_ollama() -> bool:
    """Check if Ollama is installed."""
    return shutil.which("ollama") is not None


def install_ollama() -> bool:
    """Install Ollama."""
    console.print("\n[yellow]Installing Ollama...[/yellow]")

    system = platform.system().lower()

    if system == "linux":
        cmd = "curl -fsSL https://ollama.com/install.sh | sh"
    elif system == "darwin":
        cmd = "brew install ollama"
    else:
        console.print("[red]Please install Ollama manually from https://ollama.com[/red]")
        return False

    try:
        subprocess.run(cmd, shell=True, check=True)
        return True
    except subprocess.CalledProcessError:
        console.print("[red]Failed to install Ollama[/red]")
        return False


def _normalize_ollama_host(value: str) -> str:
    """Normalize host/URL into a base URL usable by HTTP checks and the ollama CLI."""
    v = value.strip()
    if v.startswith("http://") or v.startswith("https://"):
        return v
    if ":" in v:
        return f"http://{v}"
    return f"http://{v}:11434"


def _ollama_reachable(base_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base_url}/api/version", timeout=2) as resp:
            return getattr(resp, "status", 200) == 200
    except Exception:
        return False


def find_ollama_endpoint() -> str | None:
    """Return the first reachable Ollama base URL (or None if none are reachable)."""
    candidates: list[str] = []

    for key in ("OLLAMA_HOST", "SPLOITGPT_OLLAMA_HOST"):
        raw = os.environ.get(key)
        if raw:
            candidates.append(_normalize_ollama_host(raw))

    candidates.extend(
        [
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://172.17.0.1:11434",
        ]
    )

    # Deduplicate while keeping order
    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        if _ollama_reachable(url):
            return url

    return None


def start_ollama() -> str | None:
    """Ensure Ollama is reachable; returns the reachable base URL or None."""
    try:
        endpoint = find_ollama_endpoint()
        if endpoint:
            return endpoint

        # Start in background (fallback)
        subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        import time

        for _ in range(30):
            time.sleep(1)
            endpoint = find_ollama_endpoint()
            if endpoint:
                return endpoint

        return None

    except Exception as e:
        console.print(f"[red]Failed to start Ollama: {e}[/red]")
        return None


def pull_model(model: str, ollama_host: str) -> bool:
    """Pull an Ollama model."""
    console.print(f"\n[yellow]Pulling model {model}...[/yellow]")
    console.print("[dim]This may take a while depending on your connection speed.[/dim]")

    env = os.environ.copy()
    env["OLLAMA_HOST"] = ollama_host

    try:
        subprocess.run(["ollama", "pull", model], check=True, env=env)
        return True
    except subprocess.CalledProcessError:
        return False


def download_sploitgpt_model(
    quantization: str = "q5", ollama_host: str = "http://localhost:11434"
) -> bool:
    """Download the fine-tuned SploitGPT model from HuggingFace and register with Ollama.

    Args:
        quantization: "q5" for best quality (12GB+ VRAM) or "q4" for smaller (8GB+ VRAM)
        ollama_host: Ollama server URL

    Returns:
        True if successful, False otherwise
    """
    import tempfile

    HF_REPO = "cheeseman25/sploitgpt-7b-v5-gguf"
    MODEL_FILES = {
        "q5": ("model-Q5_K_M.gguf", "sploitgpt-7b-v5.10e:q5"),
        "q4": ("model-Q4_K_M.gguf", "sploitgpt-7b-v5.10e:q4"),
    }

    if quantization not in MODEL_FILES:
        console.print(f"[red]Invalid quantization: {quantization}[/red]")
        return False

    filename, model_name = MODEL_FILES[quantization]
    url = f"https://huggingface.co/{HF_REPO}/resolve/main/{filename}"

    console.print(f"\n[yellow]Downloading SploitGPT model ({quantization.upper()})...[/yellow]")
    console.print(f"[dim]Source: {url}[/dim]")
    console.print("[dim]This is a ~5GB download, please be patient.[/dim]")

    # Check if model already exists in Ollama
    env = os.environ.copy()
    env["OLLAMA_HOST"] = ollama_host
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, env=env)
        if model_name in result.stdout:
            console.print(f"[green]✓ Model {model_name} already installed[/green]")
            return True
    except subprocess.CalledProcessError:
        pass

    # Download to temp directory
    with tempfile.TemporaryDirectory() as tmpdir:
        gguf_path = Path(tmpdir) / filename

        try:
            # Use wget or curl for download with progress
            if shutil.which("wget"):
                subprocess.run(
                    ["wget", "-q", "--show-progress", "-O", str(gguf_path), url], check=True
                )
            elif shutil.which("curl"):
                subprocess.run(
                    ["curl", "-L", "--progress-bar", "-o", str(gguf_path), url], check=True
                )
            else:
                # Fallback to urllib
                console.print("[dim]Downloading (no progress bar)...[/dim]")
                urllib.request.urlretrieve(url, gguf_path)

            console.print("[green]✓ Download complete[/green]")

        except Exception as e:
            console.print(f"[red]✗ Download failed: {e}[/red]")
            return False

        # Create Modelfile
        modelfile_content = f'''FROM {gguf_path}

TEMPLATE """{{{{ if .System }}}}<|im_start|>system
{{{{ .System }}}}<|im_end|>
{{{{ end }}}}{{{{ if .Prompt }}}}<|im_start|>user
{{{{ .Prompt }}}}<|im_end|>
{{{{ end }}}}<|im_start|>assistant
"""

PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
PARAMETER temperature 0.3
PARAMETER top_p 0.9
'''

        modelfile_path = Path(tmpdir) / "Modelfile"
        modelfile_path.write_text(modelfile_content)

        # Register with Ollama
        console.print(f"[yellow]Registering model with Ollama as {model_name}...[/yellow]")
        try:
            subprocess.run(
                ["ollama", "create", model_name, "-f", str(modelfile_path)], check=True, env=env
            )
            console.print(f"[green]✓ Model {model_name} registered successfully[/green]")
            return True
        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗ Failed to register model: {e}[/red]")
            return False


async def sync_knowledge_bases():
    """Sync MITRE ATT&CK and other knowledge bases."""
    from sploitgpt.knowledge import sync_attack_data
    from sploitgpt.knowledge.gtfobins import download_gtfobins_data

    console.print("\n[yellow]Syncing knowledge bases...[/yellow]")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # MITRE ATT&CK
        task = progress.add_task("Downloading MITRE ATT&CK data...", total=None)
        try:
            count = await sync_attack_data(force=True)
            progress.update(task, description=f"[green]✓ Loaded {count} ATT&CK techniques[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]✗ ATT&CK sync failed: {e}[/red]")

        # GTFOBins
        task = progress.add_task("Downloading GTFOBins data...", total=None)
        try:
            count = await download_gtfobins_data()
            progress.update(task, description=f"[green]✓ Loaded {count} GTFOBins entries[/green]")
        except Exception as e:
            progress.update(task, description=f"[red]✗ GTFOBins sync failed: {e}[/red]")


async def build_training_data():
    """Build training data from security sources."""
    from scripts.build_training_data import main as build_data

    console.print("\n[yellow]Building training data...[/yellow]")

    try:
        await build_data()
        console.print("[green]✓ Training data built successfully[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to build training data: {e}[/red]")


async def run_finetuning(model: str) -> str:
    """Run install-time fine-tuning.

    Note: The fine-tuning pipeline is implemented in sploitgpt.training.finetune.
    It produces a GGUF and can register it with Ollama as a new model name.

    Args:
        model: The currently selected Ollama base model name (used as fallback).

    Returns:
        Model name to use after fine-tuning ("sploitgpt" on success, else input model).
    """

    console.print("\n[yellow]Running fine-tuning...[/yellow]")
    console.print(
        "[dim]This will create a security-specialized model and register it with Ollama.[/dim]"
    )

    # Training data is produced by scripts/build_training_data.py
    training_data = Path("data/training/sploitgpt_train.jsonl")
    if not training_data.exists():
        console.print(
            "[yellow]⚠ Training data not found. Build it first (or re-run installer and choose to build it).[/yellow]"
        )
        return model

    try:
        from sploitgpt.training.finetune import register_with_ollama, run_finetuning

        output_dir = Path("models/sploitgpt")

        # run_finetuning is CPU/GPU heavy and synchronous; run it in a thread.
        success = await asyncio.to_thread(
            run_finetuning,
            training_data=training_data,
            output_dir=output_dir,
            base_model=None,  # auto-detect based on GPU
            epochs=3,
        )

        if not success:
            console.print("[yellow]⚠ Fine-tuning skipped or failed, using base model[/yellow]")
            return model

        registered = await asyncio.to_thread(
            register_with_ollama,
            output_dir / "gguf",
            "sploitgpt",
        )

        if registered:
            console.print("[green]✓ Fine-tuning completed and registered as 'sploitgpt'[/green]")
            return "sploitgpt"

        console.print(
            "[yellow]⚠ Fine-tuning completed but could not register with Ollama. Using base model.[/yellow]"
        )
        return model

    except Exception as e:
        console.print(f"[red]✗ Fine-tuning failed: {e}[/red]")
        return model


def build_podman_image() -> bool:
    """Build the container image via podman compose."""
    console.print("\n[yellow]Building container image (Podman)...[/yellow]")
    console.print(
        "[dim]This builds a Kali Linux container with the included pentesting toolchain.[/dim]"
    )

    try:
        subprocess.run(["podman", "compose", "-f", "compose.yaml", "build"], check=True)
        console.print("[green]✓ Image built successfully[/green]")
        return True
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗ Failed to build image: {e}[/red]")
        return False


def create_env_file(model: str, ollama_host: str):
    """Create/overwrite .env file with configuration."""
    env_content = "\n".join(
        [
            "# SploitGPT Configuration",
            f"SPLOITGPT_OLLAMA_HOST={ollama_host}",
            f"SPLOITGPT_MODEL={model}",
            f"SPLOITGPT_LLM_MODEL={model}",
            "SPLOITGPT_DEBUG=false",
            "SPLOITGPT_AUTO_TRAIN=true",
            "# Optional API keys",
            "# SHODAN_API_KEY=",
            "# SPLOITGPT_SHODAN_TIMEOUT=30",
            "# SPLOITGPT_SHODAN_MAX_ATTEMPTS=3",
            "# SPLOITGPT_SHODAN_BACKOFF_BASE=1",
            "# SPLOITGPT_SHODAN_BACKOFF_MAX=60",
            "",
        ]
    )

    env_path = Path(".env")
    if env_path.exists() and env_path.read_text().strip():
        if not Confirm.ask(f"{env_path} already exists. Overwrite?", default=False):
            console.print("[yellow]Skipping .env update[/yellow]")
            return

    env_path.write_text(env_content)
    console.print(f"[green]✓ Configuration saved to {env_path}[/green]")


async def main():
    """Main installation routine."""
    console.print(Panel(BANNER, border_style="red"))
    console.print("\n[bold]Welcome to SploitGPT Installation![/bold]\n")

    # Check if running in container
    if is_in_container():
        console.print("[yellow]⚠ Running inside a container[/yellow]")
        console.print(
            "[dim]GPU operations (Ollama, fine-tuning) should be run on the host machine.[/dim]"
        )
        console.print(
            "[dim]This script will set up the container to connect to Ollama on the host.[/dim]\n"
        )

    # Check GPU
    console.print("[cyan]Checking system...[/cyan]")
    gpu_info = check_gpu()

    if gpu_info["has_nvidia"]:
        console.print(f"[green]✓ NVIDIA GPU detected with {gpu_info['vram_gb']:.1f}GB VRAM[/green]")
    elif gpu_info["has_amd"]:
        console.print("[green]✓ AMD GPU detected (ROCm)[/green]")
    else:
        if is_in_container():
            console.print("[dim]No GPU visible (expected in container - GPU is on host)[/dim]")
        else:
            console.print("[yellow]⚠ No GPU detected, will use CPU (slower)[/yellow]")

    console.print(f"[dim]Recommended model: {gpu_info['recommended_model']}[/dim]")

    # Check Podman
    if check_podman():
        console.print("[green]✓ Podman is installed and running[/green]")
    else:
        console.print("[red]✗ Podman is not available[/red]")
        console.print("[dim]Please install Podman Desktop (or podman CLI) and retry.[/dim]")
        if not Confirm.ask("Continue without containers? (limited functionality)", default=False):
            return

    # Install/check Ollama
    if check_ollama():
        console.print("[green]✓ Ollama is installed[/green]")
    else:
        console.print("[yellow]⚠ Ollama not found[/yellow]")
        if Confirm.ask("Install Ollama now?"):
            if not install_ollama():
                console.print("[red]Failed to install Ollama[/red]")
                return

    # Start/locate Ollama
    console.print("\n[cyan]Checking Ollama service...[/cyan]")
    ollama_host = start_ollama()
    if not ollama_host:
        console.print("[red]Failed to start or reach Ollama[/red]")
        console.print("[dim]Try starting Ollama manually, then re-run this installer.[/dim]")
        return

    console.print(f"[green]✓ Ollama is running[/green] [dim]({ollama_host})[/dim]")

    # Model selection - offer fine-tuned SploitGPT model first
    console.print("\n[cyan]Model Selection[/cyan]")
    console.print(
        "[dim]SploitGPT includes a fine-tuned model optimized for penetration testing.[/dim]"
    )

    model_choice = Prompt.ask(
        "Select model type",
        choices=["sploitgpt-q5", "sploitgpt-q4", "base-model"],
        default="sploitgpt-q5"
        if gpu_info["vram_gb"] >= 12
        else "sploitgpt-q4"
        if gpu_info["vram_gb"] >= 8
        else "base-model",
    )

    if model_choice == "sploitgpt-q5":
        # Download fine-tuned Q5 model (best quality, needs 12GB+ VRAM)
        if not download_sploitgpt_model("q5", ollama_host):
            console.print("[yellow]Falling back to base model...[/yellow]")
            model = gpu_info["recommended_model"]
            if not pull_model(model, ollama_host=ollama_host):
                console.print(f"[red]Failed to pull {model}[/red]")
                return
        else:
            model = "sploitgpt-7b-v5.10e:q5"
    elif model_choice == "sploitgpt-q4":
        # Download fine-tuned Q4 model (smaller, needs 8GB+ VRAM)
        if not download_sploitgpt_model("q4", ollama_host):
            console.print("[yellow]Falling back to base model...[/yellow]")
            model = gpu_info["recommended_model"]
            if not pull_model(model, ollama_host=ollama_host):
                console.print(f"[red]Failed to pull {model}[/red]")
                return
        else:
            model = "sploitgpt-7b-v5.10e:q4"
    else:
        # Use base Qwen model
        model = Prompt.ask(
            "Select base model",
            default=gpu_info["recommended_model"],
            choices=["qwen2.5:3b", "qwen2.5:7b", "qwen2.5:14b", "qwen2.5:32b"],
        )
        if not pull_model(model, ollama_host=ollama_host):
            console.print(f"[red]Failed to pull {model}[/red]")
            return

    console.print(f"[green]✓ Model {model} is ready[/green]")

    # Sync knowledge bases
    await sync_knowledge_bases()

    # Build training data
    if Confirm.ask("\n[cyan]Build training data from security sources?[/cyan]", default=True):
        await build_training_data()

    # Fine-tuning (optional) - only if using base model and have GPU
    final_model = model
    if model.startswith("sploitgpt-"):
        # Already using fine-tuned model, skip fine-tuning
        console.print(
            "\n[green]✓ Using pre-trained SploitGPT model (no fine-tuning needed)[/green]"
        )
    elif is_in_container():
        console.print(
            "\n[yellow]⚠ Fine-tuning skipped (run on GPU host, not in container)[/yellow]"
        )
        console.print(
            "[dim]To fine-tune, run this script directly on your host machine with the GPU.[/dim]"
        )
    elif gpu_info["has_nvidia"] and gpu_info["vram_gb"] >= 16:
        if Confirm.ask(
            "\n[cyan]Run install-time fine-tuning?[/cyan] (optional, ~30 min)", default=False
        ):
            final_model = await run_finetuning(model)
    else:
        console.print("\n[dim]Using base model. Fine-tuning requires 16GB+ VRAM.[/dim]")

    # Build container image
    if check_podman():
        if Confirm.ask("\n[cyan]Build container image (Podman)?[/cyan]", default=True):
            build_podman_image()

    # Create config
    create_env_file(final_model, ollama_host=ollama_host)

    # Done!
    console.print(
        Panel(
            f"""
[bold green]Installation Complete![/bold green]

[cyan]To start SploitGPT:[/cyan]

  [bold]Podman (recommended):[/bold]
    podman compose -f compose.yaml up -d --build
    ./sploitgpt.sh

  [bold]Local development:[/bold]
    source .venv/bin/activate
    python -m sploitgpt

[dim]Model: {final_model}[/dim]
[dim]Documentation: https://github.com/cheeseman2422/SploitGPT[/dim]
        """,
            title="🎉 Ready!",
            border_style="green",
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
