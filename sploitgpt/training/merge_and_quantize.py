"""
Merge LoRA adapters and quantize model for local inference.

Exports to GGUF format for Ollama.
"""

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    from unsloth import FastLanguageModel
except Exception:
    FastLanguageModel = None


def _gpu_supported() -> bool:
    """Return True if torch sees a supported CUDA GPU."""
    try:
        import torch

        if not torch.cuda.is_available():
            return False
        cap = torch.cuda.get_device_capability()
        archs = torch.cuda.get_arch_list() or []
        return f"sm_{cap[0]}{cap[1]}" in archs
    except Exception:
        return False


def _resolve_llama_quantize() -> Path:
    """Resolve llama-quantize binary path."""
    env_path = os.getenv("LLAMA_QUANTIZE")
    if env_path:
        candidate = Path(env_path)
        if candidate.exists():
            return candidate
    which_path = shutil.which("llama-quantize")
    if which_path:
        return Path(which_path)
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "llama.cpp" / "build" / "bin" / "llama-quantize"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(
        "llama-quantize not found. Set LLAMA_QUANTIZE or build llama.cpp to create "
        "llama.cpp/build/bin/llama-quantize."
    )


def _convert_to_f16(model_path: Path, f16_path: Path) -> None:
    """Convert HF model to F16 GGUF using llama.cpp tooling."""
    env_convert = os.getenv("LLAMA_CPP_CONVERT")
    if env_convert:
        convert_script = Path(env_convert)
        if convert_script.exists():
            subprocess.run(
                [
                    sys.executable,
                    str(convert_script),
                    str(model_path),
                    "--outfile",
                    str(f16_path),
                    "--outtype",
                    "f16",
                ],
                check=True,
            )
            return

    llama_cpp_spec = importlib.util.find_spec("llama_cpp")
    if llama_cpp_spec:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "llama_cpp.convert_hf_to_gguf",
                str(model_path),
                "--outfile",
                str(f16_path),
                "--outtype",
                "f16",
            ],
            check=True,
        )
        return

    repo_root = Path(__file__).resolve().parents[2]
    convert_script = repo_root / "llama.cpp" / "convert_hf_to_gguf.py"
    if convert_script.exists():
        subprocess.run(
            [
                sys.executable,
                str(convert_script),
                str(model_path),
                "--outfile",
                str(f16_path),
                "--outtype",
                "f16",
            ],
            check=True,
        )
        return

    raise FileNotFoundError(
        "convert_hf_to_gguf.py not found. Install llama_cpp or ensure llama.cpp is present."
    )


def _load_base_model_name(adapter_path: Path) -> str | None:
    """Read base model name from adapter_config.json."""
    config_path = adapter_path / "adapter_config.json"
    if not config_path.exists():
        return None
    with open(config_path, encoding="utf-8") as f:
        data = json.load(f)
    return data.get("base_model_name_or_path")


def merge_lora(
    model_path: Path,
    output_path: Path,
    max_seq_length: int = 4096,
    base_model: str | None = None,
):
    """Merge LoRA adapters into base model."""
    print(f"🔗 Merging LoRA adapters from {model_path}...")

    force_cpu = os.getenv("SPLOITGPT_FORCE_CPU_MERGE") == "1"
    if FastLanguageModel and not force_cpu and _gpu_supported():
        # Load model with adapters using Unsloth
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=str(model_path),
            max_seq_length=max_seq_length,
            dtype=None,
            load_in_4bit=False,  # Load in full precision for merging
        )
    else:
        # Fallback to standard HF + PEFT merge on CPU
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        base_name = base_model or _load_base_model_name(model_path)
        if not base_name:
            raise ValueError(
                "Base model not found. Provide --base-model or ensure adapter_config.json "
                "contains base_model_name_or_path."
            )

        print(f"🔧 Loading base model: {base_name}")
        model = AutoModelForCausalLM.from_pretrained(
            base_name,
            torch_dtype=torch.float16,
            device_map="cpu",
            low_cpu_mem_usage=True,
        )
        tokenizer = AutoTokenizer.from_pretrained(base_name)
        model = PeftModel.from_pretrained(model, str(model_path))

    # Merge and save
    print("🔨 Merging...")
    model = model.merge_and_unload()

    output_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(output_path))
    tokenizer.save_pretrained(str(output_path))

    print(f"✅ Merged model saved to {output_path}")
    return output_path


def quantize_to_gguf(model_path: Path, output_dir: Path, quant_methods: list[str]):
    """Quantize model to GGUF format using llama.cpp."""
    print("\n🔢 Quantizing to GGUF...")

    output_dir.mkdir(parents=True, exist_ok=True)

    # First convert to GGUF f16 (intermediate format)
    f16_path = output_dir / "model-f16.gguf"

    print("  Converting to F16 GGUF...")
    _convert_to_f16(model_path, f16_path)

    # Quantize to each requested method
    for quant_method in quant_methods:
        output_path = output_dir / f"model-{quant_method}.gguf"
        print(f"  Quantizing to {quant_method}...")

        quantize_bin = _resolve_llama_quantize()
        subprocess.run(
            [
                str(quantize_bin),
                str(f16_path),
                str(output_path),
                quant_method,
            ],
            check=True,
        )

        print(f"  ✅ Saved {output_path}")

    keep_f16 = os.getenv("KEEP_F16", "0").lower() in ("1", "true", "yes")
    if not keep_f16:
        try:
            f16_path.unlink()
            print(f"  🧹 Removed intermediate {f16_path}")
        except FileNotFoundError:
            pass

    print(f"\n✅ Quantization complete! GGUFs in {output_dir}")


def create_modelfile(gguf_path: Path, output_path: Path, model_name: str):
    """Create Ollama Modelfile."""
    gguf_path = gguf_path.resolve()
    modelfile_content = f"""# SploitGPT Fine-Tuned Model
FROM {gguf_path}

# Chat template for Qwen2.5
TEMPLATE \"\"\"
{{{{ if .System }}}}<|im_start|>system
{{{{ .System }}}}<|im_end|>
{{{{ end }}}}{{{{ if .Prompt }}}}<|im_start|>user
{{{{ .Prompt }}}}<|im_end|>
{{{{ end }}}}<|im_start|>assistant
\"\"\"

PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
PARAMETER temperature 0.3
PARAMETER top_p 0.9
"""

    output_path.write_text(modelfile_content)
    print(f"✅ Modelfile created: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Merge and quantize SploitGPT model")
    parser.add_argument("--model", required=True, help="Path to trained model with LoRA")
    parser.add_argument(
        "--base-model",
        default=None,
        help="Base model ID/path (used if Unsloth is unavailable)",
    )
    parser.add_argument(
        "--output-dir", default="models/sploitgpt-7b-gguf", help="Output directory for GGUFs"
    )
    parser.add_argument(
        "--quant-methods",
        nargs="+",
        default=["Q5_K_M", "Q4_K_M"],
        help="Quantization methods (Q5_K_M, Q4_K_M, Q3_K_M, etc.)",
    )
    parser.add_argument("--max-seq-length", type=int, default=4096, help="Max sequence length")
    parser.add_argument(
        "--skip-merge", action="store_true", help="Skip merging (use if already merged)"
    )

    args = parser.parse_args()

    model_path = Path(args.model)
    output_dir = Path(args.output_dir)

    # Step 1: Merge LoRA (if needed)
    if not args.skip_merge:
        merged_dir = output_dir / "merged"
        merged_path = merge_lora(
            model_path,
            merged_dir,
            args.max_seq_length,
            base_model=args.base_model,
        )
    else:
        merged_path = model_path
        print(f"⏭️  Skipping merge, using {merged_path}")

    # Step 2: Quantize to GGUF
    gguf_dir = output_dir / "gguf"
    quantize_to_gguf(merged_path, gguf_dir, args.quant_methods)

    # Step 3: Create Modelfile for Q5_K_M (recommended for 5070)
    q5_gguf = gguf_dir / "model-Q5_K_M.gguf"
    if q5_gguf.exists():
        modelfile_path = output_dir / "Modelfile"
        create_modelfile(q5_gguf, modelfile_path, "sploitgpt-7b-q5")

        print("\n🎯 To load into Ollama:")
        print(f"   cd {output_dir}")
        print("   ollama create sploitgpt-7b-q5 -f Modelfile")

    print("\n✅ All done! Model ready for inference on RTX 5070 (12GB)")


if __name__ == "__main__":
    main()
