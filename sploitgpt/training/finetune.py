"""
Install-Time Fine-Tuning

Uses unsloth + LoRA to fine-tune a base model on security data.
Runs automatically on first install (~30 min on consumer GPU).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any
import os


def check_gpu_available() -> dict[str, Any]:
    """Check if GPU is available and get specs."""
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
            "cuda_version": torch.version.cuda,
        }
    except ImportError:
        return {"available": False, "reason": "PyTorch not installed"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


def get_recommended_model(gpu_memory_gb: float) -> tuple[str, dict[str, Any]]:
    """Get recommended base model based on GPU memory."""
    
    if gpu_memory_gb >= 24:
        return "unsloth/Qwen2.5-32B-Instruct-bnb-4bit", {
            "max_seq_length": 4096,
            "lora_r": 16,
            "lora_alpha": 32,
            "batch_size": 2,
            "gradient_accumulation": 4,
        }
    elif gpu_memory_gb >= 16:
        return "unsloth/Qwen2.5-14B-Instruct-bnb-4bit", {
            "max_seq_length": 4096,
            "lora_r": 16,
            "lora_alpha": 32,
            "batch_size": 2,
            "gradient_accumulation": 4,
        }
    elif gpu_memory_gb >= 8:
        return "unsloth/Qwen2.5-7B-Instruct-bnb-4bit", {
            "max_seq_length": 2048,
            "lora_r": 8,
            "lora_alpha": 16,
            "batch_size": 1,
            "gradient_accumulation": 8,
        }
    else:
        return "unsloth/Qwen2.5-3B-Instruct-bnb-4bit", {
            "max_seq_length": 2048,
            "lora_r": 8,
            "lora_alpha": 16,
            "batch_size": 1,
            "gradient_accumulation": 8,
        }


def run_finetuning(
    training_data: Path,
    output_dir: Path,
    base_model: str | None = None,
    epochs: int = 3,
    learning_rate: float = 2e-4,
    export_gguf: bool = True,
) -> bool:
    """
    Run LoRA fine-tuning on the base model.
    
    Args:
        training_data: Path to training JSONL file
        output_dir: Where to save the fine-tuned model
        base_model: Base model to fine-tune (auto-detected if None)
        epochs: Number of training epochs
        learning_rate: Learning rate for training
    
    Returns:
        True if successful, False otherwise
    """
    try:
        os.environ.setdefault("UNSLOTH_RETURN_LOGITS", "1")
        import torch
        from datasets import load_dataset
        from trl import SFTConfig
        from trl.trainer.sft_trainer import SFTTrainer
        from unsloth import FastLanguageModel
        from unsloth.chat_templates import get_chat_template
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("   Run: pip install unsloth datasets trl")
        return False
    
    # Check GPU
    gpu_info = check_gpu_available()
    if not gpu_info["available"]:
        print(f"❌ No GPU available: {gpu_info['reason']}")
        print("   Fine-tuning requires a CUDA GPU")
        return False
    
    print(f"🖥️  GPU: {gpu_info['name']} ({gpu_info['memory_gb']} GB)")
    
    # Select model based on GPU
    if base_model is None:
        base_model, config = get_recommended_model(gpu_info["memory_gb"])
    else:
        _, config = get_recommended_model(gpu_info["memory_gb"])
    
    print(f"📦 Base model: {base_model}")
    print(f"⚙️  Config: {config}")
    
    # Load base model with 4-bit quantization
    print("\n📥 Loading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model,
        max_seq_length=config["max_seq_length"],
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )
    
    # Apply LoRA adapters
    print("🔧 Applying LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=config["lora_r"],
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=config["lora_alpha"],
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    
    # Set up chat template
    tokenizer = get_chat_template(
        tokenizer,
        chat_template="chatml",
    )
    if tokenizer.pad_token in (None, "<PAD_TOKEN>", "<|PAD_TOKEN|>"):
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # Load training data
    print(f"📚 Loading training data from {training_data}...")
    dataset = load_dataset("json", data_files=str(training_data), split="train")

    def formatting_func(example: dict[Any, Any]) -> str:
        """Format a dataset row into a chat-formatted training string."""
        messages = example.get("messages", [])
        return str(
            tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=False,
            )
        )

    print(f"   {len(dataset)} training examples loaded")
    
    # Training arguments
    output_dir.mkdir(parents=True, exist_ok=True)
    
    training_args = SFTConfig(
        output_dir=str(output_dir / "checkpoints"),
        per_device_train_batch_size=config["batch_size"],
        gradient_accumulation_steps=config["gradient_accumulation"],
        warmup_steps=10,
        num_train_epochs=epochs,
        learning_rate=learning_rate,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        save_strategy="epoch",
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
        use_liger_kernel=False,
        eos_token=tokenizer.eos_token,
        pad_token=tokenizer.pad_token or tokenizer.eos_token,
    )
    training_args.eos_token = tokenizer.eos_token
    training_args.pad_token = tokenizer.pad_token

    # Create trainer
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer,
        formatting_func=formatting_func,
    )
    
    # Train!
    print("\n🚀 Starting training...")
    print("   This will take ~30 minutes on a consumer GPU\n")
    
    trainer.train()
    
    # Save the model
    print("\n💾 Saving fine-tuned model...")
    
    # Save LoRA adapters
    model.save_pretrained(output_dir / "lora")
    tokenizer.save_pretrained(output_dir / "lora")
    
    # Merge and save full model for faster inference
    print("🔀 Merging LoRA weights...")
    model.save_pretrained_merged(
        output_dir / "merged",
        tokenizer,
        save_method="merged_16bit",
    )
    
    # Export to GGUF for Ollama
    if export_gguf:
        print("📦 Exporting to GGUF format...")
        model.save_pretrained_gguf(
            output_dir / "gguf",
            tokenizer,
            quantization_method="q4_k_m",
        )
    else:
        print("⚠️  Skipping GGUF export (omit --skip-gguf to generate it here).")
    
    print("\n✅ Fine-tuning complete!")
    print(f"   LoRA adapters: {output_dir / 'lora'}")
    print(f"   Merged model: {output_dir / 'merged'}")
    print(f"   GGUF model: {output_dir / 'gguf'}")
    
    return True


def create_ollama_modelfile(gguf_path: Path, output_path: Path) -> Path:
    """Create Ollama Modelfile for the fine-tuned model."""
    
    modelfile_content = f'''# SploitGPT - Fine-tuned security model
FROM {gguf_path}

# System prompt
SYSTEM """You are SploitGPT, an autonomous penetration testing assistant running inside a Kali Linux container. You help security professionals conduct authorized penetration tests.

You have access to tools for running terminal commands, searching Metasploit, and executing exploits. Always ask for clarification before running intrusive or potentially dangerous commands.

Be thorough in reconnaissance, methodical in exploitation, and clear in your communication."""

# Parameters optimized for security tasks
PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER num_ctx 4096
PARAMETER stop "<|im_end|>"
'''
    
    modelfile_path = output_path / "Modelfile"
    modelfile_path.write_text(modelfile_content)
    
    return modelfile_path


def register_with_ollama(gguf_dir: Path, model_name: str = "sploitgpt") -> bool:
    """Register the fine-tuned model with Ollama."""
    
    # Find the GGUF file
    gguf_files = list(gguf_dir.glob("*.gguf"))
    if not gguf_files:
        print(f"❌ No GGUF file found in {gguf_dir}")
        return False
    
    gguf_path = gguf_files[0]
    
    # Create Modelfile
    modelfile_path = create_ollama_modelfile(gguf_path, gguf_dir)
    
    # Register with Ollama
    print(f"📝 Registering {model_name} with Ollama...")
    
    try:
        result = subprocess.run(
            ["ollama", "create", model_name, "-f", str(modelfile_path)],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0:
            print(f"❌ Failed to register with Ollama: {result.stderr}")
            return False
        
        print(f"✅ Model registered as '{model_name}'")
        print(f"   Run: ollama run {model_name}")
        return True
        
    except FileNotFoundError:
        print("❌ Ollama not found. Install from https://ollama.ai")
        return False


async def main() -> None:
    """CLI entry point for fine-tuning."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Fine-tune SploitGPT model")
    parser.add_argument(
        "--data",
        default="data/training/sploitgpt_train.jsonl",
        help="Path to training data JSONL"
    )
    parser.add_argument(
        "--output",
        default="models/sploitgpt",
        help="Output directory for fine-tuned model"
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Base model (auto-detected based on GPU if not specified)"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs"
    )
    parser.add_argument(
        "--skip-gguf",
        action="store_true",
        help="Skip exporting a GGUF (useful when disk space is limited; you can export later)",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Register model with Ollama after training"
    )
    
    args = parser.parse_args()
    
    # Check GPU first
    gpu_info = check_gpu_available()
    print("=" * 50)
    print("🔥 SploitGPT Install-Time Fine-Tuning")
    print("=" * 50)
    
    if gpu_info["available"]:
        print(f"✅ GPU detected: {gpu_info['name']}")
        print(f"   Memory: {gpu_info['memory_gb']} GB")
        print(f"   CUDA: {gpu_info['cuda_version']}")
    else:
        print(f"❌ No GPU: {gpu_info['reason']}")
        print("\nFine-tuning requires a CUDA GPU.")
        print("Options:")
        print("  1. Use a cloud GPU (Vast.ai, RunPod, etc.)")
        print("  2. Purchase pre-trained model from sploitgpt.com")
        print("  3. Use base model without fine-tuning (reduced accuracy)")
        sys.exit(1)
    
    print()
    
    # Run fine-tuning
    success = run_finetuning(
        training_data=Path(args.data),
        output_dir=Path(args.output),
        base_model=args.model,
        epochs=args.epochs,
        export_gguf=not args.skip_gguf,
    )
    
    if success and args.register:
        register_with_ollama(Path(args.output) / "gguf")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
