#!/usr/bin/env python3
"""
Merge LoRA adapter with base model and save as full precision model.
This creates a merged model that can then be converted to GGUF.

The LoRA adapter was trained on unsloth/qwen2.5-7b-instruct-bnb-4bit but
the adapter weights can be merged with the full precision Qwen/Qwen2.5-7B-Instruct
since they share the same architecture.
"""

import argparse
import gc
import os
import torch
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Merge LoRA adapter with base model")
    parser.add_argument(
        "--adapter-path",
        type=str,
        default="models-adapters/sploitgpt-7b-v5.10e",
        help="Path to LoRA adapter directory",
    )
    parser.add_argument(
        "--output-path",
        type=str,
        default="models-merged/sploitgpt-7b-v5.10e",
        help="Path to save merged model",
    )
    parser.add_argument(
        "--base-model",
        type=str,
        default="Qwen/Qwen2.5-7B-Instruct",
        help="Base model to merge with (full precision version)",
    )
    parser.add_argument(
        "--low-memory",
        action="store_true",
        help="Use CPU-only mode to save GPU memory (slower but works with limited RAM)",
    )
    args = parser.parse_args()

    adapter_path = Path(args.adapter_path)
    output_path = Path(args.output_path)

    print(f"Loading base model: {args.base_model}")
    print(f"Adapter path: {adapter_path}")
    print(f"Output path: {output_path}")
    print(f"Low memory mode: {args.low_memory}")

    # Import here to avoid slow startup for --help
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    # Determine device map based on memory mode
    if args.low_memory:
        # CPU only - slower but uses less GPU memory
        device_map = "cpu"
        torch_dtype = torch.float32  # CPU works better with float32
        print("\nUsing CPU-only mode (slower but memory efficient)...")
    else:
        # Auto device mapping - uses GPU when available
        device_map = "auto"
        torch_dtype = torch.bfloat16
        print("\nUsing auto device mapping...")

    print(f"\nLoading base model in {torch_dtype}...")
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        device_map=device_map,
        torch_dtype=torch_dtype,
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )

    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)

    print(f"Loading LoRA adapter from {adapter_path}...")
    model = PeftModel.from_pretrained(
        base_model,
        str(adapter_path),
        torch_dtype=torch_dtype,
    )

    print("Merging LoRA weights into base model...")
    model = model.merge_and_unload()

    print(f"Saving merged model to {output_path}...")
    output_path.mkdir(parents=True, exist_ok=True)

    # Save in safetensors format with bfloat16 for GGUF conversion
    # Convert to bfloat16 before saving if we used float32
    if torch_dtype == torch.float32:
        print("Converting to bfloat16 for saving...")
        model = model.to(torch.bfloat16)

    model.save_pretrained(
        output_path,
        safe_serialization=True,
        max_shard_size="4GB",
    )
    tokenizer.save_pretrained(output_path)

    print("\nMerge complete!")
    print(f"Merged model saved to: {output_path}")

    # Cleanup
    del model
    del base_model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()


if __name__ == "__main__":
    main()
