"""
Fine-tune SploitGPT using Unsloth for fast LoRA training.

Optimized for cloud GPU training with quantization export for local inference.
Supports both SFTTrainer (default) and standard Trainer (--simple flag) modes.
"""

import argparse
import json
from pathlib import Path
from typing import Any


def load_training_data(data_path: Path) -> list[dict]:
    """Load training examples from JSONL."""
    examples = []
    with open(data_path) as f:
        for line in f:
            if line.strip():
                examples.append(json.loads(line))
    return examples


def _ensure_lora_trainable(model: Any) -> None:
    """Ensure LoRA parameters are trainable after loading an adapter."""
    trainable = 0
    total = 0
    for name, param in model.named_parameters():
        if "lora" in name:
            param.requires_grad = True
        total += param.numel()
        if param.requires_grad:
            trainable += param.numel()

    if trainable == 0:
        raise RuntimeError("No trainable parameters found after loading adapter.")

    if hasattr(model, "enable_input_require_grads"):
        model.enable_input_require_grads()

    print(f"Trainable params after resume: {trainable} / {total}")


def format_chat_example(example: dict) -> dict[str, Any]:
    """
    Format example into chat template format with proper tool_calls serialization.

    Handles both old format (prompt/response) and new format (messages).
    Tool calls are serialized as XML <tool_call> tags with JSON content.
    """
    # Handle both old format (prompt/response) and new format (messages)
    if "messages" in example:
        messages = example["messages"]
    elif "prompt" in example and "response" in example:
        # Convert old format to messages format
        messages = [
            {"role": "user", "content": example["prompt"]},
            {"role": "assistant", "content": example["response"]},
        ]
    else:
        # Skip invalid examples
        return {"text": ""}

    formatted_parts = []

    for msg in messages:
        role = msg["role"]
        content = msg.get("content", "")

        # Start message with proper role
        formatted_parts.append(f"<|im_start|>{role}\n")

        # Add content if present
        if content:
            formatted_parts.append(f"{content}\n")

        # If assistant has tool_calls, serialize them after reasoning/content
        if role == "assistant" and "tool_calls" in msg and msg["tool_calls"]:
            for tc in msg["tool_calls"]:
                # Serialize tool call as XML with function details
                func = tc.get("function", {})
                tool_call_json = json.dumps(
                    {"name": func.get("name", ""), "arguments": func.get("arguments", {})}
                )
                formatted_parts.append(f"<tool_call>{tool_call_json}</tool_call>\n")

        formatted_parts.append("<|im_end|>\n")

    return {"text": "".join(formatted_parts)}


def train_with_sft(args, model, tokenizer, formatted_examples):
    """Train using SFTTrainer from TRL library."""
    import json
    import tempfile

    import torch
    from datasets import Dataset
    from trl import SFTConfig, SFTTrainer

    # Save formatted examples to temp file to avoid pickling issues
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".jsonl") as f:
        temp_file = f.name
        for ex in formatted_examples:
            f.write(json.dumps(ex) + "\n")

    # Load dataset from file
    dataset = Dataset.from_json(temp_file)

    # Training arguments
    training_args = SFTConfig(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,
        warmup_steps=10,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        save_strategy="epoch",
        save_total_limit=2,
        dataloader_num_workers=0,  # Disable multiprocessing to avoid pickling issues
        dataset_num_proc=1,  # Avoid multiprocessing pickling in dataset.map
        max_length=args.max_seq_length,
    )

    # Trainer
    print("\nStarting training with SFTTrainer...")
    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        args=training_args,
        processing_class=tokenizer,
    )

    trainer.train()
    return trainer


def train_with_standard(args, model, tokenizer, formatted_examples):
    """Train using standard Trainer (fallback mode for pickling issues)."""
    import torch
    from datasets import Dataset
    from transformers import DataCollatorForLanguageModeling, Trainer, TrainingArguments

    # Filter out empty examples and tokenize
    formatted_texts = [ex["text"] for ex in formatted_examples if ex["text"]]
    print(f"   Formatted {len(formatted_texts)} valid examples")

    print("Tokenizing...")

    def tokenize_function(text):
        return tokenizer(text, truncation=True, max_length=args.max_seq_length)

    tokenized_data = [tokenize_function(text) for text in formatted_texts]
    dataset = Dataset.from_dict(
        {
            "input_ids": [item["input_ids"] for item in tokenized_data],
            "attention_mask": [item["attention_mask"] for item in tokenized_data],
        }
    )

    # Data collator
    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    # Training arguments
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,
        warmup_steps=10,
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        save_strategy="epoch",
        save_total_limit=2,
        dataloader_num_workers=0,
    )

    # Trainer
    print("\nStarting training with standard Trainer...")
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        data_collator=data_collator,
    )

    trainer.train()
    return trainer


def main():
    from peft import PeftModel
    from unsloth import FastLanguageModel

    parser = argparse.ArgumentParser(description="Fine-tune SploitGPT")
    parser.add_argument(
        "--base-model",
        default="unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
        help="Base model to fine-tune",
    )
    parser.add_argument("--data", required=True, help="Training data JSONL path")
    parser.add_argument(
        "--output-dir",
        default="models/sploitgpt-7b-trained",
        help="Output directory for model",
    )
    parser.add_argument("--lora-r", type=int, default=64, help="LoRA rank")
    parser.add_argument("--lora-alpha", type=int, default=128, help="LoRA alpha")
    parser.add_argument("--epochs", type=int, default=3, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    parser.add_argument(
        "--gradient-accumulation",
        type=int,
        default=4,
        help="Gradient accumulation steps",
    )
    parser.add_argument("--learning-rate", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--max-seq-length", type=int, default=4096, help="Max sequence length")
    parser.add_argument(
        "--resume-adapter",
        type=str,
        default="",
        help="Optional path to an existing LoRA adapter to continue training",
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Use standard Trainer instead of SFTTrainer (fallback for pickling issues)",
    )

    args = parser.parse_args()

    print("SploitGPT Fine-Tuning")
    print(f"  Base model: {args.base_model}")
    print(f"  Data: {args.data}")
    print(f"  Output: {args.output_dir}")
    print(f"  Mode: {'Standard Trainer' if args.simple else 'SFTTrainer'}")

    # Load model with Unsloth (4bit quantized for training speed)
    print("\nLoading model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.base_model,
        max_seq_length=args.max_seq_length,
        dtype=None,  # Auto-detect
        load_in_4bit=True,  # 4bit quantization for training
    )

    if args.resume_adapter:
        print(f"Loading LoRA adapter for continued training: {args.resume_adapter}")
        model = PeftModel.from_pretrained(model, args.resume_adapter, is_trainable=True)
        _ensure_lora_trainable(model)
    else:
        # Add LoRA adapters
        print(f"Adding LoRA adapters (r={args.lora_r}, alpha={args.lora_alpha})...")
        model = FastLanguageModel.get_peft_model(
            model,
            r=args.lora_r,
            lora_alpha=args.lora_alpha,
            lora_dropout=0,
            target_modules=[
                "q_proj",
                "k_proj",
                "v_proj",
                "o_proj",
                "gate_proj",
                "up_proj",
                "down_proj",
            ],
            use_gradient_checkpointing="unsloth",  # Unsloth optimization
            random_state=42,
        )

    # Load and format training data
    print("\nLoading training data...")
    examples = load_training_data(Path(args.data))
    print(f"   Found {len(examples)} examples")

    # Format examples with proper tool_calls serialization
    print("Formatting examples with tool_calls serialization...")
    formatted_examples = [format_chat_example(ex) for ex in examples]

    # Train with selected mode
    if args.simple:
        train_with_standard(args, model, tokenizer, formatted_examples)
    else:
        train_with_sft(args, model, tokenizer, formatted_examples)

    # Save final model
    print("\nSaving model...")
    model.save_pretrained(args.output_dir)
    tokenizer.save_pretrained(args.output_dir)

    print(f"\nTraining complete! Model saved to {args.output_dir}")
    print("\nNext steps:")
    print(f"   1. Merge LoRA: python -m sploitgpt.training.merge --model {args.output_dir}")
    print(f"   2. Quantize: python -m sploitgpt.training.quantize --model {args.output_dir}")


if __name__ == "__main__":
    main()
