#!/usr/bin/env python3
"""
Upload SploitGPT GGUF models to HuggingFace.

Usage:
    # First login to HuggingFace
    huggingface-cli login

    # Then run this script
    python scripts/upload_to_hf.py
"""

from huggingface_hub import HfApi, create_repo
from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser(description="Upload SploitGPT models to HuggingFace")
    parser.add_argument(
        "--repo-id",
        default="cheeseman2422/sploitgpt-7b-v5-gguf",
        help="HuggingFace repo ID",
    )
    parser.add_argument(
        "--models-dir",
        default="models-gguf/sploitgpt-7b-v5.10e/gguf",
        help="Path to GGUF models directory",
    )
    args = parser.parse_args()

    api = HfApi()
    models_dir = Path(args.models_dir)

    # Create repo if it doesn't exist
    try:
        create_repo(args.repo_id, repo_type="model", exist_ok=True)
        print(f"Repository {args.repo_id} ready")
    except Exception as e:
        print(f"Note: {e}")

    # Files to upload
    files = [
        ("model-Q5_K_M.gguf", "Best quality (12GB+ VRAM)"),
        ("model-Q4_K_M.gguf", "Good quality, smaller (8GB+ VRAM)"),
    ]

    for filename, description in files:
        filepath = models_dir / filename
        if filepath.exists():
            print(f"Uploading {filename} ({filepath.stat().st_size / 1e9:.1f}GB)...")
            api.upload_file(
                path_or_fileobj=str(filepath),
                path_in_repo=filename,
                repo_id=args.repo_id,
                repo_type="model",
            )
            print(f"  Uploaded: {filename}")
        else:
            print(f"  Skipped (not found): {filename}")

    # Create README
    readme_content = """---
license: apache-2.0
base_model: Qwen/Qwen2.5-7B-Instruct
tags:
  - security
  - pentesting
  - ollama
  - gguf
language:
  - en
pipeline_tag: text-generation
---

# SploitGPT 7B v5 GGUF

Fine-tuned Qwen2.5-7B model for autonomous penetration testing. Designed for use with [SploitGPT](https://github.com/cheeseman2422/SploitGPT).

## Model Variants

| File | Size | VRAM | Description |
|------|------|------|-------------|
| `model-Q5_K_M.gguf` | 5.1GB | 12GB+ | Best quality |
| `model-Q4_K_M.gguf` | 4.4GB | 8GB+ | Good quality, faster inference |

## Quick Start

```bash
# Download model (choose based on VRAM)
wget https://huggingface.co/cheeseman2422/sploitgpt-7b-v5-gguf/resolve/main/model-Q5_K_M.gguf

# Create Ollama model
ollama create sploitgpt-7b-v5.10e:q5 -f - <<'EOF'
FROM ./model-Q5_K_M.gguf
TEMPLATE \"\"\"{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
\"\"\"
PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
PARAMETER temperature 0.3
PARAMETER top_p 0.9
EOF

# Verify
ollama list | grep sploitgpt
```

## Training

- **Base Model**: Qwen2.5-7B-Instruct
- **Training Method**: LoRA fine-tuning with Unsloth
- **Training Data**: MITRE ATT&CK techniques, Metasploit modules, pentesting workflows
- **LoRA Config**: r=64, alpha=128

## Capabilities

- Tool calling for security tools (nmap, metasploit, etc.)
- MITRE ATT&CK knowledge retrieval
- Penetration testing workflow reasoning
- Scope-aware command generation

## Usage with SploitGPT

See the main repository: https://github.com/cheeseman2422/SploitGPT

```bash
git clone https://github.com/cheeseman2422/SploitGPT.git
cd SploitGPT
./install.sh  # Downloads model automatically
./sploitgpt.sh --tui
```

## License

- Model weights: Apache 2.0 (following Qwen2.5 license)
- Fine-tuning data and methodology: MIT

## Disclaimer

This model is for authorized security testing only. Users are responsible for ensuring they have proper authorization before using this model for penetration testing activities.
"""

    readme_path = models_dir / "HF_README.md"
    readme_path.write_text(readme_content)

    api.upload_file(
        path_or_fileobj=str(readme_path),
        path_in_repo="README.md",
        repo_id=args.repo_id,
        repo_type="model",
    )
    print("Uploaded README.md")

    print(f"\nDone! Models available at: https://huggingface.co/{args.repo_id}")


if __name__ == "__main__":
    main()
