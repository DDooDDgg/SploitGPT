"""Convert instruction data into chat-format JSONL for fine-tuning."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_instructions(path: Path) -> list[dict]:
    data: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            data.append(json.loads(line))
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Prep training dataset")
    parser.add_argument("--input", type=Path, default=Path("data/training/instructions.jsonl"))
    parser.add_argument("--output", type=Path, default=Path("data/training/synthetic_chat.jsonl"))
    args = parser.parse_args()

    instructions = load_instructions(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.output.open("w", encoding="utf-8") as out:
        for item in instructions:
            prompt = item.get("prompt", "").strip()
            response = item.get("response", "").strip()
            if not prompt or not response:
                continue
            messages = [
                {"role": "user", "content": prompt},
                {"role": "assistant", "content": response},
            ]
            out.write(json.dumps({"messages": messages, "metadata": item.get("metadata", {})}) + "\n")

    print(f"Wrote chat dataset to {args.output}")


if __name__ == "__main__":
    main()
