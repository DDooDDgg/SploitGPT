"""Generate synthetic instruction/response pairs from SploitGPT docs.

Workflow:
1. Load exported docs (see scripts/export_docs.py) and optional exploit DB JSON.
2. Create prompt templates for various phases/services.
3. Optionally call a local LLM via Litellm (Ollama/transformers) to enrich responses.

Outputs JSONL with fields:
  {
    "prompt": "...",
    "response": "...",
    "metadata": {...}
  }
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Iterable

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from litellm import completion


def _load_docs(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("Expected list of documents")
    return data


def _base_prompts(docs: list[dict], limit: int) -> Iterable[tuple[str, dict]]:
    random.shuffle(docs)
    count = 0
    for doc in docs:
        meta = doc.get("metadata", {})
        content = doc.get("content", "").strip()
        if not content:
            continue

        if meta.get("kind") == "command":
            prompt = (
                f"You are preparing commands for {meta.get('category', '').lower()} tasks. "
                "Summarize when to use this command and what it does:\n\n"
                f"{content}"
            )
        elif meta.get("kind") == "technique":
            prompt = (
                f"Explain MITRE technique {meta.get('id', '')} for pentesters and outline "
                "how to detect and leverage it:\n\n"
                f"{content}"
            )
        else:
            prompt = f"Summarize this pentest methodology section:\n\n{content}"

        yield prompt, meta
        count += 1
        if limit and count >= limit:
            break


def _llm_generate(prompt: str, model: str, temperature: float) -> str:
    resp = completion(
        model=model,
        messages=[
            {"role": "system", "content": "You are SploitGPT, an expert pentest assistant."},
            {"role": "user", "content": prompt},
        ],
        temperature=temperature,
        max_tokens=600,
    )
    return resp.choices[0].message.get("content", "").strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic instructions")
    parser.add_argument("--docs", type=Path, default=Path("data/rag_docs.json"))
    parser.add_argument("--output", type=Path, default=Path("data/training/instructions.jsonl"))
    parser.add_argument("--model", type=str, default="ollama/llama3:8b")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--temperature", type=float, default=0.7)
    args = parser.parse_args()

    docs = _load_docs(args.docs)
    args.output.parent.mkdir(parents=True, exist_ok=True)

    with args.output.open("w", encoding="utf-8") as fh:
        for prompt, meta in _base_prompts(docs, limit=args.count):
            response = _llm_generate(prompt, args.model, args.temperature)
            if not response:
                continue
            fh.write(
                json.dumps({
                    "prompt": prompt,
                    "response": response,
                    "metadata": meta,
                })
                + "\n"
            )

    print(f"Wrote synthetic instructions to {args.output}")


if __name__ == "__main__":
    main()
