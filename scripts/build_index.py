"""Build embedding index for SploitGPT docs using sentence-transformers.

Usage:
    python scripts/build_index.py --docs data/rag_docs.json \
        --encoder sentence-transformers/all-MiniLM-L12-v2 \
        --output data/rag.index

The output is a simple JSON with vectors stored in a .npy file for now.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer


def load_docs(path: Path) -> list[dict]:
    data = json.loads(path.read_text())
    if not isinstance(data, list):
        raise ValueError("Docs must be a list")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Build embedding index")
    parser.add_argument("--docs", type=Path, default=Path("data/rag_docs.json"))
    parser.add_argument("--encoder", type=str, default="sentence-transformers/all-MiniLM-L12-v2")
    parser.add_argument("--output", type=Path, default=Path("data/rag.index"))
    args = parser.parse_args()

    docs = load_docs(args.docs)
    model = SentenceTransformer(args.encoder)

    contents = [doc.get("content", "") for doc in docs]
    embeddings = model.encode(contents, batch_size=64, show_progress_bar=True, normalize_embeddings=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    np.save(args.output.with_suffix(".npy"), embeddings)
    args.output.write_text(json.dumps(docs))

    print(f"Saved {len(docs)} embeddings to {args.output.with_suffix('.npy')}")


if __name__ == "__main__":
    main()
