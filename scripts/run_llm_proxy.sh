#!/usr/bin/env bash
# Start a local OpenAI-compatible proxy that points at the Ollama-served sploitgpt-local model.
# Requires: python venv with litellm[proxy] installed, and Ollama running on 172.17.0.1:11434.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${VENV:-${ROOT_DIR}/.venv}"
CONFIG="${ROOT_DIR}/config/litellm.yaml"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4000}"

if [ ! -f "${VENV}/bin/activate" ]; then
  echo "[!] venv not found at ${VENV}. Create one first: python3 -m venv .venv"
  exit 1
fi

source "${VENV}/bin/activate"

if ! python - <<'PY' >/dev/null 2>&1; then
from importlib.util import find_spec
import sys
missing = [pkg for pkg in ("litellm",) if find_spec(pkg) is None]
if missing:
    print(" ".join(missing))
    sys.exit(1)
PY
  echo "[+] Installing litellm[proxy] ..."
  pip install -q "litellm[proxy]"
fi

echo "[*] Starting LiteLLM proxy on http://${HOST}:${PORT} using ${CONFIG}"
exec litellm --config "${CONFIG}" --port "${PORT}" --host "${HOST}"
