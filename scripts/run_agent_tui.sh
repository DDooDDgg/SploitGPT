#!/usr/bin/env bash
# Launch the built-in SploitGPT Textual TUI (agent + tools) inside Podman.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

if ! podman info >/dev/null 2>&1; then
  echo "[!] Podman is not accessible for the current user."
  exit 1
fi

# Ensure core services are up
podman compose -f compose.yaml up -d ollama sploitgpt >/dev/null

# Launch the Textual TUI inside the container (uses the full SploitGPT agent)
exec podman compose -f compose.yaml exec -it sploitgpt sploitgpt
