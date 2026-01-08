#!/usr/bin/env bash
# Run the real SploitGPT agent (CLI) inside the Podman container.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

if ! podman info >/dev/null 2>&1; then
  echo "[!] Podman is not accessible for the current user."
  exit 1
fi

# Ensure core services are up
podman compose -f compose.yaml up -d ollama sploitgpt >/dev/null

# Attach to the agent CLI (tool-enabled) inside the container
podman compose -f compose.yaml exec -it sploitgpt sploitgpt --cli
