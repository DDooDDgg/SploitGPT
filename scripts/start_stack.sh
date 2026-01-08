#!/usr/bin/env bash
set -euo pipefail

# Start SploitGPT stack (SploitGPT + Ollama) in detached mode.
cd "$(dirname "$(readlink -f "$0")")/.."

if ! podman info >/dev/null 2>&1; then
  echo "[!] Podman is not accessible for the current user."
  exit 1
fi

echo "[*] Starting SploitGPT stack (sploitgpt + ollama)..."
podman compose -f compose.yaml up -d ollama sploitgpt
echo "[+] Stack is up. Run './sploitgpt.sh' to launch the TUI."
