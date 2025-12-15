#!/usr/bin/env bash
set -euo pipefail

# Start SploitGPT stack (SploitGPT + Ollama) in detached mode.
cd "$(dirname "$(readlink -f "$0")")/.."

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not accessible for the current user."
  echo "    Fix: sudo usermod -aG docker $USER && newgrp docker"
  exit 1
fi

echo "[*] Starting SploitGPT stack (sploitgpt + ollama)..."
docker compose up -d ollama sploitgpt
echo "[+] Stack is up. Run './sploitgpt.sh' to launch the TUI."
