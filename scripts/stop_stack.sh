#!/usr/bin/env bash
set -euo pipefail

# Stop the entire SploitGPT stack (SploitGPT + Ollama).
cd "$(dirname "$(readlink -f "$0")")/.."

if ! podman info >/dev/null 2>&1; then
  echo "[!] Podman is not accessible for the current user."
  exit 1
fi

echo "[*] Stopping SploitGPT stack..."
podman compose -f compose.yaml down
echo "[+] Stack stopped."
