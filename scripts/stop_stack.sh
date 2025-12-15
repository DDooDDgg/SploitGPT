#!/usr/bin/env bash
set -euo pipefail

# Stop the entire SploitGPT stack (SploitGPT + Ollama).
cd "$(dirname "$(readlink -f "$0")")/.."

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not accessible for the current user."
  echo "    Fix: sudo usermod -aG docker $USER && newgrp docker"
  exit 1
fi

echo "[*] Stopping SploitGPT stack..."
docker compose down
echo "[+] Stack stopped."
