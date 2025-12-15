#!/bin/bash
# Quick start script for SploitGPT

set -e

# Ensure Docker daemon is accessible
if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not accessible for the current user."
  echo "    Fix (recommended): sudo usermod -aG docker $USER && newgrp docker"
  echo "    Or run docker commands with sudo (less ideal for file permissions)."
  exit 1
fi

# Ensure the toolbox container is running.
# (The compose service runs as a long-lived container; SploitGPT is executed via exec.)
if [ -z "$(docker compose ps --status running -q sploitgpt 2>/dev/null)" ]; then
    docker compose up -d --build
fi

docker compose exec sploitgpt sploitgpt "$@"
