#!/bin/bash
# Quick start script for SploitGPT (works from any directory, Podman-first)

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "$ROOT_DIR"

# Launch the built-in Textual TUI (agent-driven) inside the container stack
exec "${ROOT_DIR}/scripts/run_agent_tui.sh" "$@"
