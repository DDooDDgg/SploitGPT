#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [ "${1:-}" = "--legacy" ]; then
  shift
  exec ./install-legacy.sh "$@"
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 not found."
  echo "    Either install python3 or run the legacy installer: ./install-legacy.sh"
  exit 1
fi

# Canonical installer (single source of truth)
exec python3 scripts/install.py "$@"
