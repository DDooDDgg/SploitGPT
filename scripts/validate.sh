#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: scripts/validate.sh [--container] [--container-build]

Runs local quality gates:
  - pytest
  - ruff
  - mypy

Optional:
  --container        Also run scripts/smoke_podman.sh
  --container-build  If --container is set, force a rebuild (smoke_podman.sh without --no-build)

Legacy aliases (deprecated):
  --docker        Alias for --container
  --docker-build  Alias for --container-build
USAGE
}

DO_CONTAINER=false
DO_CONTAINER_BUILD=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --container|--docker)
      DO_CONTAINER=true
      ;;
    --container-build|--docker-build)
      DO_CONTAINER_BUILD=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

VENV_BIN="./.venv/bin"

if [ ! -x "$VENV_BIN/pytest" ] || [ ! -x "$VENV_BIN/ruff" ] || [ ! -x "$VENV_BIN/mypy" ]; then
  echo "[!] Expected tools not found in $VENV_BIN" >&2
  echo "    Create venv and install dev deps, then retry." >&2
  exit 1
fi

echo "[*] pytest"
"$VENV_BIN/pytest" -q

echo "[*] ruff"
"$VENV_BIN/ruff" check sploitgpt scripts tests

echo "[*] mypy"
"$VENV_BIN/mypy" sploitgpt

if [ "$DO_CONTAINER" = true ]; then
  echo "[*] container smoke"
  if [ "$DO_CONTAINER_BUILD" = true ]; then
    ./scripts/smoke_podman.sh
  else
    ./scripts/smoke_podman.sh --no-build
  fi
fi

echo "[+] validate OK"
