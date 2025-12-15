#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: scripts/validate.sh [--docker] [--docker-build]

Runs local quality gates:
  - pytest
  - ruff
  - mypy

Optional:
  --docker        Also run scripts/smoke_docker.sh
  --docker-build  If --docker is set, force a docker rebuild (smoke_docker.sh without --no-build)
USAGE
}

DO_DOCKER=false
DO_DOCKER_BUILD=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --docker)
      DO_DOCKER=true
      ;;
    --docker-build)
      DO_DOCKER_BUILD=true
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

if [ "$DO_DOCKER" = true ]; then
  echo "[*] docker smoke"
  if [ "$DO_DOCKER_BUILD" = true ]; then
    ./scripts/smoke_docker.sh
  else
    ./scripts/smoke_docker.sh --no-build
  fi
fi

echo "[+] validate OK"
