#!/usr/bin/env bash
# Launch the Opencode TUI against the local SploitGPT model via the LiteLLM proxy.
# - Prefers the vendored fork (vendor/opencode) if its CLI exists.
# - Ensures the docker stack is up.
# - Starts the LiteLLM proxy if not already listening.
# - Exports OpenAI-compatible env vars and runs `opencode`.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_LOG="${ROOT_DIR}/logs/litellm_proxy.log"
# Isolate config/cache/data so we don't clobber a user's global Opencode install.
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config/sploitgpt-opencode}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share/sploitgpt-opencode}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state/sploitgpt-opencode}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache/sploitgpt-opencode}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-4000}"
OPENAI_API_BASE="http://${HOST}:${PORT}/v1"
OPENAI_API_KEY="${OPENAI_API_KEY:-local-gguf}"
OPENAI_MODEL="${OPENAI_MODEL:-sploitgpt-local}"
VENDORED_BUN="${ROOT_DIR}/vendor/opencode"
# Bun binary (fallback to ~/.bun/bin/bun if not in PATH)
BUN_BIN="$(command -v bun || true)"
if [ -z "${BUN_BIN}" ] && [ -x "${HOME}/.bun/bin/bun" ]; then
  BUN_BIN="${HOME}/.bun/bin/bun"
fi

cd "${ROOT_DIR}"

# Prefer vendored bun-based TUI; fall back to global opencode
if [ -n "${BUN_BIN}" ] && [ -d "${VENDORED_BUN}" ]; then
  OPENCODE_CMD=("${BUN_BIN}" run dev)
  OPENCODE_CWD="${VENDORED_BUN}"
else
  OPENCODE_BIN="$(command -v opencode || true)"
  if [ -n "${OPENCODE_BIN}" ]; then
    OPENCODE_CMD=("${OPENCODE_BIN}")
    OPENCODE_CWD="${ROOT_DIR}"
  else
    cat <<'MSG'
[!] opencode CLI not found.
    To use the vendored fork:
      cd vendor/opencode
      bun install
      bun run dev
    Or install opencode globally (npm/pnpm).
MSG
    exit 1
  fi
fi

# Ensure Docker is available
if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon not accessible. Start Docker or fix permissions (sudo usermod -aG docker $USER && newgrp docker)."
  exit 1
fi

# Ensure stack is up (ollama + sploitgpt). Do not rebuild.
docker compose up -d ollama sploitgpt >/dev/null

# Start LiteLLM proxy if not already listening on PORT
if ! ss -lnt "( sport = :${PORT} )" | grep -q ":${PORT}" 2>/dev/null; then
  mkdir -p "${ROOT_DIR}/logs"
  echo "[*] Starting LiteLLM proxy on ${OPENAI_API_BASE} (log: ${PROXY_LOG})"
  nohup "${ROOT_DIR}/scripts/run_llm_proxy.sh" >"${PROXY_LOG}" 2>&1 &
  sleep 2
fi

# Set terminal title to SploitGPT
printf '\033]0;SploitGPT\007'

export OPENAI_API_BASE
export OPENAI_API_KEY
export OPENAI_MODEL
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${OPENAI_API_BASE}}"
export OPENAI_API_URL="${OPENAI_API_URL:-${OPENAI_API_BASE}}"
export OPENAI_API_HOST="${OPENAI_API_HOST:-${OPENAI_API_BASE}}"
export OPENAI_MODEL_ID="${OPENAI_MODEL_ID:-${OPENAI_MODEL}}"

cat <<'BANNER'
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝
              [ SploitGPT — powered by your local model ]
BANNER
echo "[*] Launching Opencode TUI via LiteLLM proxy at ${OPENAI_API_BASE} with model=${OPENAI_MODEL}"
cd "${OPENCODE_CWD}"
exec "${OPENCODE_CMD[@]}" "$@"
