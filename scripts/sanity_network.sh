#!/usr/bin/env bash
set -euo pipefail

say() { printf '%s\n' "$*"; }

say "[*] Container states:"
podman inspect -f 'sploitgpt: {{.State.Status}} (running={{.State.Running}})' sploitgpt 2>/dev/null || say "sploitgpt: MISSING"
podman inspect -f 'ollama:   {{.State.Status}} (running={{.State.Running}})' ollama 2>/dev/null || say "ollama: MISSING"
say ""

RUNNING="$(podman inspect -f '{{.State.Running}}' sploitgpt 2>/dev/null || echo false)"
if [ "$RUNNING" != "true" ]; then
  say "[!] sploitgpt container is not running. Start it (Podman Desktop or: podman start sploitgpt)."
  exit 1
fi

say "[*] Services inside sploitgpt container:"
podman exec sploitgpt sh -lc 'pg_isready -q -p 5432 && echo "postgres: ok" || echo "postgres: not ready"'
podman exec sploitgpt sh -lc 'nc -z 127.0.0.1 55553 && echo "msfrpcd: ok" || echo "msfrpcd: not reachable"'
podman exec sploitgpt sh -lc 'curl -fsS "${SPLOITGPT_OLLAMA_HOST:-http://ollama:11434}/api/version" && echo' || say "[!] Ollama not reachable from inside sploitgpt"

say ""
say "[*] Port publishing (should be empty unless you intentionally exposed listener ports):"
podman port sploitgpt || true
