#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: scripts/smoke_docker.sh [--no-build] [--down]

Runs an end-to-end Docker smoke test:
  - docker compose up (optionally --build)
  - waits for container health (if healthcheck is configured)
  - verifies PostgreSQL, msfrpcd, and host Ollama connectivity
  - runs a trivial SploitGPT --task and expects output: ok

Options:
  --no-build   Do not force a rebuild
  --down       Bring the compose stack down after the test
USAGE
}

DO_BUILD=true
DO_DOWN=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-build)
      DO_BUILD=false
      ;;
    --down)
      DO_DOWN=true
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

if ! docker info >/dev/null 2>&1; then
  echo "[!] Docker daemon is not accessible for the current user." >&2
  exit 1
fi

echo "[*] Starting compose stack..."
if [ "$DO_BUILD" = true ]; then
  docker compose up -d --build
else
  docker compose up -d
fi

CID="$(docker compose ps --status running -q sploitgpt 2>/dev/null || true)"
if [ -z "$CID" ]; then
  echo "[!] sploitgpt container is not running" >&2
  docker compose ps >&2 || true
  exit 1
fi

# Wait for health if a healthcheck is configured.
if docker inspect -f '{{.State.Health.Status}}' "$CID" >/dev/null 2>&1; then
  echo "[*] Waiting for container health..."
  for _ in $(seq 1 30); do
    STATUS="$(docker inspect -f '{{.State.Health.Status}}' "$CID" 2>/dev/null || true)"
    if [ "$STATUS" = "healthy" ]; then
      echo "[+] Container is healthy"
      break
    fi
    if [ "$STATUS" = "unhealthy" ]; then
      echo "[!] Container is unhealthy" >&2
      docker logs --tail 200 "$CID" >&2 || true
      exit 1
    fi
    sleep 2
  done
fi

echo "[*] Checking PostgreSQL readiness..."
docker exec "$CID" sh -c 'pg_isready -q -p 5432'

echo "[*] Checking Metasploit RPC port..."
docker exec "$CID" sh -c 'nc -z "$SPLOITGPT_MSF_HOST" "$SPLOITGPT_MSF_PORT"'

echo "[*] Verifying Metasploit RPC authentication + module search..."
docker exec -i "$CID" python3 - <<'PY'
import asyncio

from sploitgpt.msf import get_msf_client


async def main() -> None:
    msf = get_msf_client()
    try:
        ok = await msf.connect()
        assert ok, "msfrpcd auth failed"

        mods = await msf.search_modules("portscan", module_type="auxiliary")
        assert mods, "module search returned no results"
    finally:
        await msf.disconnect()


asyncio.run(main())
PY

echo "[*] Verifying msf_run can execute a safe auxiliary module..."
docker exec -i "$CID" python3 - <<'PY'
import asyncio

from sploitgpt.tools import execute_tool


async def main() -> None:
    out = await execute_tool(
        "msf_run",
        {
            "module": "auxiliary/scanner/portscan/tcp",
            "options": {"RHOSTS": "127.0.0.1", "PORTS": "5432"},
        },
    )
    low = out.lower()
    assert "5432" in low, out


asyncio.run(main())
PY

echo "[*] Checking Ollama connectivity..."
docker exec "$CID" sh -c 'curl -fsS "${SPLOITGPT_OLLAMA_HOST:-http://ollama:11434}/api/version" >/dev/null'

echo "[*] Running SploitGPT headless smoke task..."
LAST_LINE="$(./sploitgpt.sh --task "Respond with exactly the text: ok" \
  | tr -d '\r' \
  | awk 'NF{last=$0} END{print last}')"

if [ "$LAST_LINE" != "ok" ]; then
  echo "[!] Unexpected final output line: $LAST_LINE" >&2
  exit 1
fi

echo "[+] Smoke test passed"

if [ "$DO_DOWN" = true ]; then
  echo "[*] Bringing compose stack down..."
  docker compose down
fi
