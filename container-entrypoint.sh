#!/bin/bash
set -e

# Container entrypoint for SploitGPT.

# ASCII Banner
echo '
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   

            [ Autonomous AI Penetration Testing Framework ]
'

# Configuration from environment or defaults
MSF_PASSWORD="${SPLOITGPT_MSF_PASSWORD:-sploitgpt}"
MSF_PORT="${SPLOITGPT_MSF_PORT:-55553}"
MSF_HOST="${SPLOITGPT_MSF_HOST:-127.0.0.1}"
MSF_ALLOW_REMOTE="${SPLOITGPT_MSF_ALLOW_REMOTE:-false}"
MSF_SSL="${SPLOITGPT_MSF_SSL:-false}"

# Optional: in-container VPN (recommended: WireGuard config mounted from the host)
VPN_AUTOSTART="${SPLOITGPT_VPN_AUTOSTART:-false}"
VPN_WG_CONF="${SPLOITGPT_VPN_WG_CONF:-}"
VPN_STARTED=false

# Security hardening: avoid accidentally exposing msfrpcd on non-loopback.
# If you intentionally want remote msfrpcd access, set SPLOITGPT_MSF_ALLOW_REMOTE=true
# and set SPLOITGPT_MSF_HOST to the desired bind address.
if [ "$MSF_ALLOW_REMOTE" != "true" ] && [ "$MSF_ALLOW_REMOTE" != "1" ]; then
    case "$MSF_HOST" in
        127.0.0.1|localhost|::1)
            ;;
        *)
            echo "[!] Refusing to bind msfrpcd to non-loopback address ($MSF_HOST)."
            echo "    Set SPLOITGPT_MSF_ALLOW_REMOTE=true to override."
            MSF_HOST="127.0.0.1"
            ;;
    esac
fi

# Function to clean up background processes on exit
cleanup() {
    echo "[*] Shutting down services..."

    if [ "$VPN_STARTED" = true ] && [ -n "$VPN_WG_CONF" ]; then
        wg-quick down "$VPN_WG_CONF" >/dev/null 2>&1 || true
    fi

    if [ -n "${MSFRPCD_PID:-}" ]; then
        kill "$MSFRPCD_PID" 2>/dev/null || true
    fi

    # Stop PostgreSQL cluster if we started it
    if [ -n "${PG_VER:-}" ] && [ -n "${PG_NAME:-}" ]; then
        pg_ctlcluster "$PG_VER" "$PG_NAME" stop 2>/dev/null || true
    fi
}

on_term() {
    cleanup
    exit 0
}
trap on_term SIGTERM SIGINT

# Optional: start a WireGuard VPN before launching tooling.
# Provide a config (NOT committed) via volume mount, e.g. ./vpn/mullvad.conf -> /vpn/mullvad.conf
# Then set:
#   SPLOITGPT_VPN_AUTOSTART=true
#   SPLOITGPT_VPN_WG_CONF=/vpn/mullvad.conf
if [ "$VPN_AUTOSTART" = "true" ] || [ "$VPN_AUTOSTART" = "1" ]; then
    if [ -n "$VPN_WG_CONF" ] && [ -f "$VPN_WG_CONF" ]; then
        if command -v wg-quick >/dev/null 2>&1; then
            echo "[*] Starting WireGuard VPN: $VPN_WG_CONF"
            if wg-quick up "$VPN_WG_CONF"; then
                VPN_STARTED=true
                echo "[+] WireGuard is up"
            else
                echo "[!] Warning: failed to start WireGuard (continuing without VPN)" >&2
            fi
        else
            echo "[!] Warning: wg-quick not found (install wireguard-tools)" >&2
        fi
    else
        echo "[!] Warning: VPN autostart requested but config not found: $VPN_WG_CONF" >&2
    fi
fi

# Start Metasploit RPC daemon in background
echo "[*] Starting Metasploit RPC daemon on ${MSF_HOST}:${MSF_PORT}..."

# Silence Kali login banner in non-interactive container contexts
# (msfdb may invoke tools via su, which can emit MOTD unless hushlogin is present)
touch /root/.hushlogin /var/lib/postgresql/.hushlogin 2>/dev/null || true

# Start PostgreSQL if present (Metasploit uses it for workspace/module metadata)
if command -v pg_lsclusters >/dev/null 2>&1 && command -v pg_ctlcluster >/dev/null 2>&1; then
    CLUSTER_LINE="$(pg_lsclusters --no-header 2>/dev/null | head -n 1 || true)"
    if [ -n "$CLUSTER_LINE" ]; then
        PG_VER="$(echo "$CLUSTER_LINE" | awk '{print $1}')"
        PG_NAME="$(echo "$CLUSTER_LINE" | awk '{print $2}')"
        PG_PORT="$(echo "$CLUSTER_LINE" | awk '{print $3}')"
        PG_STATUS="$(echo "$CLUSTER_LINE" | awk '{print $4}')"

        if [ "$PG_STATUS" != "online" ]; then
            echo "[*] Starting PostgreSQL cluster ${PG_VER}/${PG_NAME}..."
            pg_ctlcluster "$PG_VER" "$PG_NAME" start || true
        fi

        echo "[*] Waiting for PostgreSQL to become ready..."
        for i in {1..15}; do
            if pg_isready -q -p "$PG_PORT" 2>/dev/null; then
                echo "[+] PostgreSQL is ready (port $PG_PORT)"
                break
            fi
            sleep 1
        done
    fi
fi

# Initialize Metasploit database/config on first run
if command -v msfdb &> /dev/null; then
    if [ ! -f /usr/share/metasploit-framework/config/database.yml ]; then
        msfdb init 2>/dev/null || true
    fi
fi

# Start msfrpcd in the foreground (but background it from the entrypoint so we can supervise it)
# -P password, -S disable SSL, -a bind address, -p port, -f foreground
MSF_SSL_FLAG="-S"
if [ "$MSF_SSL" = "true" ] || [ "$MSF_SSL" = "1" ]; then
    MSF_SSL_FLAG=""
fi
msfrpcd -P "$MSF_PASSWORD" ${MSF_SSL_FLAG} -a "$MSF_HOST" -p "$MSF_PORT" -f > /var/log/msfrpcd.log 2>&1 &
MSFRPCD_PID=$!

# Wait for msfrpcd to start
echo "[*] Waiting for Metasploit RPC to initialize..."
for i in {1..15}; do
    if nc -z "$MSF_HOST" "$MSF_PORT" 2>/dev/null; then
        echo "[+] Metasploit RPC ready on ${MSF_HOST}:${MSF_PORT}"
        break
    fi
    sleep 1
done

if ! nc -z "$MSF_HOST" "$MSF_PORT" 2>/dev/null; then
    echo "[!] Warning: Metasploit RPC may not have started correctly"
    echo "[!] Check /var/log/msfrpcd.log for details"
fi

# Initialize database if needed
if [ ! -f /app/data/sploitgpt.db ]; then
    echo "[*] Initializing database..."
    python3 -c "from sploitgpt.db import init_db; init_db()"
fi

# Check for Ollama connection and warm the model
OLLAMA_URL="${OLLAMA_HOST:-${SPLOITGPT_OLLAMA_HOST:-}}"
MODEL_NAME="${SPLOITGPT_MODEL:-sploitgpt-local:latest}"
if [ -n "$OLLAMA_URL" ]; then
    echo "[*] Checking Ollama connection at $OLLAMA_URL..."
    if curl -s "$OLLAMA_URL/api/tags" > /dev/null 2>&1; then
        echo "[+] Ollama connected"
        if [ -n "$MODEL_NAME" ]; then
            echo "[*] Warming model ${MODEL_NAME}..."
            curl -sS -X POST "$OLLAMA_URL/api/generate" \
              -H "Content-Type: application/json" \
              -d "{\"model\":\"${MODEL_NAME}\",\"prompt\":\"ready\",\"stream\":false}" \
              >/dev/null 2>&1 || true
        fi
    else
        echo "[!] Warning: Cannot connect to Ollama at $OLLAMA_URL"
    fi
fi

# Parse loot directory for prior work
if [ -d /app/loot ] && [ "$(ls -A /app/loot 2>/dev/null)" ]; then
    echo "[*] Found prior reconnaissance data in loot/"
    ls -la /app/loot/*.nmap /app/loot/*.xml 2>/dev/null | head -5 || true
fi

echo "[*] SploitGPT ready"
echo ""

# Run the main command while supervising background services.
"$@" &
MAIN_PID=$!

# If either the main command or msfrpcd exits, stop the container (restart policy can bring it back).
wait -n "$MAIN_PID" "$MSFRPCD_PID" 2>/dev/null || wait "$MAIN_PID" || true
EXIT_CODE=$?

cleanup
exit "$EXIT_CODE"
