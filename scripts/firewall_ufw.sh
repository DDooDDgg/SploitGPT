#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/firewall_ufw.sh [options]

Prints (default) or applies (--apply) a minimal UFW ruleset suitable for running
SploitGPT on a workstation.

This script is conservative:
- Default deny incoming
- Default allow outgoing
- Optional: allow SSH
- Optional: allow specific listener ports (reverse shells, web servers, etc.)

Options:
  --allow-ssh               Allow inbound SSH (22/tcp via OpenSSH profile)
  --allow-tcp PORT          Allow inbound TCP port (repeatable)
  --allow-udp PORT          Allow inbound UDP port (repeatable)
  --apply                   Apply the rules (requires root)
  --status                  Show ufw status and exit
  -h, --help                Show this help

Examples:
  scripts/firewall_ufw.sh --allow-ssh --allow-tcp 4444 --allow-tcp 8000
  sudo scripts/firewall_ufw.sh --allow-ssh --allow-tcp 4444 --apply
USAGE
}

ALLOW_SSH=false
APPLY=false
SHOW_STATUS=false
ALLOW_TCP_PORTS=()
ALLOW_UDP_PORTS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --allow-ssh)
      ALLOW_SSH=true
      ;;
    --allow-tcp)
      shift
      [ "$#" -gt 0 ] || { echo "[!] --allow-tcp requires a PORT" >&2; exit 2; }
      ALLOW_TCP_PORTS+=("$1")
      ;;
    --allow-udp)
      shift
      [ "$#" -gt 0 ] || { echo "[!] --allow-udp requires a PORT" >&2; exit 2; }
      ALLOW_UDP_PORTS+=("$1")
      ;;
    --apply)
      APPLY=true
      ;;
    --status)
      SHOW_STATUS=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if ! command -v ufw >/dev/null 2>&1; then
  echo "[!] ufw not found. Install it first (e.g., sudo apt-get install -y ufw)." >&2
  exit 1
fi

if [ "$SHOW_STATUS" = true ]; then
  ufw status verbose
  exit 0
fi

cmds=()
cmds+=("ufw default deny incoming")
cmds+=("ufw default allow outgoing")

if [ "$ALLOW_SSH" = true ]; then
  cmds+=("ufw allow OpenSSH")
fi

for p in "${ALLOW_TCP_PORTS[@]}"; do
  if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "[!] Invalid TCP port: $p" >&2
    exit 2
  fi
  cmds+=("ufw allow ${p}/tcp")
done

for p in "${ALLOW_UDP_PORTS[@]}"; do
  if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
    echo "[!] Invalid UDP port: $p" >&2
    exit 2
  fi
  cmds+=("ufw allow ${p}/udp")
done

cmds+=("ufw enable")

if [ "$APPLY" = true ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "[!] --apply requires root. Re-run with sudo." >&2
    exit 1
  fi

  echo "[*] Applying UFW rules..."
  for c in "${cmds[@]}"; do
    echo "[+] $c"
    $c
  done

  echo "[*] Current status:"
  ufw status verbose
else
  echo "[*] Planned UFW commands (dry run):"
  for c in "${cmds[@]}"; do
    echo "  $c"
  done
  echo ""
  echo "Run with --apply to execute (requires sudo)."
fi
