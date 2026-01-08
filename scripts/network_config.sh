#!/bin/bash
# SploitGPT Network Configuration Helper
# Detects container bridge IP and configures Ollama connection (Podman-first)

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}SploitGPT Network Configuration${NC}"
echo "================================"
echo ""

# Detect container bridge IP (Podman).
detect_container_bridge() {
    # Podman rootful bridge interfaces vary by distro/version.
    for iface in podman0 cni-podman0 docker0; do
        if ip addr show "$iface" &>/dev/null; then
            BRIDGE_IP=$(ip addr show "$iface" | grep -oP 'inet \K[\d.]+' | head -1)
            if [ -n "$BRIDGE_IP" ]; then
                echo "$BRIDGE_IP"
                return 0
            fi
        fi
    done
    
    # Fallback: check any bridge interface
    for iface in $(ip link show type bridge 2>/dev/null | grep -oP '^\d+: \K[^:]+'); do
        BRIDGE_IP=$(ip addr show "$iface" | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -n "$BRIDGE_IP" ]; then
            echo "$BRIDGE_IP"
            return 0
        fi
    done
    
    # Default fallback
    echo "172.17.0.1"
}

# Detect host's main IP (for reverse shells)
detect_host_ip() {
    # Get the default route interface
    DEFAULT_IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
    if [ -n "$DEFAULT_IFACE" ]; then
        HOST_IP=$(ip addr show "$DEFAULT_IFACE" | grep -oP 'inet \K[\d.]+' | head -1)
        echo "$HOST_IP"
        return 0
    fi
    echo "unknown"
}

# Detect VPN
detect_vpn() {
    # Check for WireGuard
    if ip link show type wireguard &>/dev/null 2>&1; then
        WG_IFACE=$(ip link show type wireguard | head -1 | grep -oP '^\d+: \K[^:]+')
        if [ -n "$WG_IFACE" ]; then
            echo "wireguard:$WG_IFACE"
            return 0
        fi
    fi
    
    # Check for tun interfaces (OpenVPN, etc.)
    for iface in tun0 tun1 tap0; do
        if ip link show "$iface" &>/dev/null 2>&1; then
            echo "openvpn:$iface"
            return 0
        fi
    done
    
    echo "none"
}

echo -e "${CYAN}Detecting network configuration...${NC}"
echo ""

CONTAINER_BRIDGE=$(detect_container_bridge)
HOST_IP=$(detect_host_ip)
VPN_STATUS=$(detect_vpn)

echo -e "Container Bridge IP:  ${GREEN}$CONTAINER_BRIDGE${NC}"
echo -e "Host IP:           ${GREEN}$HOST_IP${NC}"
echo -e "VPN:               ${GREEN}$VPN_STATUS${NC}"
echo ""

# Generate .env file
ENV_FILE=".env"
FORCE=false
if [ "${1:-}" = "--force" ]; then
    FORCE=true
fi

if [ -f "$ENV_FILE" ] && [ "$FORCE" = false ]; then
    echo -e "${YELLOW}[!]${NC} $ENV_FILE already exists"
    read -r -p "Overwrite $ENV_FILE? [y/N]: " OVERWRITE
    if [[ ! "$OVERWRITE" =~ ^[Yy]$ ]]; then
        echo "Aborted (no changes made)."
        exit 1
    fi
fi

cat > "$ENV_FILE" << EOF
# SploitGPT Network Configuration
# Generated: $(date)

# Ollama connection (compose service DNS on the private container network)
SPLOITGPT_OLLAMA_HOST=http://ollama:11434

# Model to use
SPLOITGPT_MODEL=qwen2.5:7b

# Listener port guidance (ports open only when tools bind)
SPLOITGPT_LPORT=40000
SPLOITGPT_LISTENER_PORTS=40000-40100

# Your host IP (for reverse shells - update if using VPN)
LHOST=${HOST_IP}

# Default listener port
LPORT=40000
EOF

echo -e "${GREEN}Configuration saved to $ENV_FILE${NC}"
echo ""
echo "To use a different Ollama host, edit .env or run:"
echo "  export SPLOITGPT_OLLAMA_HOST=http://your-ip:11434"
echo ""

# Network mode note
echo -e "${CYAN}Network Mode Note:${NC}"
echo ""
echo "  This project defaults to bridge networking (isolated from the host)."
echo "  If you need inbound callbacks/listeners (reverse shells, payload servers, etc.),"
echo "  enable the listener profile to publish a limited port range:"
echo "    podman compose --profile listeners -f compose.yaml up -d listener-proxy"
echo "  Use a port from SPLOITGPT_LISTENER_PORTS and your host's reachable IP for LHOST."

echo ""
echo -e "${CYAN}VPN Note:${NC}"
echo ""
echo "  VPN detected on host: $VPN_STATUS"
echo "  If you run a VPN inside the container instead, container traffic can be routed"
echo "  independently of the host."
echo ""
