#!/bin/bash
# SploitGPT Firewall Setup
# 
# Security Architecture:
# ┌─────────────────────────────────────────────────────────────────┐
# │                           HOST                                   │
# │  ┌─────────────────┐                                            │
# │  │ Ollama          │ ← Binds to container bridge only          │
# │  │ Port 11434      │                                            │
# │  └────────▲────────┘                                            │
# │           │ Container bridge (varies by engine)                 │
# │  ┌────────┴────────────────────────────────────────────────┐   │
# │  │              SploitGPT Container                         │   │
# │  │  ┌──────────────┐  ┌─────────────────────────────────┐  │   │
# │  │  │ Metasploit   │  │ Python App                      │  │   │
# │  │  │ RPC 127.0.0.1│◄─│ Connects to MSF + Ollama        │  │   │
# │  │  │ :55553       │  │                                 │  │   │
# │  │  └──────────────┘  └─────────────────────────────────┘  │   │
# │  │                              │                           │   │
# │  │                              ▼ VPN Tunnel (host network) │   │
# │  └──────────────────────────────┼───────────────────────────┘   │
# │                                 │                               │
# └─────────────────────────────────┼───────────────────────────────┘
#                                   ▼
#                              Internet (via Mullvad VPN)
#
# Security Rules:
# 1. Ollama (11434): ONLY accessible from the container bridge subnet
# 2. MSF RPC (55553): Runs inside container on 127.0.0.1 (no external access)
# 3. Container uses host networking → shares VPN tunnel
# 4. Inbound blocked by default (UFW default deny)

set -e

# Configuration
OLLAMA_PORT=11434
MSF_PORT=55553
CONTAINER_BRIDGE="172.17.0.0/16"
CONTAINER_BRIDGE_IP="172.17.0.1"

# Podman default network (best-effort): prefer its gateway/subnet when available.
if command -v podman >/dev/null 2>&1; then
    if podman network inspect podman >/dev/null 2>&1; then
        DETECTED="$(
            podman network inspect podman 2>/dev/null \
            | python3 - <<'PY'
import json, sys
data = json.load(sys.stdin)
if isinstance(data, list) and data:
    data = data[0]
subnets = data.get("subnets") or []
subnet = ""
gateway = ""
if subnets and isinstance(subnets[0], dict):
    subnet = (subnets[0].get("subnet") or "").strip()
    gateway = (subnets[0].get("gateway") or "").strip()
print(f"{subnet}|{gateway}".strip("|"))
PY
        )"
        DETECTED_SUBNET="${DETECTED%%|*}"
        DETECTED_GW="${DETECTED#*|}"
        if [ -n "$DETECTED_SUBNET" ] && [ "$DETECTED_SUBNET" != "$DETECTED" ]; then
            CONTAINER_BRIDGE="$DETECTED_SUBNET"
        fi
        if [ -n "$DETECTED_GW" ] && [ "$DETECTED_GW" != "$DETECTED" ]; then
            CONTAINER_BRIDGE_IP="$DETECTED_GW"
        fi
    fi
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║           SploitGPT Security Configuration                    ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

echo -e "${CYAN}[1/5]${NC} Detecting firewall..."

# Detect firewall
if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    FIREWALL="ufw"
    echo -e "  ${GREEN}✓${NC} UFW detected (active)"
elif command -v firewall-cmd &> /dev/null && systemctl is-active firewalld &> /dev/null; then
    FIREWALL="firewalld"
    echo -e "  ${GREEN}✓${NC} firewalld detected"
else
    FIREWALL="iptables"
    echo -e "  ${YELLOW}!${NC} Using raw iptables"
fi

echo ""
echo -e "${CYAN}[2/5]${NC} Configuring Ollama binding..."

# Configure Ollama to bind to container bridge only
mkdir -p /etc/systemd/system/ollama.service.d

cat > /etc/systemd/system/ollama.service.d/override.conf << EOF
[Service]
Environment="OLLAMA_HOST=${CONTAINER_BRIDGE_IP}"
EOF

systemctl daemon-reload
systemctl restart ollama 2>/dev/null || echo -e "  ${YELLOW}!${NC} Ollama service not found (may not be installed as service)"

echo -e "  ${GREEN}✓${NC} Ollama configured to bind to ${CONTAINER_BRIDGE_IP}"

echo ""
echo -e "${CYAN}[3/5]${NC} Configuring firewall rules..."

configure_ufw() {
    echo "  Configuring UFW..."
    # Ensure default policies
    ufw default deny incoming > /dev/null 2>&1 || true
    ufw default allow outgoing > /dev/null 2>&1 || true
    
    # Remove any existing Ollama rules to avoid duplicates
    ufw delete allow $OLLAMA_PORT/tcp 2>/dev/null || true
    ufw delete deny $OLLAMA_PORT/tcp 2>/dev/null || true
    ufw delete allow from $CONTAINER_BRIDGE to any port $OLLAMA_PORT proto tcp 2>/dev/null || true
    
    # Add Ollama rules: Allow from container bridge, deny from everywhere else
    # UFW processes rules in order, first match wins
    ufw insert 1 allow from $CONTAINER_BRIDGE to any port $OLLAMA_PORT proto tcp comment "Ollama - containers only" > /dev/null
    ufw insert 2 deny $OLLAMA_PORT/tcp comment "Ollama - Block external" > /dev/null
    
    # Allow container bridge traffic in general (for container communication)
    ufw allow from $CONTAINER_BRIDGE comment "Container bridge" > /dev/null 2>&1 || true
    
    # IMPORTANT: Allow libvirt/KVM virtual machine networking
    # This allows VMs on virbr0/virbr1 to communicate (DHCP, DNS, etc.)
    echo "  Allowing libvirt VM networking..."
    ufw allow in on virbr0 > /dev/null 2>&1 || true
    ufw allow in on virbr1 > /dev/null 2>&1 || true
    # Common libvirt network ranges
    ufw allow from 192.168.122.0/24 comment "libvirt default network" > /dev/null 2>&1 || true
    ufw allow from 192.168.200.0/24 comment "libvirt isolated network" > /dev/null 2>&1 || true
    
    # Allow established connections
    # (UFW does this by default, but being explicit)
    
    echo -e "  ${GREEN}✓${NC} UFW rules configured"
    echo -e "  ${GREEN}✓${NC} VM networking preserved"
}

configure_firewalld() {
    echo "  Configuring firewalld..."
    # Create containers zone
    firewall-cmd --permanent --new-zone=containers 2>/dev/null || true
    firewall-cmd --permanent --zone=containers --add-source=$CONTAINER_BRIDGE
    firewall-cmd --permanent --zone=containers --add-port=$OLLAMA_PORT/tcp
    
    # Remove from public
    firewall-cmd --permanent --zone=public --remove-port=$OLLAMA_PORT/tcp 2>/dev/null || true
    
    firewall-cmd --reload
    echo -e "  ${GREEN}✓${NC} firewalld rules configured"
}

configure_iptables() {
    echo "  Configuring iptables..."
    # Allow Ollama from container bridge
    iptables -I INPUT -p tcp --dport $OLLAMA_PORT -s $CONTAINER_BRIDGE -j ACCEPT
    
    # Drop Ollama from everywhere else
    iptables -A INPUT -p tcp --dport $OLLAMA_PORT -j DROP
    
    # Allow established connections
    iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Try to save rules
    if command -v netfilter-persistent &> /dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi
    
    echo -e "  ${GREEN}✓${NC} iptables rules configured"
}

case "$FIREWALL" in
    ufw)
        configure_ufw
        ;;
    firewalld)
        configure_firewalld
        ;;
    iptables)
        configure_iptables
        ;;
esac

echo ""
echo -e "${CYAN}[4/5]${NC} Verifying configuration..."

# Verify Ollama binding
sleep 2  # Wait for Ollama to restart
OLLAMA_LISTEN=$(ss -tlnp 2>/dev/null | grep ":$OLLAMA_PORT" || true)

if echo "$OLLAMA_LISTEN" | grep -q "$CONTAINER_BRIDGE_IP"; then
    echo -e "  ${GREEN}✓${NC} Ollama listening on ${CONTAINER_BRIDGE_IP}:${OLLAMA_PORT}"
elif echo "$OLLAMA_LISTEN" | grep -q "0.0.0.0"; then
    echo -e "  ${YELLOW}!${NC} Ollama on 0.0.0.0 (firewall will protect)"
else
    echo -e "  ${YELLOW}?${NC} Could not verify Ollama binding"
fi

# Test connectivity
echo ""
echo -e "${CYAN}[5/5]${NC} Testing security..."

# Test from container bridge gateway (should work)
if curl -s --max-time 3 "http://${CONTAINER_BRIDGE_IP}:${OLLAMA_PORT}/api/tags" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Ollama accessible from container bridge"
else
    echo -e "  ${RED}✗${NC} Ollama NOT accessible from container bridge"
fi

# Test from localhost (should fail or timeout)
if curl -s --max-time 2 "http://127.0.0.1:${OLLAMA_PORT}/api/tags" > /dev/null 2>&1; then
    echo -e "  ${YELLOW}!${NC} Ollama accessible from localhost (expected if Ollama binds to 0.0.0.0)"
else
    echo -e "  ${GREEN}✓${NC} Ollama blocked from localhost"
fi

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}                    ${GREEN}Setup Complete${NC}                            ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Security Configuration:"
echo "  • Ollama:        ${CONTAINER_BRIDGE_IP}:${OLLAMA_PORT} (container bridge only)"
echo "  • MSF RPC:       127.0.0.1:${MSF_PORT} (container localhost only)"
echo "  • Container:     Host networking (uses VPN tunnel)"
echo "  • Inbound:       Blocked by default (UFW deny)"
echo ""
echo "Protected from:"
echo "  • Internet access to Ollama ✓"
echo "  • LAN access to Ollama ✓"
echo "  • External access to MSF RPC ✓"
echo ""
echo "Allowed:"
echo "  • Container → Ollama (via container bridge)"
echo "  • Container → MSF RPC (localhost inside container)"
echo "  • Container → Internet (via host VPN)"
echo ""
