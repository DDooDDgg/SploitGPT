#!/bin/bash
set -euo pipefail

echo '
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   
                                                                         
                        [ INSTALLER ]
'

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${CYAN}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

ENV_FILE=".env"

set_env_kv() {
    local key="$1"
    local value="$2"

    touch "$ENV_FILE"

    if grep -q "^${key}=" "$ENV_FILE"; then
        # Replace existing value (Linux sed)
        sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

normalize_ollama_host() {
    # Normalize a host/URL into an http URL usable by curl/ollama CLI.
    # Accepts: "http://host:11434", "host:11434", or "host".
    local h="${1:-}"
    if [ -z "$h" ]; then
        return 1
    fi

    if [[ "$h" == http://* || "$h" == https://* ]]; then
        echo "$h"
        return 0
    fi

    if [[ "$h" == *:* ]]; then
        echo "http://$h"
        return 0
    fi

    echo "http://$h:11434"
}

find_ollama_endpoint() {
    # Return the first reachable Ollama base URL.
    local candidates=()
    local c

    c="$(normalize_ollama_host "${OLLAMA_HOST:-}" 2>/dev/null || true)"
    if [ -n "$c" ]; then
        candidates+=("$c")
    fi

    c="$(normalize_ollama_host "${SPLOITGPT_OLLAMA_HOST:-}" 2>/dev/null || true)"
    if [ -n "$c" ]; then
        candidates+=("$c")
    fi

    candidates+=("http://localhost:11434" "http://127.0.0.1:11434" "http://172.17.0.1:11434")

    for url in "${candidates[@]}"; do
        if curl -fsS "$url/api/version" >/dev/null 2>&1; then
            echo "$url"
            return 0
        fi
    done

    return 1
}

# Check prerequisites
log_info "Checking prerequisites..."

# Docker
if command -v docker &> /dev/null; then
    log_success "Docker found"
else
    log_error "Docker not found. Please install Docker first."
    exit 1
fi

# Check for NVIDIA GPU (optional)
if command -v nvidia-smi &> /dev/null; then
    GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo "")
    if [ -n "$GPU_INFO" ]; then
        log_success "NVIDIA GPU detected: $GPU_INFO"
        HAS_GPU=true
    else
        log_warn "nvidia-smi found but no GPU detected"
        HAS_GPU=false
    fi
else
    log_warn "No NVIDIA GPU detected - will use CPU inference (slower)"
    HAS_GPU=false
fi

# Check for Ollama
if command -v ollama &> /dev/null; then
    log_success "Ollama found"
    OLLAMA_INSTALLED=true
else
    log_warn "Ollama not found - will install"
    OLLAMA_INSTALLED=false
fi

echo ""
log_info "Installation Options:"
echo ""
echo "  1) Full install (Ollama + Model + Docker image)"
echo "  2) Docker only (assumes Ollama already running)"
echo "  3) Development install (local Python, no Docker)"
echo ""
read -p "Select option [1]: " INSTALL_OPTION
INSTALL_OPTION=${INSTALL_OPTION:-1}

case $INSTALL_OPTION in
    1)
        # Install Ollama if needed
        if [ "$OLLAMA_INSTALLED" = false ]; then
            log_info "Installing Ollama..."
            curl -fsSL https://ollama.ai/install.sh | sh
            log_success "Ollama installed"
        fi
        
        # Ensure Ollama is running and discover its reachable endpoint
        log_info "Checking Ollama server..."
        OLLAMA_ENDPOINT="$(find_ollama_endpoint || true)"
        if [ -z "$OLLAMA_ENDPOINT" ]; then
            log_info "Starting Ollama server (fallback)..."
            (ollama serve &>/dev/null &) || true
            sleep 3
            OLLAMA_ENDPOINT="$(find_ollama_endpoint || true)"
        fi

        if [ -z "$OLLAMA_ENDPOINT" ]; then
            log_error "Ollama is installed but not reachable. Start it (e.g., 'ollama serve' or 'systemctl start ollama') and re-run."
            exit 1
        fi

        log_success "Ollama reachable at: $OLLAMA_ENDPOINT"
        export OLLAMA_HOST="$OLLAMA_ENDPOINT"
        
        # Pull model based on GPU
        if [ "$HAS_GPU" = true ]; then
            # Check VRAM
            VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1)
            VRAM=${VRAM:-0}
            if ! [[ "$VRAM" =~ ^[0-9]+$ ]]; then
                VRAM=0
            fi
            if [ "$VRAM" -ge 24000 ]; then
                MODEL="qwen2.5:32b"
                log_info "24GB+ VRAM detected - using Qwen2.5-32B"
            elif [ "$VRAM" -ge 12000 ]; then
                MODEL="qwen2.5:14b"
                log_info "12GB+ VRAM detected - using Qwen2.5-14B"
            else
                MODEL="qwen2.5:7b"
                log_info "<12GB VRAM detected - using Qwen2.5-7B"
            fi
        else
            MODEL="qwen2.5:7b"
            log_info "No GPU - using Qwen2.5-7B (CPU mode will be slow)"
        fi
        
        log_info "Pulling model: $MODEL (this may take a while)..."
        ollama pull "$MODEL"
        log_success "Model ready: $MODEL"

        # Save config (idempotent)
        set_env_kv "SPLOITGPT_MODEL" "$MODEL"
        set_env_kv "SPLOITGPT_LLM_MODEL" "ollama/$MODEL"
        set_env_kv "SPLOITGPT_OLLAMA_HOST" "$OLLAMA_ENDPOINT"
        ;;
    2)
        log_info "Docker-only install"
        OLLAMA_ENDPOINT="$(find_ollama_endpoint || true)"
        if [ -z "$OLLAMA_ENDPOINT" ]; then
            log_warn "Could not auto-detect a reachable Ollama endpoint; defaulting to http://172.17.0.1:11434"
            OLLAMA_ENDPOINT="http://172.17.0.1:11434"
        fi
        set_env_kv "SPLOITGPT_OLLAMA_HOST" "$OLLAMA_ENDPOINT"
        ;;
    3)
        log_info "Development install"
        python3 -m pip install -e .
        log_success "Installed in development mode"
        echo ""
        log_info "Run with: python -m sploitgpt"
        exit 0
        ;;
esac

# Build Docker image (compose uses the local Dockerfile)
log_info "Building Docker image (this may take a while)..."
docker compose build
log_success "Docker image built"

# Start toolbox container
log_info "Starting container..."
docker compose up -d

# Create directories
mkdir -p loot sessions data

# Done
echo ""
log_success "Installation complete!"
echo ""
echo "To start SploitGPT:"
echo ""
echo "  ./sploitgpt.sh"
echo ""
echo "Other modes:"
echo ""
echo "  ./sploitgpt.sh --cli"
echo "  ./sploitgpt.sh --task \"Respond with exactly the text: ok\""
echo ""
echo "Optional validation:"
echo ""
echo "  ./scripts/smoke_docker.sh"
echo ""
