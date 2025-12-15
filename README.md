# SploitGPT

```text
 ███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ██████╗ ██████╗ ████████╗
 ██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝
 ███████╗██████╔╝██║     ██║   ██║██║   ██║   ██║  ███╗██████╔╝   ██║   
 ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ██║   ██║██╔═══╝    ██║   
 ███████║██║     ███████╗╚██████╔╝██║   ██║   ╚██████╔╝██║        ██║   
 ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   
                                                                         
            [ Autonomous AI Penetration Testing Framework ]
```

> **⚠️ AUTHORIZED USE ONLY** - This tool is for authorized penetration testing and security research only. Unauthorized access to computer systems is illegal.

## What is SploitGPT?

SploitGPT is an AI-powered penetration testing framework that:

- 🧠 **Fine-tunes on install** - Trains a security-specialized model on your GPU
- 🔄 **Learns from your sessions** - Gets smarter the more you use it
- 🎯 **Asks, doesn't guess** - Clarifying questions instead of wrong assumptions
- 🔓 **Runs 100% locally** - Private, secure, no API costs after install
- ⚡ **Executes autonomously** - Actually runs commands, not just suggestions

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/sploitgpt.git
cd sploitgpt

# Install (includes 30-min fine-tuning on your GPU)
./install.sh

# Run
./sploitgpt
```

## Requirements

- **Docker**
- **NVIDIA GPU** with 8GB+ VRAM (for local LLM)
- **Ollama** (auto-installed)
- Linux (tested on Kali, Ubuntu, Debian)

## Features

### 🎯 Intelligent Attack Planning

SploitGPT uses MITRE ATT&CK techniques to plan attacks. When multiple paths exist, it asks you:

```text
sploitgpt > compromise 10.0.0.1

🔍 Scanning target...

PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  smb

Multiple attack paths available:
[1] 🌐 Web Application (T1190) - Test for vulns, SQLi, RCE
[2] 📁 SMB Shares (T1021.002) - Enumerate shares, null session
[3] 🔑 Credential Attack (T1110) - Brute force SSH
[4] 🎯 Full Assessment - Try all paths

> 
```

### 🔧 Metasploit Integration

Uses Metasploit as the exploitation backend - no reinventing the wheel:

```text
sploitgpt > use exploit for CVE-2021-44228

Using: exploit/multi/http/log4shell_header_injection
Setting RHOSTS=10.0.0.1
Launching exploit...

[*] Meterpreter session 1 opened
```

### 💻 Hybrid Terminal

Direct shell access + AI commands in one interface:

```bash
# Direct shell command
sploitgpt > nmap -sV 10.0.0.1

# AI-assisted command (prefix with /)
sploitgpt > /enumerate this target

# Or just ask
sploitgpt > what services are running?
```

### 📚 Self-Improving

Every session makes the model smarter:

```text
Boot sequence:
[✓] Loading SploitGPT model
[✓] Found 47 new session logs
[?] Train on recent data? (5 min) [Y/n]: y
[✓] Model updated with your techniques
```

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         SploitGPT                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Ollama    │  │   Hybrid    │  │      Metasploit         │ │
│  │   (Local    │◄►│   Terminal  │◄►│      RPC Backend        │ │
│  │    LLM)     │  │   (TUI)     │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│         │                │                      │              │
│         ▼                ▼                      ▼              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Kali Linux Container                     ││
│  │  nmap • gobuster • sqlmap • hydra • nuclei • burp • ...    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Network Configuration

SploitGPT supports flexible network configurations for different pentesting scenarios.

### Network Modes

#### 1. Host Networking (Recommended for VPN/WiFi attacks)

Container shares host's network stack - ideal for:

- VPN tunneling (Mullvad, etc.)
- WiFi attacks (direct adapter access)
- LAN pivoting after initial access

```bash
# docker-compose.yml
network_mode: host  # Container uses host network directly
```

#### 2. Bridge Networking (Default Docker)

Isolated container network - ideal for:

- Lab environments
- Testing against local VMs
- Isolated engagements

```bash
# docker-compose.yml  
network_mode: bridge  # Default Docker networking
ports:
  - "4444:4444"  # Expose needed ports
```

### Environment Variables

Configure via `.env` file or environment:

```bash
# Generate auto-detected config
./scripts/network_config.sh > .env

# Or set manually:
SPLOITGPT_OLLAMA_HOST=http://172.17.0.1:11434  # Ollama endpoint
SPLOITGPT_MSF_HOST=127.0.0.1                    # MSF RPC bind address
SPLOITGPT_MSF_PORT=55553                        # MSF RPC port
SPLOITGPT_MSF_PASSWORD=msf                      # MSF RPC password
```

### Auto-Detection

SploitGPT auto-detects the Docker bridge IP at startup. For custom setups:

```bash
# Force specific Ollama endpoint
export SPLOITGPT_OLLAMA_HOST=http://192.168.1.100:11434
docker-compose up -d
```

## Security Configuration

SploitGPT is designed to run securely with the following setup:

### Network Isolation

```text
┌─────────────────┐     ┌─────────────────────────────────┐
│     Internet    │     │            Host                 │
│                 │     │  ┌─────────────────────────┐    │
└────────┬────────┘     │  │   Ollama (172.17.0.1)   │    │
         │              │  │   Firewall protected    │    │
         │ VPN          │  └───────────▲─────────────┘    │
         ▼              │              │ Docker bridge    │
┌─────────────────┐     │  ┌───────────┴─────────────┐    │
│  SploitGPT      │◄────┼──│   Docker Container      │    │
│  Container      │     │  │   (host networking)     │    │
│  (via host VPN) │     │  └─────────────────────────┘    │
└─────────────────┘     └─────────────────────────────────┘
```

- **Ollama**: Binds only to Docker bridge IP (`172.17.0.1`) - not exposed to internet/LAN
- **Container**: Uses host networking to share VPN tunnel for anonymous pentesting
- **Firewall**: UFW/iptables rules block external access to Ollama

### Setup Firewall Rules

```bash
# Automated setup (configures UFW/iptables + Ollama binding)
sudo ./scripts/firewall_setup.sh

# Or manually:
# 1. Configure Ollama to bind to Docker bridge
sudo mkdir -p /etc/systemd/system/ollama.service.d
echo '[Service]
Environment="OLLAMA_HOST=172.17.0.1"' | sudo tee /etc/systemd/system/ollama.service.d/override.conf
sudo systemctl daemon-reload && sudo systemctl restart ollama

# 2. Add firewall rules
sudo ufw allow from 172.17.0.0/16 to any port 11434 proto tcp
sudo ufw deny 11434/tcp
```

### Scenario: WiFi Attack / LAN Pentest

For engagements where you join a target network:

```bash
# 1. Connect to target WiFi
nmcli dev wifi connect "TargetNetwork" password "password123"

# 2. Start container with host networking
docker-compose up -d  # network_mode: host in compose file

# 3. Container now has direct LAN access
docker exec -it sploitgpt sploitgpt
sploitgpt > scan 192.168.1.0/24
```

### Scenario: VPN Tunnel

For anonymous pentesting through VPN:

```bash
# 1. Connect VPN on host
mullvad connect

# 2. Verify VPN
curl https://am.i.mullvad.net/connected  # Should show connected

# 3. Start container (inherits VPN via host networking)
docker-compose up -d
```

### Verify Security

```bash
# Ollama should NOT be accessible from localhost or network
curl http://localhost:11434/api/tags        # Should fail
curl http://YOUR_LAN_IP:11434/api/tags      # Should fail

# But accessible from container
docker exec sploitgpt curl http://172.17.0.1:11434/api/tags  # Should work
```

## Cloud GPU (experimental)

SploitGPT includes an opt-in Cloud GPU feature to help users prepare and use a remote GPU instance (e.g., for running hashcat). The feature is disabled by default and requires explicit consent to perform any remote operations.

Highlights:

- Explicit consent is required for sync and remote commands (set `consent=True` when calling tools).
- Dry-run mode is supported to preview actions without executing them.
- Use `cloud_gpu_status` to verify connectivity and `cloud_gpu_sync` to sync wordlists.
- See `proposals/cloud_gpu_feature` for design notes, security checklist, and sample dialogues.

## Training Data

SploitGPT is trained on:

- MITRE ATT&CK techniques and procedures
- Atomic Red Team executable tests
- Public penetration testing writeups
- Tool documentation and examples
- Your own session history (opt-in)

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. Users are responsible for complying with all applicable laws. The developers assume no liability for misuse.

---
