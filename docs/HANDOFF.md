# SploitGPT Project Handoff

## What is SploitGPT?

SploitGPT is an AI-powered penetration testing assistant built on a fine-tuned Qwen2.5-7B model. It runs inside a Kali Linux container and helps security professionals conduct authorized red-team engagements by:

- Executing reconnaissance scans (nmap, gobuster, etc.)
- Enumerating services (SMB, LDAP, SNMP, DNS)
- Searching for exploits (Metasploit, searchsploit, CVE databases)
- Running attacks with user confirmation
- Suggesting privilege escalation techniques

The model is fine-tuned to use a specific **tool-calling pattern** where it wraps shell commands in a `terminal` tool rather than hallucinating tool names.

---

## Current Production Model

**Model:** `sploitgpt-7b-v5.10e:q5`  
**Accuracy:** 82.9% on eval suite  
**Location:** `/home/cheese/SploitGPT/models-gguf/sploitgpt-7b-v5.10e/gguf/`

This model works and should be considered the baseline. Do not replace it unless a new model demonstrably exceeds its performance.

---

## Architecture

### Tool System
The agent has access to these tools (defined in `sploitgpt/tools/`):

| Tool | Purpose |
|------|---------|
| `terminal` | Execute shell commands in Kali container |
| `tool_search` | Find appropriate security tools for a task |
| `tool_help` | Get usage help for a specific tool |
| `msf_search` | Search Metasploit modules |
| `msf_info` | Get details about a Metasploit module |
| `msf_run` | Execute a Metasploit module |
| `cve_search` | Search CVE databases |
| `searchsploit` | Search Exploit-DB |
| `knowledge_search` | RAG search over security knowledge base |
| `get_privesc` | Get privilege escalation techniques (GTFOBins) |
| `get_shells` | Generate reverse shell payloads |
| `shodan_search` | Query Shodan API |
| `generate_wordlist` | Create targeted wordlists |
| `ask_user` | Request clarification from user |
| `finish` | Mark task complete |

### Critical Pattern: Terminal Wrapper
The model MUST use `terminal` to run shell commands:
```json
{"name": "terminal", "arguments": {"command": "nmap -sV 10.0.0.1"}}
```

NOT this (wrong):
```json
{"name": "nmap", "arguments": {"target": "10.0.0.1"}}
```

The base Qwen model doesn't know this pattern - it must be learned through fine-tuning.

### Enumeration Workflow
For service enumeration tasks (SMB, LDAP, SNMP, etc.), the expected pattern is:
1. `tool_search` - find the right tool
2. `tool_help` - get syntax if needed  
3. `terminal` - execute the command

### Confirmation Mode
When `CONFIRM_ACTIONS=true`, the model should:
1. Explain what it will do
2. Ask "Should I proceed?" / "Confirm?"
3. Wait for user to say "yes"
4. Then make the tool call

---

## Training Infrastructure

### Fine-tuning Script
`sploitgpt/training/finetune.py`

Uses Unsloth for fast LoRA training on Qwen2.5-7B-Instruct.

**Key parameters:**
- `--data`: Path to JSONL training data
- `--output-dir`: Where to save LoRA adapter
- `--resume-adapter`: **CRITICAL** - Path to existing adapter for incremental training
- `--epochs`: Training epochs (default 3)
- `--lora-r`: LoRA rank (default 64)
- `--lora-alpha`: LoRA alpha (default 128)

### Training Data Format
JSONL with messages array:
```json
{
  "messages": [
    {"role": "system", "content": "You are SploitGPT..."},
    {"role": "user", "content": "Scan 10.0.0.1 for open ports"},
    {"role": "assistant", "content": "I'll run nmap. Should I proceed?"},
    {"role": "user", "content": "yes"},
    {"role": "assistant", "content": "", "tool_calls": [
      {"id": "call_1", "type": "function", "function": {"name": "terminal", "arguments": {"command": "nmap -sV 10.0.0.1"}}}
    ]}
  ]
}
```

### Data Locations
- Training data: `data/training/*.jsonl`
- Production dataset: `data/training/sploitgpt_v5_10e_strict.jsonl`
- Generated datasets: `enumeration_strict.jsonl`, `fallback_chains.jsonl`, `triage_patterns.jsonl`, `recon_terminal.jsonl`

### Model Pipeline
1. Fine-tune with LoRA → saves adapter to `models-adapters/`
2. Merge LoRA into base model → full weights
3. Convert to GGUF format using llama.cpp
4. Quantize to Q5_K_M (5.4GB) or Q4_K_M (4.7GB)
5. Create Ollama model with Modelfile
6. Run evaluation

---

## Evaluation System

### Eval Script
`scripts/evaluate_model.py`

Runs 35 test cases across categories:
- recon (port scanning, ping sweeps)
- enumeration (SMB, LDAP, DNS, SNMP)
- web (directory brute force, tech fingerprinting)
- vuln (vulnerability scanning)
- exploit (Metasploit search/info)
- credentials (brute force, hash cracking)
- privesc (SUID, sudo, capabilities)
- fallback (handling tool failures)
- triage (filtering large result sets)

### Running Evaluation
```bash
PYTHONPATH=/home/cheese/SploitGPT \
SPLOITGPT_OLLAMA_HOST=http://localhost:11434 \
python scripts/evaluate_model.py --model sploitgpt-7b-v5.10e:q5
```

### What "Passing" Means
A test passes if:
1. Model calls the expected tool(s)
2. Tool arguments contain required terms
3. Model asks for confirmation when expected (confirm mode)
4. Model doesn't ask unnecessary questions

---

## What Went Wrong (v5.11 - v5.13)

### The Mistake
v5.10e achieved 82.9% accuracy through **incremental training** - each version built on the previous adapter using `--resume-adapter`.

Attempts to create v5.11+ trained **from scratch** on base Qwen, losing all the learned behaviors from v5.1 through v5.10e.

### Results
| Model | Accuracy | Issue |
|-------|----------|-------|
| v5.10e | 82.9% | Production baseline |
| v5.11 | 37.1% | Outputs `nmap` instead of `terminal` |
| v5.12 | 37.1% | Same issue |
| v5.13 | 0% | Completely broken |

### Root Cause
The training data teaches the `terminal` wrapper pattern, but when trained from scratch:
1. Base Qwen's prior knowledge interferes
2. Not enough examples to override base behavior
3. Model reverts to treating tool names as direct functions

---

## Path Forward

### Option A: Stay on v5.10e (Recommended Short-Term)
v5.10e works at 82.9%. Use it until you have a solid plan for improvement.

### Option B: Incremental Training (Correct Approach)
To improve on v5.10e:

1. **Get v5.10e adapter** - Either from backup or retrain v5.10e from scratch following the original incremental chain

2. **Create targeted delta dataset** - Focus ONLY on failing test cases:
   - Enumeration tasks not calling `tool_search` first
   - Fallback logic when primary tool fails
   - Triage for filtering large result sets

3. **Train incrementally:**
   ```bash
   python sploitgpt/training/finetune.py \
     --data data/training/delta_improvements.jsonl \
     --output-dir models-adapters/sploitgpt-7b-v5.11 \
     --resume-adapter models-adapters/sploitgpt-7b-v5.10e \
     --epochs 1 \
     --learning-rate 5e-5
   ```

4. **Evaluate before committing** - Run full eval suite before replacing production model

### Option C: Fresh Training with Complete Dataset
If starting fresh is necessary:

1. Combine ALL working training data into one dataset
2. Ensure heavy weighting on `terminal` wrapper examples
3. Include examples for EVERY eval test case category
4. Train for more epochs (5+) to override base model priors
5. Validate with quick sanity checks during training

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `sploitgpt/agent/agent.py` | Main agent logic, SYSTEM_PROMPT |
| `sploitgpt/training/finetune.py` | Fine-tuning script |
| `sploitgpt/training/collector.py` | Training data collection from sessions |
| `sploitgpt/core/config.py` | Settings (model, ollama host, etc.) |
| `sploitgpt/core/ollama.py` | Ollama API client |
| `scripts/evaluate_model.py` | Model evaluation suite |
| `scripts/generate_*.py` | Training data generators |
| `data/training/*.jsonl` | Training datasets |
| `models-gguf/` | Quantized GGUF models |
| `models-adapters/` | LoRA adapters |

---

## Environment Setup

### Dependencies
```bash
pip install -e .  # Install sploitgpt package
# or
pip install unsloth transformers datasets trl peft torch
```

### Ollama
Must have Ollama running with the model loaded:
```bash
ollama serve  # Start server
ollama create sploitgpt-7b-v5.10e:q5 -f models-gguf/sploitgpt-7b-v5.10e/gguf/Modelfile.q5
```

### Cloud GPU Training
For training, use a cloud GPU (L40S, A100, etc.):
1. Upload training data and finetune.py
2. Run training
3. Merge LoRA adapter
4. Convert to GGUF with llama.cpp
5. Quantize
6. Download and test locally

---

## Common Pitfalls

1. **Training from scratch** - Always use `--resume-adapter` for improvements
2. **Wrong Ollama host** - Set `SPLOITGPT_OLLAMA_HOST` environment variable
3. **Model name mismatch** - Use exact name including tag (`:q5`, `:latest`)
4. **Missing terminal wrapper** - Check training data has `"name": "terminal"` not tool names directly
5. **Eval connecting to wrong port** - Default is 11434, tunnels may use different ports

---

## Success Criteria

A production-ready model should achieve:
- **>85% accuracy** on eval suite
- **>90% confirmation rate** in confirm mode
- **Correct tool calling** - `terminal` wrapper, `tool_search` for enumeration
- **Graceful fallback** - Handles tool failures appropriately
- **No hallucination** - Doesn't invent tool names or flags

---

## Contact/Resources

- Project repo: `/home/cheese/SploitGPT`
- Eval results: `reports/evals/`
- Training logs: `logs/`
- Improvement plan: `docs/IMPROVEMENT_PLAN_V5.11.md`
