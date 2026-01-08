"""
SploitGPT Agent

The core AI agent that:
1. Understands natural language tasks
2. Plans using MITRE ATT&CK techniques
3. Asks clarifying questions when needed
4. Executes commands and parses output
5. Chains tools together
6. Uses GTFOBins for privilege escalation
7. Generates payloads and suggests wordlists
"""

import asyncio
import json
import re
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any

from sploitgpt.agent.context import (
    build_dynamic_context,
    get_context_builder,
    parse_service_from_nmap,
    parse_suid_binaries,
)
from sploitgpt.agent.response import AgentResponse
from sploitgpt.core.boot import BootContext
from sploitgpt.core.config import get_settings
from sploitgpt.core.ollama import OllamaClient
from sploitgpt.core.scope import check_command_scope, get_scope_mode, is_scope_defined
from sploitgpt.knowledge.rag import get_retrieved_context
from sploitgpt.tools import execute_tool
from sploitgpt.tools.commands import get_all_commands_formatted
from sploitgpt.training.collector import SessionCollector

# Heartbeat interval in seconds for long-running operations
HEARTBEAT_INTERVAL = 30.0

SYSTEM_PROMPT = """You are SploitGPT, an AI assistant for authorized red-team penetration testing.

## Your Environment
You are running inside a Kali Linux container with access to common security tools.

## Default Behavior (Autonomous Tool Use)
- If the request is actionable and required inputs are present, call the best tool immediately.
- Provide brief reasoning (1-2 sentences) before the tool call.
- Ask for clarification only when critical inputs are missing (target, scope, credentials) or the action is high-risk.
- If multiple viable tools exist, choose the best one and proceed.

## Confirmation Mode
- When CONFIRM_ACTIONS is enabled, follow this workflow:
  1. Explain what you'll do (1-2 sentences).
  2. Ask for confirmation explicitly (e.g., "Proceed?", "Confirm?", "Okay to run?").
  3. Wait for user to respond "yes".
  4. Then make the tool_call.
- Do not call tools until after the user confirms. If the user declines, offer a short alternative or ask how they'd like to proceed.

## When Executing
1. Execute one step at a time using tools (primarily `terminal`, sometimes Metasploit tools).
2. Save important output to `/app/loot/` using `tee` or tool flags.
3. Do not repeat scans unnecessarily.
4. On failure, switch strategy or tool rather than retrying the same call.

## Tool Use Rules
- Prefer one tool call per step (one command at a time).
- Wait for results before choosing the next step.
- When choosing among Kali tools, use `tool_search` to discover the best-fit command(s) if unsure.
- Do not guess flags/options. If unsure, use `tool_help` (preferred) or `knowledge_search`, then run via `terminal`.
 - For Metasploit: prefer `msf_search` -> `msf_info` -> `msf_run` (avoid guessing required options).
 - Do not invent tool names; run commands via `terminal`.
- Use `finish` when the task is complete with a concise summary and (if applicable) MITRE technique IDs.
- If you need inbound listeners, use an allowed `LPORT` and only start them when needed.
"""


@dataclass
class PendingInteraction:
    """Represents a pending user interaction required to proceed."""

    kind: str  # "ask_user" | "confirm_tool"
    tool_name: str
    tool_args: dict[str, Any]
    question: str
    options: list[str]


class Agent:
    """The SploitGPT AI Agent."""

    def __init__(self, context: BootContext):
        self.context = context
        self.settings = get_settings()
        self.conversation: list[dict[str, Any]] = []
        self._http_client_closed = False
        # Reset shared context builder for this session
        from sploitgpt.agent.context import get_context_builder

        get_context_builder().reset()

        # Session tracking
        self.session_collector = SessionCollector(self.settings.sessions_dir / "sessions.db")
        self.current_phase = "recon"
        self.discovered_services: list[str] = []
        self.discovered_hosts: list[str] = []
        self.target: str | None = None
        self.lhost: str | None = None

        # Interaction gating
        self.autonomous: bool = False
        self.confirm_actions: bool = self.settings.confirm_actions
        self._pending: PendingInteraction | None = None

        # Tool call tracking to prevent infinite loops
        self._tool_call_depth: int = 0
        self._max_tool_depth: int = 10  # Max consecutive tool calls before stopping
        self._failed_tools: dict[str, int] = {}  # Track consecutive failures per tool
        self._max_tool_failures: int = 2  # Max failures before skipping a tool
        self._recent_tools: list[str] = []  # Track recent tool calls for loop detection
        self._max_repeated_pattern: int = 3  # Stop if same tool called 3+ times consecutively

        # Start session
        self.session_id = str(uuid.uuid4())[:8]
        self.session_collector.start_session(self.session_id)

        # Set audit context and log session start
        from sploitgpt.core.audit import get_audit_logger, set_audit_context

        set_audit_context(session_id=self.session_id)
        get_audit_logger().log_session_start(self.session_id)

    async def aclose(self) -> None:
        """Cleanup resources (placeholder for future shared clients)."""
        self._http_client_closed = True

    async def process(self, user_input: str) -> AsyncGenerator[AgentResponse, None]:
        """Process user input and yield responses."""

        # If we're waiting on a choice/confirmation, treat input as the answer.
        if self._pending is not None:
            async for r in self.submit_choice(user_input):
                yield r
            return

        # Reset tool call tracking for new user input
        self._tool_call_depth = 0
        self._failed_tools.clear()
        self._recent_tools.clear()

        # Extract target from common patterns
        self._extract_target_info(user_input)

        # Check if we should ask for clarification before proceeding
        clarification = self._should_clarify(user_input)
        if clarification is not None:
            question, options = clarification
            self._pending = PendingInteraction(
                kind="clarify",
                tool_name="ask_user",
                tool_args={"question": question, "options": options},
                question=question,
                options=options,
            )
            yield AgentResponse(type="choice", question=question, options=options)
            return

        # Add user message to conversation
        self.conversation.append({"role": "user", "content": user_input})

        # Build messages for LLM
        messages = [{"role": "system", "content": self._build_system_prompt()}, *self.conversation]

        # Call LLM
        try:
            response = await self._call_llm(messages)
        except Exception as e:
            yield AgentResponse(type="error", content=str(e))
            return

        # Process response
        async for agent_response in self._process_llm_response(response):
            yield agent_response

    def _extract_target_info(self, text: str) -> None:
        """Extract target IP/hostname from user input."""
        # IP pattern
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        matches = re.findall(ip_pattern, text)
        if matches:
            self.target = matches[0]
            get_context_builder().set_target(self.target)

        # LHOST pattern (look for "from", "using", "attacker", "our IP")
        if "lhost" in text.lower() or "our ip" in text.lower():
            for match in matches:
                if match != self.target:
                    self.lhost = match
                    get_context_builder().set_lhost(self.lhost)
                    break

    def _should_clarify(self, user_input: str) -> tuple[str, list[str]] | None:
        """Check if clarification is needed before proceeding.

        Returns a (question, options) tuple if clarification is needed,
        or None if we should proceed without clarification.

        Note: This is designed to be conservative - we prefer to let the LLM
        handle ambiguity rather than blocking with too many prompts. Only
        truly critical cases trigger clarification.
        """
        text_lower = user_input.lower()

        # Check if there's already an IP pattern in the input
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        has_ip_in_input = bool(re.search(ip_pattern, user_input))

        # Check for hostname patterns (simple alphanumeric.domain patterns)
        hostname_pattern = r"\b[a-zA-Z][a-zA-Z0-9-]*\.(?:com|net|org|io|local|htb|thm)\b"
        has_hostname_in_input = bool(re.search(hostname_pattern, user_input, re.IGNORECASE))

        # If there's a target in the input, extract will handle it
        if has_ip_in_input or has_hostname_in_input:
            return None

        # If we already have a target set, no need to ask
        if self.target is not None:
            return None

        # Define high-risk keywords that should trigger confirmation
        # These are truly destructive operations, not normal pentest actions
        high_risk_keywords = [
            "delete",
            "wipe",
            "destroy",
            "format",
            "drop database",
            "rm -rf",
            "ransomware",
            "shutdown",
            "reboot",
        ]

        is_high_risk = any(kw in text_lower for kw in high_risk_keywords)

        # For high-risk actions, always ask for confirmation even in autonomous mode
        if is_high_risk:
            return (
                "This appears to be a destructive operation. Confirm you want to proceed?",
                ["Yes, proceed", "No, abort", "Show me the plan first"],
            )

        # For exploit/attack requests with explicit "the target" but no actual target,
        # ask for clarification. This catches phrases like "exploit the target" when
        # no target is set.
        explicit_target_ref = any(
            phrase in text_lower
            for phrase in ["the target", "the box", "the machine", "the server", "the host"]
        )

        needs_target_keywords = ["exploit", "attack", "shell", "reverse shell", "meterpreter"]
        is_exploit_request = any(kw in text_lower for kw in needs_target_keywords)

        if explicit_target_ref and is_exploit_request and self.target is None:
            return (
                "What is the target IP address or hostname?",
                ["Enter target IP/hostname"],
            )

        # No clarification needed - let the LLM handle it
        return None

    def _build_system_prompt(self) -> str:
        """Build the system prompt with current context."""
        # Get command reference
        command_ref = get_all_commands_formatted()

        # Current context
        listener_ports = getattr(self.settings, "listener_ports", "40000-40100")
        context_info = f"""
## Current Session
- Target: {self.target or "Not set - ask user for target"}
- Known hosts: {", ".join(self.discovered_hosts) if self.discovered_hosts else "None yet"}
- Services found: {", ".join(self.discovered_services) if self.discovered_services else "None yet"}
- Phase: {self.current_phase.upper()}
- Metasploit: {"Available" if self.context.msf_connected else "Not connected"}
- Listener ports: {listener_ports} (opened on demand)

{command_ref}
"""

        # Dynamic context based on discovered services
        dynamic_context = build_dynamic_context(
            target=self.target,
            services=self.discovered_services,
            phase=self.current_phase,
            lhost=self.lhost,
        )

        if dynamic_context:
            context_info += f"\n## Service-Specific Techniques\n{dynamic_context}"

        # Retrieval-augmented context from local curated sources + DB cache.
        last_user_msg = ""
        for msg in reversed(self.conversation):
            if msg.get("role") == "user":
                last_user_msg = str(msg.get("content") or "")
                break

        retrieval_query = " ".join(
            [
                last_user_msg.strip(),
                (self.target or "").strip(),
                " ".join(self.discovered_services[:8]).strip(),
            ]
        ).strip()

        retrieved = get_retrieved_context(
            retrieval_query,
            services=self.discovered_services,
            phase=self.current_phase,
            top_k=4,
            max_chars=2200,
        )
        if retrieved:
            context_info += f"\n\n{retrieved}"

        return SYSTEM_PROMPT + context_info

    async def _call_llm(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Call the Ollama LLM with basic retry and friendly errors."""
        tools = self._get_tool_definitions() if self._supports_tools() else None
        last_error: Exception | None = None

        for attempt in range(2):
            try:
                async with OllamaClient() as client:
                    response: dict[str, Any] = await client.chat(
                        messages,
                        stream=False,
                        tools=tools,
                    )
                return response
            except Exception as e:
                last_error = e
                # Backoff on transient errors
                if attempt < 1:
                    await asyncio.sleep(0.6)

        raise RuntimeError(
            f"Ollama call failed at {self.settings.ollama_host} for model {self.settings.effective_model}: {last_error}"
        )

    def _supports_tools(self) -> bool:
        """Check if the current model supports function calling."""
        # Models known to support Ollama tools
        tool_models = ["llama3.1", "llama3.2", "mistral", "mixtral", "qwen2.5", "sploitgpt"]
        model_lower = self.settings.effective_model.lower()
        return any(m in model_lower for m in tool_models)

    def _parse_commands_from_text(self, text: str) -> list[dict[str, Any]]:
        """Parse shell commands from LLM text output when tools aren't supported.

        Looks for commands in:
        - Code blocks: ```bash ... ``` or ```shell ... ``` or ``` ... ```
        - Lines starting with $ or #
        - Common command patterns
        """
        tool_calls: list[dict[str, Any]] = []

        # Pattern 1: Code blocks with bash/shell/no language
        code_block_pattern = r"```(?:bash|shell|sh)?\s*\n(.*?)```"
        matches = re.findall(code_block_pattern, text, re.DOTALL | re.IGNORECASE)

        for match in matches:
            # Each line in the code block could be a command
            for line in match.strip().split("\n"):
                line = line.strip()
                # Skip comments and empty lines
                if not line or (line.startswith("#") and not line.startswith("#!")):
                    continue
                # Remove leading $ or # prompt
                if line.startswith(("$ ", "# ")):
                    line = line[2:]
                if line:
                    tool_calls.append(
                        {"function": {"name": "terminal", "arguments": {"command": line}}}
                    )

        # If no code blocks, look for inline commands with $ prefix
        if not tool_calls:
            for line in text.split("\n"):
                line = line.strip()
                if line.startswith("$ "):
                    cmd = line[2:].strip()
                    if cmd:
                        tool_calls.append(
                            {"function": {"name": "terminal", "arguments": {"command": cmd}}}
                        )

        return tool_calls

    def _parse_tool_call_xml(self, text: str) -> list[dict[str, Any]]:
        """Parse <tool_call>{...}</tool_call> XML format emitted by fine-tuned models.

        The v3 model emits tool calls in the format:
        <tool_call>{"name": "tool_name", "arguments": "{...}"}</tool_call>

        Returns a list of tool calls in the standard format expected by the agent.
        """
        tool_calls: list[dict[str, Any]] = []

        # Pattern to match <tool_call>...</tool_call> blocks
        pattern = r"<tool_call>\s*(\{.*?\})\s*</tool_call>"
        matches = re.findall(pattern, text, re.DOTALL)

        for match in matches:
            try:
                data = json.loads(match)
                name = data.get("name", "")
                arguments = data.get("arguments", {})

                # Arguments may be a JSON string that needs parsing
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        # Keep as string if not valid JSON
                        pass

                if name:
                    tool_calls.append({"function": {"name": name, "arguments": arguments}})
            except json.JSONDecodeError:
                continue

        return tool_calls

    def _parse_ask_user_from_text(self, text: str) -> tuple[str, list[str]] | None:
        """Recover an ask_user payload when the model prints JSON instead of calling the tool."""
        # Accept either ```json ...``` or ``` ...``` blocks that decode to an object like:
        # {"question": "...", "options": ["...", ...]}
        code_block_pattern = r"```(?:json)?\s*\n(.*?)```"
        matches = re.findall(code_block_pattern, text, re.DOTALL | re.IGNORECASE)

        for block in matches:
            candidate = block.strip()
            if not candidate.startswith("{"):
                continue
            try:
                data = json.loads(candidate)
            except Exception:
                continue

            if not isinstance(data, dict):
                continue

            question = data.get("question")
            options = data.get("options")

            if not isinstance(question, str) or not question.strip():
                continue
            if not isinstance(options, list) or not options:
                continue

            # Normalize options to strings.
            normalized: list[str] = []
            for opt in options:
                if isinstance(opt, str) and opt.strip():
                    normalized.append(opt.strip())
                else:
                    normalized.append(str(opt))

            # Basic sanity limits to avoid accidentally treating unrelated JSON as a prompt.
            if len(normalized) < 2 or len(normalized) > 10:
                continue

            return question.strip(), normalized

        return None

    def _infer_confirmation_question(self, text: str) -> str | None:
        """Infer a confirmation prompt when the model asks to execute without a tool call."""
        lowered = text.lower()
        triggers = (
            "would you like me to execute",
            "would you like me to run",
            "should i execute",
            "should i run",
            "should i proceed",
            "may i proceed",
            "do you want me to execute",
            "do you want me to run",
            "confirm?",
            "proceed?",
            "okay to execute",
            "okay to run",
            "okay if i run",
            "okay if i proceed",
            "shall i",
            "can i run",
            "can i proceed",
            "ready to execute",
            "ready to run",
        )
        if not any(t in lowered for t in triggers):
            return None

        last_line = text.strip().splitlines()[-1].strip()
        if last_line.endswith("?"):
            return last_line
        return "Execute the recommended step?"

    def _get_tool_definitions(self) -> list[dict[str, Any]]:
        """Get tool definitions for function calling."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "terminal",
                    "description": "Run a shell command in the Kali Linux environment. Prefer args[] over raw shell strings when possible.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute (no shell features; will be split safely)",
                            },
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Preferred: argv-style list to execute without a shell",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds (default 300)",
                                "default": 300,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "ask_user",
                    "description": "Ask the user to choose between multiple options. Use when you find multiple attack paths or need clarification.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "question": {"type": "string", "description": "The question to ask"},
                            "options": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of options for the user to choose from",
                            },
                        },
                        "required": ["question", "options"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "knowledge_search",
                    "description": "Search SploitGPT's local knowledge base (methodology, Kali tool reference, cached techniques/templates). Use this when you need exact commands or a per-service playbook.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (e.g., 'smb enumeration', 'hydra ssh', 'T1046 network service discovery')",
                            },
                            "top_k": {
                                "type": "integer",
                                "description": "Maximum number of snippets to return",
                                "default": 5,
                            },
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "tool_search",
                    "description": "Search installed Kali tools and return short candidates with summaries. Use this when you’re not sure which tool to use for a task.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "What you’re trying to do (e.g., 'snmp enumerate', 'ldap users', 'http fuzz', 'smb shares')",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results to return (default 8, max 20)",
                                "default": 8,
                            },
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "tool_help",
                    "description": "Fetch usage/synopsis for a local tool from cached docs, man pages, or --help output. Use this before running an unfamiliar tool so you don’t guess flags.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "tool": {
                                "type": "string",
                                "description": "Tool/command name (e.g., 'nmap', 'snmpwalk', 'rpcclient')",
                            },
                            "max_chars": {
                                "type": "integer",
                                "description": "Max characters to return (default 3200)",
                                "default": 3200,
                            },
                        },
                        "required": ["tool"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "shodan_search",
                    "description": "Search Shodan for exposed services, banners, and vulns. Requires SHODAN_API_KEY.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Shodan query (e.g., 'apache country:US port:80')",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results to return (default 5, max 20)",
                                "default": 5,
                            },
                            "page": {
                                "type": "integer",
                                "description": "Shodan results page (default 1)",
                                "default": 1,
                            },
                            "facets": {
                                "type": "string",
                                "description": "Optional comma-separated facets (e.g., 'org,port,country')",
                            },
                            "minify": {
                                "type": "boolean",
                                "description": "Reduce response payload (may omit banner details)",
                                "default": False,
                            },
                            "output": {
                                "type": "string",
                                "description": "Output format: 'text' or 'json'",
                                "default": "text",
                            },
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_search",
                    "description": "Search Metasploit/SearchSploit for modules matching a query",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (e.g., 'apache', 'CVE-2021-44228', 'eternalblue', 'portscan')",
                            },
                            "module_type": {
                                "type": "string",
                                "description": "Optional filter: exploit, auxiliary, post, payload",
                            },
                        },
                        "required": ["query"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_info",
                    "description": "Inspect a Metasploit module (info + required options). Use this before msf_run to avoid guessing option names.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module": {
                                "type": "string",
                                "description": "Module path (e.g., 'auxiliary/scanner/portscan/tcp')",
                            }
                        },
                        "required": ["module"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_sessions",
                    "description": "List active Metasploit sessions (read-only)",
                    "parameters": {"type": "object", "properties": {}},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_run",
                    "description": "Run a Metasploit module with options (prefer msf_info first to check required options)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module": {
                                "type": "string",
                                "description": "Module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')",
                            },
                            "options": {
                                "type": "object",
                                "description": "Module options (e.g., {'RHOSTS': '10.0.0.1', 'LHOST': '10.0.0.2'})",
                            },
                        },
                        "required": ["module", "options"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_meterpreter",
                    "description": "Run a meterpreter command in an existing session",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "session_id": {
                                "type": "integer",
                                "description": "Session ID (from msf_sessions)",
                            },
                            "command": {
                                "type": "string",
                                "description": "Meterpreter command (e.g., 'sysinfo', 'getuid')",
                            },
                        },
                        "required": ["session_id", "command"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "save_note",
                    "description": "Save a note to the loot directory for later reference",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "title": {
                                "type": "string",
                                "description": "Note title (becomes filename)",
                            },
                            "content": {"type": "string", "description": "Note content"},
                        },
                        "required": ["title", "content"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_privesc",
                    "description": "Get privilege escalation techniques for discovered SUID/sudo binaries using GTFOBins",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "binaries": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of binary names found with SUID or sudo permissions",
                            }
                        },
                        "required": ["binaries"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_shells",
                    "description": "Get reverse shell payloads for various languages",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "lhost": {"type": "string", "description": "Attacker IP address"},
                            "lport": {
                                "type": "integer",
                                "description": "Attacker port (default 4444)",
                            },
                        },
                        "required": ["lhost"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "generate_wordlist",
                    "description": "Generate a targeted password wordlist using psudohash-style mutations and save it to loot/wordlists.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "base": {
                                "type": "string",
                                "description": "Primary keyword (e.g., company, username, hostname)",
                            },
                            "extra_words": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Additional keywords to combine",
                            },
                            "years": {
                                "type": "string",
                                "description": "Optional year or range to append (e.g., '2022' or '2015-2024')",
                            },
                            "min_len": {
                                "type": "integer",
                                "description": "Minimum length to keep (default 6)",
                                "default": 6,
                            },
                            "max_len": {
                                "type": "integer",
                                "description": "Maximum length to keep (default 18)",
                                "default": 18,
                            },
                            "save_as": {
                                "type": "string",
                                "description": "Optional filename; defaults to <base>.txt",
                            },
                        },
                        "required": ["base"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "nuclei_scan",
                    "description": "Run nuclei vulnerability scanner against a target using templates. Use for web vulnerability scanning, CVE detection, and misconfiguration checks.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target URL or host (e.g., 'https://example.com' or '10.0.0.1')",
                            },
                            "tags": {
                                "type": "string",
                                "description": "Comma-separated template tags (e.g., 'cve,exposure,misconfig,panel')",
                            },
                            "templates": {
                                "type": "string",
                                "description": "Specific template path or ID (e.g., 'cves/2021/CVE-2021-44228')",
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by severity (e.g., 'high,critical' or 'medium,high,critical')",
                            },
                            "rate_limit": {
                                "type": "integer",
                                "description": "Max requests per second (default 150)",
                                "default": 150,
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Scan timeout in seconds (default 600)",
                                "default": 600,
                            },
                        },
                        "required": ["target"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "nuclei_templates",
                    "description": "List available nuclei templates. Use to find templates before running a scan.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "search": {
                                "type": "string",
                                "description": "Search term to filter templates",
                            },
                            "tag": {
                                "type": "string",
                                "description": "Filter by tag (e.g., 'cve', 'exposure', 'panel')",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Max templates to return (default 20)",
                                "default": 20,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish",
                    "description": "Complete the task and provide a summary of findings",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {
                                "type": "string",
                                "description": "Summary of what was accomplished including findings",
                            },
                            "techniques_used": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "MITRE ATT&CK technique IDs used (e.g., ['T1046', 'T1110'])",
                            },
                        },
                        "required": ["summary"],
                    },
                },
            },
        ]

    async def _process_llm_response(
        self, response: dict[str, Any]
    ) -> AsyncGenerator[AgentResponse, None]:
        """Process the LLM response and execute any tool calls.

        This may pause (yield a `choice`) when user input is required.
        Call `submit_choice()` to resume.
        """

        message = response.get("message", {}) or {}
        content = message.get("content", "") or ""
        tool_calls = message.get("tool_calls", []) or []

        # If no tool calls but we have content, try to parse from text
        if not tool_calls and content:
            # First try <tool_call> XML format (used by fine-tuned v3 model)
            tool_calls = self._parse_tool_call_xml(content)

            # Fall back to parsing bash code blocks
            if not tool_calls:
                tool_calls = self._parse_commands_from_text(content)

        # Keep the UX predictable: one tool call per step.
        if tool_calls:
            tool_calls = tool_calls[:1]

        # Add assistant message to conversation
        self.conversation.append(
            {
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls if tool_calls else None,
            }
        )

        # Yield any text content
        if content:
            yield AgentResponse(type="message", content=content)

        # If the model failed to call ask_user but printed a JSON payload, recover into a real choice.
        if not tool_calls and content:
            recovered = self._parse_ask_user_from_text(content)
            if recovered is not None:
                question, options = recovered
                self._pending = PendingInteraction(
                    kind="ask_user",
                    tool_name="ask_user",
                    tool_args={"question": question, "options": options},
                    question=question,
                    options=options,
                )
                yield AgentResponse(type="choice", question=question, options=options)
                return

            inferred = self._infer_confirmation_question(content)
            if inferred is not None:
                options = ["Yes", "No"]
                self._pending = PendingInteraction(
                    kind="ask_user",
                    tool_name="ask_user",
                    tool_args={"question": inferred, "options": options},
                    question=inferred,
                    options=options,
                )
                yield AgentResponse(type="choice", question=inferred, options=options)
                return

        if not tool_calls:
            return

        tool_call = tool_calls[0]
        function = tool_call.get("function", {}) or {}
        name = function.get("name", "")
        args = function.get("arguments", {})

        # Parse args if string
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}

        # Normalize tool name to handle model variations (e.g., 'execute' -> 'terminal')
        original_name = name
        name = self._normalize_tool_name(name)

        # If this was a specific command tool, extract/reconstruct the command
        if original_name.lower() != name and name == "terminal":
            extracted_cmd = self._extract_command_from_args(original_name, args)
            if extracted_cmd:
                args = {"command": extracted_cmd}

        # Ask-user tool: pause and wait for UI
        if name == "ask_user":
            question = args.get("question", "")
            options = args.get("options", [])
            self._pending = PendingInteraction(
                kind="ask_user",
                tool_name=name,
                tool_args=args,
                question=question,
                options=options,
            )
            yield AgentResponse(type="choice", question=question, options=options)
            return

        # Confirmation gate: pause before any tool runs
        confirm_exempt = {"ask_user", "finish"}
        if name not in confirm_exempt and self.confirm_actions and not self.autonomous:
            if name == "terminal":
                preview = args.get("command", "")
            else:
                preview = f"{name} {args}"

            question = f"Execute this step?\n{preview}"
            options = ["Yes", "No", "Yes (autonomous)"]

            self._pending = PendingInteraction(
                kind="confirm_tool",
                tool_name=name,
                tool_args=args,
                question=question,
                options=options,
            )
            yield AgentResponse(type="choice", question=question, options=options)
            return

        # Check if this tool has failed too many times
        if self._failed_tools.get(name, 0) >= self._max_tool_failures:
            error_msg = f"Tool '{name}' has failed {self._max_tool_failures} times. Skipping to avoid loops."
            yield AgentResponse(type="error", content=error_msg)
            self.conversation.append({"role": "tool", "content": error_msg, "name": name})
            return

        # Track recent tools and detect repetitive patterns
        self._recent_tools.append(name)
        if len(self._recent_tools) >= self._max_repeated_pattern:
            recent = self._recent_tools[-self._max_repeated_pattern :]
            if len(set(recent)) == 1:  # Same tool called repeatedly
                error_msg = f"Tool '{name}' called {self._max_repeated_pattern} times in a row. Breaking potential loop."
                yield AgentResponse(type="error", content=error_msg)
                self.conversation.append({"role": "tool", "content": error_msg, "name": name})
                return

        # Scope enforcement for commands that target external hosts
        if name == "terminal" and is_scope_defined():
            command = args.get("command", "")
            scope_results = check_command_scope(command)
            out_of_scope = [r for r in scope_results if not r.in_scope]

            if out_of_scope:
                scope_mode = get_scope_mode()
                for scope_result in out_of_scope:
                    yield AgentResponse.scope_warning(scope_result.target, scope_result.reason)
                    # Audit log scope warning/violation
                    from sploitgpt.core.audit import get_audit_logger

                    audit = get_audit_logger()
                    if scope_mode == "block":
                        audit.log_scope_violation(
                            target=scope_result.target,
                            reason=scope_result.reason,
                            command=command,
                            session_id=self.session_id,
                        )
                    else:
                        audit.log_scope_warning(
                            target=scope_result.target,
                            reason=scope_result.reason,
                            command=command,
                            session_id=self.session_id,
                        )

                if scope_mode == "block":
                    block_msg = f"Blocked: Command targets out-of-scope host(s): {', '.join(sr.target for sr in out_of_scope)}"
                    yield AgentResponse(type="error", content=block_msg)
                    self.conversation.append({"role": "tool", "content": block_msg, "name": name})
                    return
                # In "warn" mode, continue execution after warnings

        # Scope enforcement for MSF tools
        if name in ("msf_run", "msf_module") and is_scope_defined():
            options = args.get("options", {})
            msf_out_of_scope = self._check_msf_scope(options)

            if msf_out_of_scope:
                scope_mode = get_scope_mode()
                for target, reason in msf_out_of_scope:
                    yield AgentResponse.scope_warning(target, reason)
                    # Audit log scope warning/violation for MSF
                    from sploitgpt.core.audit import get_audit_logger

                    audit = get_audit_logger()
                    module = args.get("module", "")
                    if scope_mode == "block":
                        audit.log_scope_violation(
                            target=target,
                            reason=reason,
                            command=f"msf_run {module}",
                            session_id=self.session_id,
                        )
                    else:
                        audit.log_scope_warning(
                            target=target,
                            reason=reason,
                            command=f"msf_run {module}",
                            session_id=self.session_id,
                        )

                if scope_mode == "block":
                    block_msg = f"Blocked: MSF module targets out-of-scope host(s): {', '.join(t for t, _ in msf_out_of_scope)}"
                    yield AgentResponse(type="error", content=block_msg)
                    self.conversation.append({"role": "tool", "content": block_msg, "name": name})
                    return
                # In "warn" mode, continue execution after warnings

        # Execute tool call with activity tracking and heartbeat support
        import time

        # Emit activity start
        if name == "terminal":
            cmd_preview = args.get("command", "")[:50]
            yield AgentResponse.activity_start(name, f"Running: {cmd_preview}...")
        else:
            yield AgentResponse.activity_start(name)

        start_time = time.monotonic()

        # Execute with heartbeat support for long-running operations
        result: str | None = None
        tool_task = asyncio.create_task(self._execute_tool_call(name, args))

        while not tool_task.done():
            try:
                # Wait for either the tool to complete or heartbeat interval
                await asyncio.wait_for(
                    asyncio.shield(tool_task),
                    timeout=HEARTBEAT_INTERVAL,
                )
            except TimeoutError:
                # Tool still running, emit heartbeat
                elapsed_so_far = time.monotonic() - start_time
                yield AgentResponse.activity_heartbeat(name, elapsed_so_far)

        # Get the result (task is guaranteed done now)
        result = tool_task.result()
        elapsed = time.monotonic() - start_time

        # Emit activity complete
        yield AgentResponse.activity_complete(name, elapsed)

        # Track tool failures - check for error patterns consistently
        # Tools return errors as "Error: ..." or "Error executing ..."
        is_error = (
            result is not None
            and isinstance(result, str)
            and result.strip().lower().startswith("error")
        )
        if is_error:
            self._failed_tools[name] = self._failed_tools.get(name, 0) + 1
        else:
            # Reset failure count on success
            self._failed_tools[name] = 0

        if result is not None:
            if name == "terminal":
                yield AgentResponse(type="command", content=args.get("command", ""))
                yield AgentResponse(type="result", content=result)
                self._learn_from_output(args.get("command", ""), result)

            elif name == "finish":
                summary = args.get("summary", "")
                techniques = args.get("techniques_used", [])

                # Record summary as a turn, then end the session.
                from sploitgpt.training.collector import SessionTurn

                self.session_collector.add_turn(
                    self.session_id,
                    SessionTurn(role="assistant", content=summary),
                )
                self.session_collector.end_session(
                    session_id=self.session_id,
                    successful=True,
                    rating=0,
                )

                # Audit log session end
                from sploitgpt.core.audit import get_audit_logger

                get_audit_logger().log_session_end(
                    self.session_id,
                    successful=True,
                    techniques_used=techniques,
                )

                yield AgentResponse(
                    type="done",
                    content=summary,
                    data={"techniques": techniques},
                )
                return

            elif name in ("get_privesc", "get_shells"):
                yield AgentResponse(type="info", content=result)

            else:
                yield AgentResponse(type="result", content=result)

            # Add tool result to conversation
            self.conversation.append({"role": "tool", "content": str(result), "name": name})

        # Check depth limit before continuing
        self._tool_call_depth += 1
        if self._tool_call_depth >= self._max_tool_depth:
            yield AgentResponse(
                type="error",
                content=f"Reached maximum tool call depth ({self._max_tool_depth}). Stopping to prevent infinite loop.",
            )
            return

        # Continue the conversation
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self.conversation,
        ]

        try:
            next_response = await self._call_llm(messages)
            async for agent_response in self._process_llm_response(next_response):
                yield agent_response
        except Exception as e:
            yield AgentResponse(type="error", content=str(e))

    async def submit_choice(self, user_input: str) -> AsyncGenerator[AgentResponse, None]:
        """Submit a response to a pending choice/confirmation and continue."""

        if self._pending is None:
            yield AgentResponse(type="error", content="No pending choice.")
            return

        pending = self._pending

        selection = user_input.strip()
        chosen: str | None = None

        # Numeric selection (1-based)
        if selection.isdigit():
            idx = int(selection) - 1
            if 0 <= idx < len(pending.options):
                chosen = pending.options[idx]

        # Simple shorthands for confirmations
        if chosen is None and pending.kind == "confirm_tool":
            low = selection.lower()
            if low in ("y", "yes"):
                chosen = "Yes"
            elif low in ("n", "no"):
                chosen = "No"
            elif low in ("a", "auto", "autonomous"):
                chosen = "Yes (autonomous)"

        if chosen is None:
            yield AgentResponse(type="error", content="Invalid selection.")
            yield AgentResponse(type="choice", question=pending.question, options=pending.options)
            return

        # Clear pending state
        self._pending = None

        if pending.kind == "ask_user":
            # Feed the selected option back as the ask_user tool result
            self.conversation.append({"role": "tool", "content": chosen, "name": "ask_user"})

        elif pending.kind == "clarify":
            # Handle clarification responses
            # User provided additional info (like target IP) or made a choice
            if chosen.lower().startswith("no") or chosen.lower() == "abort":
                yield AgentResponse(type="message", content="Operation cancelled.")
                return

            # For target requests, the user's input is the target itself
            if "target" in pending.question.lower() and "ip" in pending.question.lower():
                # User might have provided the target directly or selected "Enter target"
                # If they selected "Enter target IP/hostname", prompt again
                if "enter" in chosen.lower():
                    # Re-prompt - they need to actually type the target
                    yield AgentResponse(
                        type="message",
                        content="Please type the target IP address or hostname.",
                    )
                    return

                # Try to extract target from the chosen text
                ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
                ip_match = re.search(ip_pattern, selection)
                if ip_match:
                    self.target = ip_match.group()
                    get_context_builder().set_target(self.target)
                    yield AgentResponse(
                        type="info",
                        content=f"Target set to: {self.target}",
                    )
                elif selection and not selection.isdigit():
                    # Assume the user typed a hostname
                    self.target = selection
                    get_context_builder().set_target(self.target)
                    yield AgentResponse(
                        type="info",
                        content=f"Target set to: {self.target}",
                    )
                else:
                    # Can't proceed without target
                    yield AgentResponse(
                        type="error",
                        content="Could not determine target. Please provide a valid IP or hostname.",
                    )
                    return

            elif "high-risk" in pending.question.lower():
                # Handle high-risk confirmation
                if "show" in chosen.lower() or "plan" in chosen.lower():
                    yield AgentResponse(
                        type="info",
                        content="Proceeding with explanation mode. I'll explain each step before taking action.",
                    )
                    # Set autonomous to False to ensure confirmation prompts
                    self.autonomous = False
                elif chosen.lower().startswith("yes"):
                    yield AgentResponse(type="info", content="Proceeding with operation...")
                else:
                    yield AgentResponse(type="message", content="Operation cancelled.")
                    return

        elif pending.kind == "confirm_tool":
            # Handle autonomous toggle
            if chosen.lower().startswith("yes") and "autonomous" in chosen.lower():
                self.autonomous = True
                chosen = "Yes"

            if chosen.lower().startswith("no"):
                # Tell the model we skipped this action
                if pending.tool_name == "terminal":
                    cmd = pending.tool_args.get("command", "")
                    skip_msg = f"User declined to execute: {cmd}"
                else:
                    skip_msg = f"User declined to execute: {pending.tool_name}"

                self.conversation.append(
                    {"role": "tool", "content": skip_msg, "name": pending.tool_name}
                )
                yield AgentResponse(type="message", content=skip_msg)
            else:
                # Execute the tool now
                name = pending.tool_name
                args = pending.tool_args

                result = await self._execute_tool_call(name, args)

                if result is not None:
                    if name == "terminal":
                        yield AgentResponse(type="command", content=args.get("command", ""))
                        yield AgentResponse(type="result", content=result)
                        self._learn_from_output(args.get("command", ""), result)

                    elif name == "finish":
                        summary = args.get("summary", "")
                        techniques = args.get("techniques_used", [])

                        from sploitgpt.training.collector import SessionTurn

                        self.session_collector.add_turn(
                            self.session_id,
                            SessionTurn(role="assistant", content=summary),
                        )
                        self.session_collector.end_session(
                            session_id=self.session_id,
                            successful=True,
                            rating=0,
                        )

                        # Audit log session end
                        from sploitgpt.core.audit import get_audit_logger

                        get_audit_logger().log_session_end(
                            self.session_id,
                            successful=True,
                            techniques_used=techniques,
                        )

                        yield AgentResponse(
                            type="done",
                            content=summary,
                            data={"techniques": techniques},
                        )
                        return

                    elif name in ("get_privesc", "get_shells"):
                        yield AgentResponse(type="info", content=result)

                    else:
                        yield AgentResponse(type="result", content=result)

                    self.conversation.append({"role": "tool", "content": str(result), "name": name})

        # Continue conversation after providing tool result / skip
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self.conversation,
        ]

        try:
            next_response = await self._call_llm(messages)
            async for agent_response in self._process_llm_response(next_response):
                yield agent_response
        except Exception as e:
            yield AgentResponse(type="error", content=str(e))

    def _normalize_tool_name(self, name: str) -> str:
        """Normalize tool names to handle model variations."""
        # Map common aliases to canonical tool names
        aliases = {
            # Terminal/shell command execution
            "execute": "terminal",
            "run": "terminal",
            "shell": "terminal",
            "bash": "terminal",
            "cmd": "terminal",
            "command": "terminal",
            # Specific commands that should go through terminal
            "nmap": "terminal",
            "echo": "terminal",
            "ls": "terminal",
            "cat": "terminal",
            "grep": "terminal",
            "curl": "terminal",
            "wget": "terminal",
            "ping": "terminal",
            "netcat": "terminal",
            "nc": "terminal",
            "sqlmap": "terminal",
            "gobuster": "terminal",
            "dirb": "terminal",
            "nikto": "terminal",
            "hydra": "terminal",
            "john": "terminal",
            "hashcat": "terminal",
            # MSF aliases
            "metasploit_search": "msf_search",
            "msfconsole": "msf_search",
            "exploit_search": "msf_search",
            "msf_module": "msf_run",
            # Knowledge aliases
            "search": "knowledge_search",
            "lookup": "knowledge_search",
            # Shodan aliases
            "shodan": "shodan_search",
            # CVE/exploit aliases
            "cve": "cve_search",
            "exploit_db": "searchsploit",
            "exploitdb": "searchsploit",
            # Intel aliases
            "osint": "intel",
            "recon": "intel",
            # Wordlist aliases
            "wordlist": "generate_wordlist",
            "password_list": "generate_wordlist",
        }
        return aliases.get(name.lower(), name)

    def _check_msf_scope(self, options: dict[str, Any]) -> list[tuple[str, str]]:
        """Check MSF module options for out-of-scope targets.

        Returns list of (target, reason) tuples for out-of-scope targets.
        """
        from sploitgpt.core.scope import check_target_scope, is_scope_defined

        if not is_scope_defined():
            return []

        out_of_scope: list[tuple[str, str]] = []

        # Options that typically contain target hosts
        target_options = ["RHOSTS", "RHOST", "TARGET", "TARGETURI"]

        for opt in target_options:
            value = options.get(opt) or options.get(opt.lower())
            if value:
                # RHOSTS can be comma-separated or space-separated
                targets = str(value).replace(",", " ").split()
                for target in targets:
                    target = target.strip()
                    if target:
                        result = check_target_scope(target)
                        if not result.in_scope:
                            out_of_scope.append((target, result.reason))

        return out_of_scope

    def _extract_command_from_args(self, name: str, args: dict[str, Any]) -> str | None:
        """Extract a command string when model emits a specific tool like 'nmap' or 'echo'."""
        # These tools were emitted with their own name instead of 'terminal'
        tool_commands = {
            "nmap": "nmap",
            "echo": "echo",
            "ls": "ls",
            "cat": "cat",
            "grep": "grep",
            "curl": "curl",
            "wget": "wget",
            "ping": "ping",
            "netcat": "nc",
            "nc": "nc",
            "sqlmap": "sqlmap",
            "gobuster": "gobuster",
            "dirb": "dirb",
            "nikto": "nikto",
            "hydra": "hydra",
            "john": "john",
            "hashcat": "hashcat",
        }

        base_cmd = tool_commands.get(name.lower())
        if not base_cmd:
            return None

        # Build command from arguments
        if "command" in args:
            return args["command"]
        elif "target" in args:
            # nmap-style: nmap <options> <target>
            opts = args.get("options", "")
            target = args.get("target", "")
            return f"{base_cmd} {opts} {target}".strip()
        elif "message" in args:
            # echo-style
            return f"{base_cmd} {args['message']}"
        elif "url" in args:
            # curl/wget style
            return f"{base_cmd} {args['url']}"
        else:
            # Try to reconstruct from args
            arg_str = " ".join(str(v) for v in args.values() if v)
            return f"{base_cmd} {arg_str}".strip() if arg_str else base_cmd

    async def _execute_tool_call(self, name: str, args: dict[str, Any]) -> str | None:
        """Execute a tool call and return the result.

        Note: Tool name normalization happens earlier in _process_llm_response()
        before the confirmation gate, so 'name' should already be normalized.
        """
        if name == "terminal":
            command = args.get("command", "")
            timeout = args.get("timeout", 300)

            # Record for training
            from sploitgpt.training.collector import SessionTurn

            self.session_collector.add_turn(
                self.session_id, SessionTurn(role="tool", content=command, tool_name="terminal")
            )

            result = await execute_tool("terminal", {"command": command, "timeout": timeout})
            return result

        elif name == "ask_user":
            # This is handled specially - return args for UI to handle
            return None

        elif name == "knowledge_search":
            query = args.get("query", "")
            top_k = args.get("top_k", 5)
            result = await execute_tool(
                "knowledge_search",
                {"query": query, "top_k": int(top_k) if str(top_k).isdigit() else 5},
            )
            return result

        elif name == "msf_search":
            query = args.get("query", "")
            module_type = args.get("module_type")
            payload: dict[str, Any] = {"query": query}
            if isinstance(module_type, str) and module_type.strip():
                payload["module_type"] = module_type.strip()
            result = await execute_tool("msf_search", payload)
            return result

        elif name == "msf_info":
            module = args.get("module", "")
            result = await execute_tool("msf_info", {"module": module})
            return result

        elif name == "msf_sessions":
            result = await execute_tool("msf_sessions", {})
            return result

        elif name in ("msf_module", "msf_run"):  # msf_module is legacy alias
            module = args.get("module", "")
            options = args.get("options", {})

            tool_args: dict[str, Any] = {"module": module, "options": options}
            if self.target:
                tool_args["target"] = self.target
            if self.lhost:
                tool_args["lhost"] = self.lhost

            result = await execute_tool("msf_run", tool_args)
            return result

        elif name == "msf_meterpreter":
            session_id = args.get("session_id")
            command = args.get("command", "")
            result = await execute_tool(
                "msf_meterpreter", {"session_id": session_id, "command": command}
            )
            return result

        elif name == "save_note":
            title = args.get("title", "note")
            content = args.get("content", "")
            from sploitgpt.core.config import get_settings

            loot_dir = get_settings().loot_dir
            loot_dir.mkdir(parents=True, exist_ok=True)
            import re
            from uuid import uuid4

            def _safe_note_title(raw: str) -> str:
                cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
                cleaned = cleaned[:64]
                if not cleaned:
                    cleaned = f"note_{uuid4().hex}"
                return cleaned

            safe_title = _safe_note_title(str(title))
            filename = loot_dir / f"{safe_title}.txt"
            loot_root = loot_dir.resolve()
            try:
                resolved = filename.resolve(strict=False)
                resolved.relative_to(loot_root)
            except Exception:
                return "Error saving note: invalid path"
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(content)
                return f"Note saved to {filename}"
            except Exception as e:
                return f"Error saving note: {e}"

        elif name == "get_privesc":
            from sploitgpt.agent.context import get_context_builder

            binaries = args.get("binaries", [])
            builder = get_context_builder()
            return builder.get_privesc_context(binaries)

        elif name == "get_shells":
            from sploitgpt.tools.payloads import format_reverse_shells_for_agent

            lhost = args.get("lhost", "")
            lport = args.get("lport", 4444)
            return format_reverse_shells_for_agent(lhost, lport)

        elif name == "shodan_search":
            query = args.get("query", "")
            limit = args.get("limit", 5)
            page = args.get("page", 1)
            facets = args.get("facets")
            minify = args.get("minify", False)
            output = args.get("output", "text")

            shodan_args: dict[str, Any] = {
                "query": query,
                "limit": int(limit) if str(limit).isdigit() else 5,
                "page": int(page) if str(page).isdigit() else 1,
                "minify": bool(minify),
                "output": output,
            }
            if facets:
                shodan_args["facets"] = facets

            result = await execute_tool("shodan_search", shodan_args)
            return result

        elif name == "tool_search":
            query = args.get("query", "")
            result = await execute_tool("tool_search", {"query": query})
            return result

        elif name == "tool_help":
            tool = args.get("tool", "")
            result = await execute_tool("tool_help", {"tool": tool})
            return result

        elif name == "nmap_scan":
            target = args.get("target", "")
            options = args.get("options", "-sV -sC")
            result = await execute_tool("nmap_scan", {"target": target, "options": options})
            return result

        elif name == "cve_search":
            query = args.get("query", "")
            limit = args.get("limit", 10)
            result = await execute_tool("cve_search", {"query": query, "limit": int(limit)})
            return result

        elif name == "searchsploit":
            query = args.get("query", "")
            result = await execute_tool("searchsploit", {"query": query})
            return result

        elif name == "intel":
            query = args.get("query", "")
            result = await execute_tool("intel", {"query": query})
            return result

        elif name == "generate_wordlist":
            base = args.get("base", "") or args.get("target_info", "") or args.get("word", "")
            extra_words = args.get("extra_words", [])
            years = args.get("years")
            min_len = args.get("min_len", 6)
            max_len = args.get("max_len", 18)
            save_as = args.get("save_as")

            wordlist_args: dict[str, Any] = {"base": base}
            if extra_words:
                wordlist_args["extra_words"] = extra_words
            if years:
                wordlist_args["years"] = years
            if min_len:
                wordlist_args["min_len"] = int(min_len)
            if max_len:
                wordlist_args["max_len"] = int(max_len)
            if save_as:
                wordlist_args["save_as"] = save_as

            result = await execute_tool("generate_wordlist", wordlist_args)
            return result

        elif name == "nuclei_scan":
            target = args.get("target", "")
            tags = args.get("tags")
            templates = args.get("templates")
            severity = args.get("severity")
            rate_limit = args.get("rate_limit", 150)
            timeout = args.get("timeout", 600)
            output_format = args.get("output_format", "text")

            nuclei_args: dict[str, Any] = {"target": target}
            if tags:
                nuclei_args["tags"] = tags
            if templates:
                nuclei_args["templates"] = templates
            if severity:
                nuclei_args["severity"] = severity
            if rate_limit:
                nuclei_args["rate_limit"] = int(rate_limit)
            if timeout:
                nuclei_args["timeout"] = int(timeout)
            if output_format:
                nuclei_args["output_format"] = output_format

            result = await execute_tool("nuclei_scan", nuclei_args)
            return result

        elif name == "nuclei_templates":
            search = args.get("search")
            tag = args.get("tag")
            limit = args.get("limit", 20)

            template_args: dict[str, Any] = {}
            if search:
                template_args["search"] = search
            if tag:
                template_args["tag"] = tag
            if limit:
                template_args["limit"] = int(limit)

            result = await execute_tool("nuclei_templates", template_args)
            return result

        elif name == "finish":
            return str(args.get("summary", "Task completed"))

        else:
            return f"Unknown tool: {name}"

    def _learn_from_output(self, command: str, output: str) -> None:
        """Parse command output and update agent knowledge."""
        output_lower = output.lower()

        # Detect phase transitions
        if any(x in command.lower() for x in ["nmap", "masscan", "rustscan"]):
            self.current_phase = "enumeration"

            # Extract services
            services = parse_service_from_nmap(output)
            for svc in services:
                if svc not in self.discovered_services:
                    self.discovered_services.append(svc)
                    get_context_builder().add_discovered_service(svc)

        elif any(x in command.lower() for x in ["gobuster", "dirbuster", "nikto", "sqlmap"]):
            self.current_phase = "vulnerability"

        elif any(x in command.lower() for x in ["exploit", "msfconsole", "searchsploit -m"]):
            self.current_phase = "exploitation"

        elif any(x in command.lower() for x in ["find / -perm", "sudo -l", "linpeas", "privesc"]):
            self.current_phase = "post"
            # Extract SUID binaries and persist them for privesc context
            if "find" in command and "perm" in command:
                binaries = parse_suid_binaries(output)
                builder = get_context_builder()
                builder.suid_binaries = binaries
                # These will be used for GTFOBins lookup

        # Record successful patterns
        if "success" in output_lower or "found" in output_lower or "vulnerable" in output_lower:
            from sploitgpt.training.collector import SessionTurn

            self.session_collector.add_turn(
                self.session_id,
                SessionTurn(role="result", content=f"Command: {command}\nOutput: {output[:500]}"),
            )

    def save_state(self) -> None:
        """
        Persist current agent state for later resume.

        Called periodically during session and on session end.
        """
        from sploitgpt.training.collector import SessionState

        builder = get_context_builder()

        state = SessionState(
            session_id=self.session_id,
            target=self.target or "",
            lhost=self.lhost or "",
            current_phase=self.current_phase,
            discovered_services=self.discovered_services.copy(),
            discovered_hosts=self.discovered_hosts.copy(),
            autonomous=self.autonomous,
            suid_binaries=list(builder.suid_binaries) if builder.suid_binaries else [],
        )

        self.session_collector.save_state(state)

    @classmethod
    def from_session(
        cls,
        session_id: str,
        context: BootContext,
    ) -> "Agent | None":
        """
        Restore an agent from a previous session.

        Args:
            session_id: ID of session to resume
            context: Current boot context

        Returns:
            Restored Agent instance, or None if session not found
        """
        from sploitgpt.training.collector import SessionCollector

        settings = get_settings()
        collector = SessionCollector(settings.sessions_dir / "sessions.db")

        # Get session data
        session_data = collector.get_session(session_id)
        if not session_data:
            return None

        # Get saved state
        state = collector.get_state(session_id)

        # Mark session as resumed (clears ended_at)
        if not collector.resume_session(session_id):
            return None

        # Create new agent
        agent = cls(context)

        # Override session ID to continue the same session
        agent.session_id = session_id

        # Restore conversation from turns
        turns = session_data.get("turns", [])
        agent.conversation = collector.turns_to_conversation(turns)

        # Restore state if available
        if state:
            agent.target = state.target or None
            agent.lhost = state.lhost or None
            agent.current_phase = state.current_phase
            agent.discovered_services = list(state.discovered_services or [])
            agent.discovered_hosts = list(state.discovered_hosts or [])
            agent.autonomous = state.autonomous

            # Restore context builder state
            builder = get_context_builder()
            builder.suid_binaries = list(state.suid_binaries or [])
            for svc in agent.discovered_services:
                builder.add_discovered_service(svc)

        return agent
