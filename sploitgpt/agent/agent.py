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

import json
import re
import uuid
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any, cast

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
from sploitgpt.knowledge.rag import get_retrieved_context
from sploitgpt.tools import execute_tool
from sploitgpt.tools.commands import get_all_commands_formatted
from sploitgpt.training.collector import SessionCollector

SYSTEM_PROMPT = """You are SploitGPT, an AI assistant for authorized red-team penetration testing.

## Your Environment
You are running inside a Kali Linux container with access to common security tools.

## Operating Modes
- **Conversational by default**: explain, ask clarifying questions, and propose next steps.
- **Execution only when requested**: only run commands when the user explicitly asks you to execute.

## When Execution Is Requested
1. Present **2-4 options** (different tools/approaches). Recommend the best one.
2. Ask the user to choose using the `ask_user` tool.
3. Execute **one step at a time** using tools (primarily `terminal`, sometimes Metasploit tools).
4. Save important output to `/app/loot/` using `tee` or tool flags.
5. Do not repeat scans unnecessarily.

## Tool Use Rules
- Prefer **one tool call per step** (one command at a time).
- Wait for results before choosing the next step.
- Do not guess flags/options. If unsure, use `knowledge_search` or run `<tool> --help` via `terminal`.
- For Metasploit: prefer `msf_search` -> `msf_info` -> `msf_module` (avoid guessing required options).
- Use `finish` when the task is complete with a concise summary and (if applicable) MITRE technique IDs.
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
        self._pending: PendingInteraction | None = None
        
        # Start session
        self.session_id = str(uuid.uuid4())[:8]
        self.session_collector.start_session(self.session_id)
    
    async def process(self, user_input: str) -> AsyncGenerator[AgentResponse, None]:
        """Process user input and yield responses."""

        # If we're waiting on a choice/confirmation, treat input as the answer.
        if self._pending is not None:
            async for r in self.submit_choice(user_input):
                yield r
            return
        
        # Extract target from common patterns
        self._extract_target_info(user_input)
        
        # Add user message to conversation
        self.conversation.append({
            "role": "user",
            "content": user_input
        })
        
        # Build messages for LLM
        messages = [
            {"role": "system", "content": self._build_system_prompt()},
            *self.conversation
        ]
        
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
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
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
    
    def _build_system_prompt(self) -> str:
        """Build the system prompt with current context."""
        # Get command reference
        command_ref = get_all_commands_formatted()
        
        # Current context
        context_info = f"""
## Current Session
- Target: {self.target or 'Not set - ask user for target'}
- Known hosts: {', '.join(self.discovered_hosts) if self.discovered_hosts else 'None yet'}
- Services found: {', '.join(self.discovered_services) if self.discovered_services else 'None yet'}
- Phase: {self.current_phase.upper()}
- Metasploit: {'Available' if self.context.msf_connected else 'Not connected'}

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
                    response = await client.chat(
                        messages,
                        stream=False,
                        tools=tools,
                    )
                return cast(dict[str, Any], response)
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
        tool_models = ["llama3.1", "llama3.2", "mistral", "mixtral", "qwen2.5"]
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
        code_block_pattern = r'```(?:bash|shell|sh)?\s*\n(.*?)```'
        matches = re.findall(code_block_pattern, text, re.DOTALL | re.IGNORECASE)
        
        for match in matches:
            # Each line in the code block could be a command
            for line in match.strip().split('\n'):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#') and not line.startswith('#!'):
                    continue
                # Remove leading $ or # prompt
                if line.startswith('$ ') or line.startswith('# '):
                    line = line[2:]
                if line:
                    tool_calls.append({
                        "function": {
                            "name": "terminal",
                            "arguments": {"command": line}
                        }
                    })
        
        # If no code blocks, look for inline commands with $ prefix
        if not tool_calls:
            for line in text.split('\n'):
                line = line.strip()
                if line.startswith('$ '):
                    cmd = line[2:].strip()
                    if cmd:
                        tool_calls.append({
                            "function": {
                                "name": "terminal",
                                "arguments": {"command": cmd}
                            }
                        })
        
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
                                "description": "The shell command to execute (no shell features; will be split safely)"
                            },
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Preferred: argv-style list to execute without a shell"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds (default 300)",
                                "default": 300
                            }
                        },
                        "required": []
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ask_user",
                    "description": "Ask the user to choose between multiple options. Use when you find multiple attack paths or need clarification.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "question": {
                                "type": "string",
                                "description": "The question to ask"
                            },
                            "options": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of options for the user to choose from"
                            }
                        },
                        "required": ["question", "options"]
                    }
                }
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
                                "description": "Search query (e.g., 'smb enumeration', 'hydra ssh', 'T1046 network service discovery')"
                            },
                            "top_k": {
                                "type": "integer",
                                "description": "Maximum number of snippets to return",
                                "default": 5
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "cloud_gpu_status",
                    "description": "Check connectivity to a cloud GPU host (read-only). Returns 'OK: reachable' or an error message.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ssh_host": {"type": "string", "description": "IP or hostname of the GPU host"},
                            "ssh_user": {"type": "string", "description": "SSH username to use", "default": "root"},
                            "ssh_port": {"type": "integer", "description": "SSH port", "default": 22}
                        },
                        "required": ["ssh_host"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "cloud_gpu_sync",
                    "description": "Sync local wordlists to a cloud GPU host. Requires explicit consent before proceeding.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "ssh_host": {"type": "string"},
                            "ssh_user": {"type": "string", "default": "root"},
                            "ssh_port": {"type": "integer", "default": 22},
                            "local_dir": {"type": "string", "description": "Local wordlists directory (optional)"},
                            "dry_run": {"type": "boolean", "description": "If true, do not perform operations"},
                            "consent": {"type": "boolean", "description": "Explicit user consent to proceed (required)"}
                        },
                        "required": ["ssh_host", "consent"]
                    }
                }
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
                                "description": "Shodan query (e.g., 'apache country:US port:80')"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results to return (default 5, max 20)",
                                "default": 5
                            }
                        },
                        "required": ["query"]
                    }
                }
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
                                "description": "Search query (e.g., 'apache', 'CVE-2021-44228', 'eternalblue', 'portscan')"
                            },
                            "module_type": {
                                "type": "string",
                                "description": "Optional filter: exploit, auxiliary, post, payload"
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_info",
                    "description": "Inspect a Metasploit module (info + required options). Use this before msf_module to avoid guessing option names.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module": {
                                "type": "string",
                                "description": "Module path (e.g., 'auxiliary/scanner/portscan/tcp')"
                            }
                        },
                        "required": ["module"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_sessions",
                    "description": "List active Metasploit sessions (read-only)",
                    "parameters": {
                        "type": "object",
                        "properties": {}
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_module",
                    "description": "Run a Metasploit module with options (prefer msf_info first)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "module": {
                                "type": "string",
                                "description": "Module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')"
                            },
                            "options": {
                                "type": "object",
                                "description": "Module options (e.g., {'RHOSTS': '10.0.0.1', 'LHOST': '10.0.0.2'})"
                            }
                        },
                        "required": ["module", "options"]
                    }
                }
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
                                "description": "Note title (becomes filename)"
                            },
                            "content": {
                                "type": "string",
                                "description": "Note content"
                            }
                        },
                        "required": ["title", "content"]
                    }
                }
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
                                "description": "List of binary names found with SUID or sudo permissions"
                            }
                        },
                        "required": ["binaries"]
                    }
                }
            },
            {
                "type": "function", 
                "function": {
                    "name": "get_shells",
                    "description": "Get reverse shell payloads for various languages",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "lhost": {
                                "type": "string",
                                "description": "Attacker IP address"
                            },
                            "lport": {
                                "type": "integer",
                                "description": "Attacker port (default 4444)"
                            }
                        },
                        "required": ["lhost"]
                    }
                }
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
                                "description": "Summary of what was accomplished including findings"
                            },
                            "techniques_used": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "MITRE ATT&CK technique IDs used (e.g., ['T1046', 'T1110'])"
                            }
                        },
                        "required": ["summary"]
                    }
                }
            }
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

        # If no tool calls but we have content, try to parse commands from text
        if not tool_calls and content and not self._supports_tools():
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

        # Confirmation gate: pause before any execution tool runs
        if name in ("terminal", "msf_module") and not self.autonomous:
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

        # Execute tool call immediately
        result = await self._execute_tool_call(name, args)

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
            self.conversation.append(
                {"role": "tool", "content": str(result), "name": name}
            )

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

    async def submit_choice(
        self, user_input: str
    ) -> AsyncGenerator[AgentResponse, None]:
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
            self.conversation.append(
                {"role": "tool", "content": chosen, "name": "ask_user"}
            )

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

                    self.conversation.append(
                        {"role": "tool", "content": str(result), "name": name}
                    )

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
    
    async def _execute_tool_call(self, name: str, args: dict[str, Any]) -> str | None:
        """Execute a tool call and return the result."""
        
        if name == "terminal":
            command = args.get("command", "")
            timeout = args.get("timeout", 300)
            
            # Record for training
            from sploitgpt.training.collector import SessionTurn
            self.session_collector.add_turn(
                self.session_id,
                SessionTurn(role="tool", content=command, tool_name="terminal")
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
                "knowledge_search", {"query": query, "top_k": int(top_k) if str(top_k).isdigit() else 5}
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
            
        elif name == "msf_module":
            module = args.get("module", "")
            options = args.get("options", {})

            tool_args: dict[str, Any] = {"module": module, "options": options}
            if self.target:
                tool_args["target"] = self.target
            if self.lhost:
                tool_args["lhost"] = self.lhost

            result = await execute_tool("msf_run", tool_args)
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
                SessionTurn(role="result", content=f"Command: {command}\nOutput: {output[:500]}")
            )
