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
from typing import AsyncGenerator, Optional

import httpx

from sploitgpt.agent.response import AgentResponse
from sploitgpt.agent.context import (
    build_dynamic_context,
    parse_service_from_nmap,
    parse_suid_binaries,
    get_context_builder,
)
from sploitgpt.core.boot import BootContext
from sploitgpt.core.config import get_settings
from sploitgpt.tools import TOOLS, execute_tool
from sploitgpt.training.collector import SessionCollector


SYSTEM_PROMPT = """You are SploitGPT, an autonomous penetration testing AI agent with self-improving capabilities.

## Your Environment
You are running inside a Kali Linux container with full access to security tools.
You have Metasploit, nmap, sqlmap, gobuster, hydra, nikto, dirbuster, and 600+ other tools available.

## Core Capabilities
1. **Reconnaissance**: Host/port discovery, service enumeration
2. **Vulnerability Assessment**: Automated vuln scanning, CVE correlation
3. **Exploitation**: Metasploit integration, custom exploit execution
4. **Post-Exploitation**: Privilege escalation, persistence, lateral movement
5. **Reporting**: Structured output with MITRE ATT&CK technique mapping

## Rules
1. EXECUTE commands - don't just describe what you would do
2. When multiple attack paths exist, ASK the user which to pursue
3. Save all output to /app/loot/ directory with descriptive names
4. Parse command output intelligently and continue based on findings
5. Reference MITRE ATT&CK technique IDs (e.g., T1046) when explaining approach
6. Always explain your reasoning BEFORE executing commands
7. Chain multiple tools together when appropriate
8. If a command fails, analyze the error and try alternatives

## Available Tools
You have these tools available via function calling:

- **terminal(command)**: Run any shell command in Kali Linux
- **ask_user(question, options)**: Ask user to choose between options
- **msf_search(query)**: Search Metasploit/SearchSploit for exploits
- **msf_module(module, options)**: Configure and run a Metasploit module
- **save_note(title, content)**: Save a note to the loot directory
- **get_context(services, phase)**: Get relevant attack techniques and commands
- **finish(summary)**: Complete the task with a summary

## Methodology (PTES-based)
1. **RECON**: Host discovery → Port scanning → Service enumeration
2. **ENUMERATE**: Banner grabbing → Version detection → Default creds check
3. **ANALYZE**: Vulnerability scanning → CVE lookup → Exploit research
4. **EXPLOIT**: Attempt exploitation → Gain initial access
5. **POST-EXPLOIT**: Privilege escalation → Credential harvesting → Lateral movement
6. **REPORT**: Document findings with ATT&CK mappings

## Command Patterns
- Use `tee` to save output: `nmap ... | tee /app/loot/scan.txt`
- Use proper output formats: `-oA` for nmap, `--output` for others
- Check tool help: `<tool> --help` or `<tool> -h`

## Important
- Always start with reconnaissance before exploitation
- Document everything in /app/loot/
- Never make assumptions about scope - ask if unclear
- Be methodical and thorough
"""


class Agent:
    """The SploitGPT AI Agent."""
    
    def __init__(self, context: BootContext):
        self.context = context
        self.settings = get_settings()
        self.conversation: list[dict] = []
        self.http_client = httpx.AsyncClient(timeout=120)
        
        # Session tracking
        self.session_collector = SessionCollector()
        self.current_phase = "recon"
        self.discovered_services: list[str] = []
        self.discovered_hosts: list[str] = []
        self.target: Optional[str] = None
        self.lhost: Optional[str] = None
        
        # Start session
        self.session_id = self.session_collector.start_session()
    
    async def process(self, user_input: str) -> AsyncGenerator[AgentResponse, None]:
        """Process user input and yield responses."""
        
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
        # Static context about current state
        context_info = f"""
## Current Context
- Hostname: {self.context.hostname}
- User: {self.context.username}
- Target: {self.target or 'Not set'}
- Known hosts: {', '.join(self.discovered_hosts) if self.discovered_hosts else 'None discovered yet'}
- Services found: {', '.join(self.discovered_services) if self.discovered_services else 'None discovered yet'}
- Current phase: {self.current_phase.upper()}
- Available tools: {len(self.context.available_tools)} tools ready
- Metasploit: {'Connected' if self.context.msf_connected else 'Not available'}
- Session ID: {self.session_id}
"""
        
        # Dynamic context based on discovered services and phase
        dynamic_context = build_dynamic_context(
            target=self.target,
            services=self.discovered_services,
            phase=self.current_phase,
            lhost=self.lhost,
        )
        
        if dynamic_context:
            context_info += f"\n{dynamic_context}"
        
        return SYSTEM_PROMPT + context_info
    
    async def _call_llm(self, messages: list[dict]) -> dict:
        """Call the Ollama LLM."""
        url = f"{self.settings.ollama_host}/api/chat"
        
        payload = {
            "model": self.settings.model,
            "messages": messages,
            "stream": False,
            "tools": self._get_tool_definitions()
        }
        
        response = await self.http_client.post(url, json=payload)
        response.raise_for_status()
        
        return response.json()
    
    def _get_tool_definitions(self) -> list[dict]:
        """Get tool definitions for function calling."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "terminal",
                    "description": "Run a shell command in the Kali Linux environment. Use this for all command execution.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute"
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds (default 300)",
                                "default": 300
                            }
                        },
                        "required": ["command"]
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
                    "name": "msf_search",
                    "description": "Search Metasploit/SearchSploit for exploit modules matching a query",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (e.g., 'apache', 'CVE-2021-44228', 'eternalblue')"
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "msf_module",
                    "description": "Run a Metasploit module with options",
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
    
    async def _process_llm_response(self, response: dict) -> AsyncGenerator[AgentResponse, None]:
        """Process the LLM response and execute any tool calls."""
        
        message = response.get("message", {})
        content = message.get("content", "")
        tool_calls = message.get("tool_calls", [])
        
        # Add assistant message to conversation
        self.conversation.append({
            "role": "assistant",
            "content": content,
            "tool_calls": tool_calls if tool_calls else None
        })
        
        # Yield any text content
        if content:
            yield AgentResponse(type="message", content=content)
        
        # Execute tool calls
        for tool_call in tool_calls:
            function = tool_call.get("function", {})
            name = function.get("name", "")
            args = function.get("arguments", {})
            
            # Parse args if string
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            
            result = await self._execute_tool_call(name, args)
            
            if result is not None:
                # Yield command if terminal
                if name == "terminal":
                    yield AgentResponse(type="command", content=args.get("command", ""))
                    yield AgentResponse(type="result", content=result)
                    
                    # Parse output for learning
                    self._learn_from_output(args.get("command", ""), result)
                    
                elif name == "ask_user":
                    yield AgentResponse(
                        type="choice",
                        question=args.get("question", ""),
                        options=args.get("options", [])
                    )
                    # Note: Caller needs to handle user input and call back
                    
                elif name == "finish":
                    summary = args.get("summary", "")
                    techniques = args.get("techniques_used", [])
                    
                    # Save session
                    self.session_collector.complete_session(
                        outcome="success",
                        summary=summary
                    )
                    
                    yield AgentResponse(
                        type="done",
                        content=summary,
                        data={"techniques": techniques}
                    )
                    return
                    
                elif name == "get_privesc":
                    yield AgentResponse(type="info", content=result)
                    
                elif name == "get_shells":
                    yield AgentResponse(type="info", content=result)
                    
                else:
                    yield AgentResponse(type="result", content=result)
                
                # Add tool result to conversation
                self.conversation.append({
                    "role": "tool",
                    "content": str(result),
                    "name": name
                })
        
        # If there were tool calls, continue the conversation
        if tool_calls:
            messages = [
                {"role": "system", "content": self._build_system_prompt()},
                *self.conversation
            ]
            
            try:
                next_response = await self._call_llm(messages)
                async for agent_response in self._process_llm_response(next_response):
                    yield agent_response
            except Exception as e:
                yield AgentResponse(type="error", content=str(e))
    
    async def _execute_tool_call(self, name: str, args: dict) -> Optional[str]:
        """Execute a tool call and return the result."""
        
        if name == "terminal":
            command = args.get("command", "")
            timeout = args.get("timeout", 300)
            
            # Record for training
            self.session_collector.record_interaction(
                prompt=f"Execute: {command}",
                response="",
                tool_calls=[{"name": "terminal", "args": {"command": command}}]
            )
            
            result = await execute_tool("terminal", {"command": command, "timeout": timeout})
            return result
            
        elif name == "ask_user":
            # This is handled specially - return args for UI to handle
            return None
            
        elif name == "msf_search":
            query = args.get("query", "")
            result = await execute_tool("msf_search", {"query": query})
            return result
            
        elif name == "msf_module":
            module = args.get("module", "")
            options = args.get("options", {})
            result = await execute_tool("msf_run", {"module": module, "options": options})
            return result
            
        elif name == "save_note":
            title = args.get("title", "note")
            content = args.get("content", "")
            filename = f"/app/loot/{title.replace(' ', '_')}.txt"
            try:
                with open(filename, "w") as f:
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
            return args.get("summary", "Task completed")
            
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
            
            # Extract SUID binaries
            if "find" in command and "perm" in command:
                binaries = parse_suid_binaries(output)
                # These will be used for GTFOBins lookup
        
        # Record successful patterns
        if "success" in output_lower or "found" in output_lower or "vulnerable" in output_lower:
            self.session_collector.record_interaction(
                prompt=command,
                response=output[:500],  # Truncate for storage
                success=True
            )
