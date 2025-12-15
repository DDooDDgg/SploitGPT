"""
Session Data Collector

Captures user sessions for continuous learning.
This is the "self-improving" aspect - the model learns from real usage.
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast


@dataclass
class SessionTurn:
    """A single turn in a session conversation."""

    role: str  # user, assistant, tool
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    tool_name: str | None = None
    timestamp: str | None = None


@dataclass  
class SessionFeedback:
    """User feedback on a session."""
    session_id: str
    rating: int  # 1-5
    successful: bool  # Did the task succeed?
    notes: str | None = None


class SessionCollector:
    """
    Collects session data for training.
    
    Sessions are stored locally and can be exported to training format.
    Only successful sessions with positive feedback are used for training.
    """
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the sessions database."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    task_description TEXT,
                    successful INTEGER DEFAULT 0,
                    rating INTEGER DEFAULT 0,
                    exported INTEGER DEFAULT 0
                );
                
                CREATE TABLE IF NOT EXISTS turns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    turn_index INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    tool_calls TEXT,
                    tool_name TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_turns_session 
                ON turns(session_id, turn_index);
            """)
    
    def start_session(self, session_id: str, task_description: str = "") -> str:
        """Start a new session."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (id, started_at, task_description) VALUES (?, ?, ?)",
                (session_id, datetime.now().isoformat(), task_description)
            )
        return session_id
    
    def add_turn(self, session_id: str, turn: SessionTurn) -> None:
        """Add a turn to a session."""
        with sqlite3.connect(self.db_path) as conn:
            # Get next turn index
            result = conn.execute(
                "SELECT COALESCE(MAX(turn_index), -1) + 1 FROM turns WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            assert result is not None
            turn_index = int(result[0])
            
            conn.execute(
                """INSERT INTO turns 
                   (session_id, turn_index, role, content, tool_calls, tool_name, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    turn_index,
                    turn.role,
                    turn.content,
                    json.dumps(turn.tool_calls) if turn.tool_calls else None,
                    turn.tool_name,
                    turn.timestamp or datetime.now().isoformat(),
                )
            )
    
    def end_session(
        self,
        session_id: str,
        successful: bool = False,
        rating: int = 0,
    ) -> None:
        """End a session with feedback."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE sessions 
                   SET ended_at = ?, successful = ?, rating = ?
                   WHERE id = ?""",
                (datetime.now().isoformat(), int(successful), rating, session_id)
            )
    
    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get a session with all its turns."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            session = conn.execute(
                "SELECT * FROM sessions WHERE id = ?",
                (session_id,)
            ).fetchone()
            
            if not session:
                return None
            
            turns = conn.execute(
                "SELECT * FROM turns WHERE session_id = ? ORDER BY turn_index",
                (session_id,)
            ).fetchall()
            
            return {
                "session": dict(session),
                "turns": [dict(t) for t in turns],
            }
    
    def export_for_training(
        self,
        output_path: Path,
        min_rating: int = 4,
        successful_only: bool = True,
    ) -> int:
        """
        Export successful sessions to training format.
        
        Args:
            output_path: Where to write the JSONL file
            min_rating: Minimum rating to include (1-5)
            successful_only: Only include sessions marked successful
            
        Returns:
            Number of examples exported
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Find qualifying sessions
            query = """
                SELECT id FROM sessions 
                WHERE exported = 0 
                AND rating >= ?
            """
            params = [min_rating]
            
            if successful_only:
                query += " AND successful = 1"
            
            sessions = conn.execute(query, params).fetchall()
            
            count = 0
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, "a") as f:
                for session_row in sessions:
                    session_id = str(session_row["id"])
                    session_data = self.get_session(session_id)

                    if not session_data or not session_data["turns"]:
                        continue

                    turns = cast(list[dict[str, Any]], session_data["turns"])

                    # Convert to training format
                    messages = self._turns_to_messages(turns)
                    
                    if len(messages) < 2:  # Need at least user + assistant
                        continue
                    
                    session_info = cast(dict[str, Any], session_data["session"])

                    example = {
                        "messages": messages,
                        "metadata": {
                            "session_id": session_id,
                            "task": session_info.get("task_description", ""),
                            "rating": session_info.get("rating", 0),
                        },
                    }
                    
                    f.write(json.dumps(example) + "\n")
                    count += 1
                    
                    # Mark as exported
                    conn.execute(
                        "UPDATE sessions SET exported = 1 WHERE id = ?",
                        (session_id,)
                    )
            
            return count
    
    def _turns_to_messages(self, turns: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Convert database turns to message format."""
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": self._get_system_prompt(),
            }
        ]
        
        for turn in turns:
            role = turn["role"]
            content = turn["content"]
            
            if role == "user":
                messages.append({"role": "user", "content": content})
            
            elif role == "assistant":
                msg: dict[str, Any] = {"role": "assistant", "content": content}
                
                # Add tool calls if present
                if turn["tool_calls"]:
                    tool_calls = json.loads(turn["tool_calls"])
                    msg["tool_calls"] = tool_calls
                    if not content:
                        msg["content"] = None
                
                messages.append(msg)
            
            elif role == "tool":
                messages.append({
                    "role": "tool",
                    "name": turn.get("tool_name", "unknown"),
                    "content": content,
                })
        
        return messages
    
    def _get_system_prompt(self) -> str:
        """Get the system prompt for training examples."""
        return """You are SploitGPT, an autonomous penetration testing assistant running inside a Kali Linux container. You help security professionals conduct authorized penetration tests.

You have access to these tools:
- terminal: Execute shell commands in the Kali container
- ask_user: Ask for clarification or approval before risky actions
- msf_search: Search Metasploit for exploits and modules
- msf_run: Execute Metasploit modules
- finish: Mark task as complete with findings

Always ask before running exploits or intrusive actions. Gather information first, then suggest attack paths."""
    
    def get_stats(self) -> dict[str, int]:
        """Get collection statistics."""
        with sqlite3.connect(self.db_path) as conn:
            stats: dict[str, int] = {}
            
            stats["total_sessions"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM sessions"
                ).fetchone()[0]
            )
            
            stats["successful_sessions"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE successful = 1"
                ).fetchone()[0]
            )
            
            stats["high_rated_sessions"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE rating >= 4"
                ).fetchone()[0]
            )
            
            stats["exported_sessions"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM sessions WHERE exported = 1"
                ).fetchone()[0]
            )
            
            stats["total_turns"] = int(
                conn.execute(
                    "SELECT COUNT(*) FROM turns"
                ).fetchone()[0]
            )
            
            return stats
