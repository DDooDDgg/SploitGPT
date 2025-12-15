"""
SploitGPT Database

SQLite database for:
- Session state
- Known hosts/findings
- Training data collection
"""

import json
import sqlite3
import logging
from pathlib import Path

from sploitgpt.core.config import get_settings

logger = logging.getLogger(__name__)


def get_db_path() -> Path:
    """Get the database path."""
    settings = get_settings()
    return settings.data_dir / "sploitgpt.db"


def get_connection() -> sqlite3.Connection:
    """Get a database connection."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the database schema."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ended_at TIMESTAMP,
            target TEXT,
            summary TEXT
        )
    """)
    
    # Hosts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            hostname TEXT,
            os TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Ports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER REFERENCES hosts(id),
            port INTEGER,
            protocol TEXT DEFAULT 'tcp',
            state TEXT,
            service TEXT,
            version TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER REFERENCES hosts(id),
            type TEXT,
            title TEXT,
            description TEXT,
            severity TEXT,
            technique_id TEXT,
            found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Commands table (for training data collection)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER REFERENCES sessions(id),
            user_input TEXT,
            agent_response TEXT,
            command_executed TEXT,
            command_output TEXT,
            success INTEGER,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Techniques table (MITRE ATT&CK cache)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS techniques (
            id TEXT PRIMARY KEY,
            name TEXT,
            tactic TEXT,
            description TEXT,
            detection TEXT,
            platforms TEXT
        )
    """)

    # Backward-compatible schema migration:
    # Older versions used a different column name (e.g., tactic_id). Add the
    # expected 'tactic' column if it's missing so newer code can function.
    try:
        cursor.execute("PRAGMA table_info(techniques)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "tactic" not in existing_cols:
            cursor.execute("ALTER TABLE techniques ADD COLUMN tactic TEXT")
    except Exception:
        # Best-effort migration; don't block startup if this fails.
        logger.warning("Schema migration failed for techniques table", exc_info=True)
    
    conn.commit()
    conn.close()


def add_host(ip: str, hostname: str | None = None, os: str | None = None) -> int:
    """Add or update a host."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO hosts (ip, hostname, os)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hostname),
            os = COALESCE(excluded.os, os),
            last_seen = CURRENT_TIMESTAMP
        RETURNING id
    """, (ip, hostname, os))
    
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError("Failed to insert/update host")
    host_id = int(row[0])
    conn.commit()
    conn.close()
    
    return host_id


def add_port(
    host_ip: str,
    port: int,
    protocol: str = "tcp",
    state: str = "open",
    service: str | None = None,
    version: str | None = None,
) -> None:
    """Add a port to a host."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get or create host
    cursor.execute("SELECT id FROM hosts WHERE ip = ?", (host_ip,))
    row = cursor.fetchone()
    if row:
        host_id = row[0]
    else:
        host_id = add_host(host_ip)
    
    cursor.execute("""
        INSERT OR REPLACE INTO ports (host_id, port, protocol, state, service, version)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (host_id, port, protocol, state, service, version))
    
    conn.commit()
    conn.close()


def log_command(session_id: int, user_input: str, agent_response: str,
                command: str, output: str, success: bool) -> None:
    """Log a command execution for training data."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO commands (session_id, user_input, agent_response, 
                             command_executed, command_output, success)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, user_input, agent_response, command, output, int(success)))
    
    conn.commit()
    conn.close()


def export_training_data(output_path: Path) -> int:
    """Export successful commands as training data."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT user_input, agent_response, command_executed, command_output
        FROM commands
        WHERE success = 1
        ORDER BY executed_at
    """)
    
    count = 0
    with open(output_path, "w") as f:
        for row in cursor.fetchall():
            # Format as instruction-response pair
            data = {
                "instruction": row[0],
                "output": f"{row[1]}\n\n```bash\n{row[2]}\n```\n\nOutput:\n```\n{row[3]}\n```"
            }
            f.write(json.dumps(data) + "\n")
            count += 1
    
    conn.close()
    return count
