"""
SploitGPT Database

SQLite database for:
- Session state
- Known hosts/findings
- Training data collection
"""

import json
import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
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
    # Enable foreign key enforcement (critical for data integrity)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for database operations with automatic cleanup.

    Example:
        with get_db() as conn:
            conn.execute("INSERT INTO ...")
    """
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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

    # Kali tool catalog (discovery) + docs cache (how to use a tool).
    # Populated at build-time when available, and lazily extended at runtime.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS kali_tools (
            tool TEXT PRIMARY KEY,
            package TEXT,
            summary TEXT,
            categories TEXT,
            exec TEXT,
            path TEXT,
            aliases TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS kali_tool_docs (
            tool TEXT NOT NULL,
            kind TEXT NOT NULL,
            chunk_index INTEGER NOT NULL DEFAULT 0,
            content TEXT NOT NULL,
            source TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (tool, kind, chunk_index)
        )
        """
    )
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kali_tools_pkg ON kali_tools(package)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_kali_tool_docs_kind ON kali_tool_docs(kind)")

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
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO hosts (ip, hostname, os)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    hostname = COALESCE(excluded.hostname, hostname),
                    os = COALESCE(excluded.os, os),
                    last_seen = CURRENT_TIMESTAMP
                RETURNING id
            """,
                (ip, hostname, os),
            )

            row = cursor.fetchone()
            if row is None:
                raise RuntimeError("Failed to insert/update host")
            host_id = int(row[0])

            logger.debug(f"Added/updated host: {ip} (id={host_id})")
            return host_id
    except Exception as e:
        logger.error(f"Failed to add host {ip}: {e}", exc_info=True)
        raise


def add_port(
    host_ip: str,
    port: int,
    protocol: str = "tcp",
    state: str = "open",
    service: str | None = None,
    version: str | None = None,
) -> None:
    """Add a port to a host."""
    try:
        # Ensure host exists first
        host_id = add_host(host_ip)

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO ports (host_id, port, protocol, state, service, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (host_id, port, protocol, state, service, version),
            )

            logger.debug(f"Added port {port}/{protocol} to {host_ip} (service={service})")
    except Exception as e:
        logger.error(f"Failed to add port {port} to {host_ip}: {e}", exc_info=True)
        raise


def log_command(
    session_id: int, user_input: str, agent_response: str, command: str, output: str, success: bool
) -> None:
    """Log a command execution for training data."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO commands (session_id, user_input, agent_response,
                                     command_executed, command_output, success)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (session_id, user_input, agent_response, command, output, int(success)),
            )

            logger.debug(f"Logged command for session {session_id} (success={success})")
    except Exception as e:
        logger.error(f"Failed to log command for session {session_id}: {e}", exc_info=True)
        raise


def export_training_data(output_path: Path) -> int:
    """Export successful commands as training data."""
    try:
        with get_db() as conn:
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
                        "output": f"{row[1]}\n\n```bash\n{row[2]}\n```\n\nOutput:\n```\n{row[3]}\n```",
                    }
                    f.write(json.dumps(data) + "\n")
                    count += 1

            logger.info(f"Exported {count} training examples to {output_path}")
            return count
    except Exception as e:
        logger.error(f"Failed to export training data to {output_path}: {e}", exc_info=True)
        raise


# =========================================================================
# Read API Functions
# =========================================================================


def get_host(ip: str) -> dict | None:
    """Get host details by IP address.

    Args:
        ip: IP address to look up

    Returns:
        Dictionary with host details or None if not found
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, ip, hostname, os, first_seen, last_seen
                FROM hosts
                WHERE ip = ?
            """,
                (ip,),
            )

            row = cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "ip": row[1],
                    "hostname": row[2],
                    "os": row[3],
                    "first_seen": row[4],
                    "last_seen": row[5],
                }
            return None
    except Exception as e:
        logger.error(f"Failed to get host {ip}: {e}", exc_info=True)
        raise


def list_hosts() -> list[dict]:
    """List all discovered hosts.

    Returns:
        List of dictionaries with host details
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, ip, hostname, os, first_seen, last_seen
                FROM hosts
                ORDER BY last_seen DESC
            """)

            hosts = []
            for row in cursor.fetchall():
                hosts.append(
                    {
                        "id": row[0],
                        "ip": row[1],
                        "hostname": row[2],
                        "os": row[3],
                        "first_seen": row[4],
                        "last_seen": row[5],
                    }
                )
            return hosts
    except Exception as e:
        logger.error(f"Failed to list hosts: {e}", exc_info=True)
        raise


def get_ports(host_ip: str) -> list[dict]:
    """Get all ports for a specific host.

    Args:
        host_ip: IP address of the host

    Returns:
        List of dictionaries with port details
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT p.id, p.port, p.protocol, p.state, p.service, p.version, p.discovered_at
                FROM ports p
                JOIN hosts h ON p.host_id = h.id
                WHERE h.ip = ?
                ORDER BY p.port
            """,
                (host_ip,),
            )

            ports = []
            for row in cursor.fetchall():
                ports.append(
                    {
                        "id": row[0],
                        "port": row[1],
                        "protocol": row[2],
                        "state": row[3],
                        "service": row[4],
                        "version": row[5],
                        "discovered_at": row[6],
                    }
                )
            return ports
    except Exception as e:
        logger.error(f"Failed to get ports for {host_ip}: {e}", exc_info=True)
        raise


def list_findings(host_ip: str | None = None) -> list[dict]:
    """List findings, optionally filtered by host.

    Args:
        host_ip: Optional IP address to filter findings

    Returns:
        List of dictionaries with finding details
    """
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            if host_ip:
                cursor.execute(
                    """
                    SELECT f.id, h.ip, f.type, f.title, f.description, f.severity,
                           f.technique_id, f.found_at
                    FROM findings f
                    JOIN hosts h ON f.host_id = h.id
                    WHERE h.ip = ?
                    ORDER BY f.found_at DESC
                """,
                    (host_ip,),
                )
            else:
                cursor.execute("""
                    SELECT f.id, h.ip, f.type, f.title, f.description, f.severity,
                           f.technique_id, f.found_at
                    FROM findings f
                    JOIN hosts h ON f.host_id = h.id
                    ORDER BY f.found_at DESC
                """)

            findings = []
            for row in cursor.fetchall():
                findings.append(
                    {
                        "id": row[0],
                        "host_ip": row[1],
                        "type": row[2],
                        "title": row[3],
                        "description": row[4],
                        "severity": row[5],
                        "technique_id": row[6],
                        "found_at": row[7],
                    }
                )
            return findings
    except Exception as e:
        logger.error(f"Failed to list findings: {e}", exc_info=True)
        raise
