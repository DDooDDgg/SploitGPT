"""
Wordlist Management

Helpers for working with wordlists in Kali Linux.
"""

from pathlib import Path

# Common wordlist locations in Kali
WORDLIST_PATHS = {
    # Directory brute forcing
    "dirb_common": "/usr/share/wordlists/dirb/common.txt",
    "dirb_big": "/usr/share/wordlists/dirb/big.txt",
    "dirbuster_small": "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    
    # Web content discovery
    "raft_files": "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
    "raft_dirs": "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "common_api": "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    
    # Passwords
    "rockyou": "/usr/share/wordlists/rockyou.txt",
    "top1000": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "top10000": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    
    # Usernames
    "top_usernames": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    "names": "/usr/share/seclists/Usernames/Names/names.txt",
    
    # DNS
    "subdomains_top1m": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    
    # SQL injection
    "sqli_generic": "/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt",
    
    # XSS
    "xss_polyglots": "/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt",
    
    # LFI
    "lfi_linux": "/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",
}


# Wordlist recommendations by task
TASK_WORDLISTS = {
    "dir_discovery": ["dirb_common", "dirbuster_medium"],
    "dir_discovery_quick": ["dirb_common"],
    "dir_discovery_thorough": ["dirbuster_medium", "raft_dirs", "raft_files"],
    
    "password_spray": ["top1000"],
    "password_brute": ["rockyou"],
    "password_quick": ["top1000"],
    
    "username_enum": ["top_usernames", "names"],
    
    "subdomain_enum": ["subdomains_top1m"],
    
    "sqli_fuzz": ["sqli_generic"],
    "xss_fuzz": ["xss_polyglots"],
    "lfi_fuzz": ["lfi_linux"],
}


def get_wordlist(name: str) -> Path | None:
    """Get path to a wordlist by name."""
    if name in WORDLIST_PATHS:
        path = Path(WORDLIST_PATHS[name])
        if path.exists():
            return path
    
    # Check if it's already a path
    path = Path(name)
    if path.exists():
        return path
    
    return None


def get_wordlists_for_task(task: str) -> list[Path]:
    """Get recommended wordlists for a task."""
    names = TASK_WORDLISTS.get(task, [])
    wordlists = []
    
    for name in names:
        path = get_wordlist(name)
        if path:
            wordlists.append(path)
    
    return wordlists


def suggest_wordlist(context: str) -> tuple[str, Path | None]:
    """
    Suggest a wordlist based on context.
    
    Args:
        context: Description of what you're doing (e.g., "brute force ssh")
        
    Returns:
        Tuple of (reason, wordlist_path)
    """
    context_lower = context.lower()
    
    # Directory discovery
    if any(w in context_lower for w in ["dir", "gobuster", "ferox", "discovery", "enum"]):
        if "quick" in context_lower or "fast" in context_lower:
            return "Quick directory discovery", get_wordlist("dirb_common")
        else:
            return "Standard directory discovery", get_wordlist("dirbuster_medium")
    
    # Password attacks
    if any(w in context_lower for w in ["password", "brute", "crack", "hydra", "spray"]):
        if "quick" in context_lower or "spray" in context_lower:
            return "Quick password spray (top 1000)", get_wordlist("top1000")
        else:
            return "Full password brute force", get_wordlist("rockyou")
    
    # Username enumeration
    if any(w in context_lower for w in ["user", "username", "enum"]):
        return "Common usernames", get_wordlist("top_usernames")
    
    # Subdomain
    if any(w in context_lower for w in ["subdomain", "dns", "vhost"]):
        return "Subdomain enumeration", get_wordlist("subdomains_top1m")
    
    # Fuzzing
    if "sql" in context_lower:
        return "SQL injection payloads", get_wordlist("sqli_generic")
    if "xss" in context_lower:
        return "XSS payloads", get_wordlist("xss_polyglots")
    if "lfi" in context_lower or "file inclusion" in context_lower:
        return "LFI payloads", get_wordlist("lfi_linux")
    
    # Default
    return "General wordlist", get_wordlist("dirb_common")


def list_available_wordlists() -> dict[str, dict[str, object]]:
    """List all available wordlists with info."""
    available: dict[str, dict[str, object]] = {}
    
    for name, path_str in WORDLIST_PATHS.items():
        path = Path(path_str)
        if path.exists():
            # Count lines
            try:
                with open(path, errors='ignore') as f:
                    line_count = sum(1 for _ in f)
            except (OSError, UnicodeError):
                line_count = -1
            
            available[name] = {
                "path": str(path),
                "lines": line_count,
                "size_mb": round(path.stat().st_size / (1024 * 1024), 2),
            }
    
    return available


def format_wordlist_suggestions(task: str) -> str:
    """Format wordlist suggestions for the agent."""
    wordlists = get_wordlists_for_task(task)
    
    if not wordlists:
        return f"No specific wordlist recommendations for '{task}'. Using dirb/common.txt."
    
    lines = [f"**Recommended wordlists for {task}:**\n"]
    
    for i, wl in enumerate(wordlists, 1):
        try:
            with open(wl, errors='ignore') as f:
                line_count = str(sum(1 for _ in f))
        except (OSError, UnicodeError):
            line_count = "?"

        lines.append(f"{i}. `{wl}` ({line_count} entries)")
    
    return "\n".join(lines)
