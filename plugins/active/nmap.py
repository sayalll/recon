from core.orchestrator import Plugin
import re


class NmapPlugin(Plugin):
    name, phase = "nmap", "active"
    produces = ["nmap_done"]

    def __init__(self, full=False):
        self.full = full

    def run(self, ctx):
        t = ctx.target
        # in scope as a name, OR an IP explicitly authorised via --scope
        if not (ctx.scope.validate_host(t) or ctx.scope.validate_host(t, allow_ip=True)):
            print(f"[*] nmap: {t} not in authorised scope, skip")
            return
        flag = "-p- " if self.full else "--top-ports 1000 "
        out = ctx.run_tool(f"nmap -sV -T4 -Pn {flag}{t}",
                           1800 if self.full else 900)
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
            if m and re.search(r"vsftpd 2\.3\.4|proftpd 1\.3\.[0-3]\b|openssh [45]\.|"
                               r"mysql.*5\.[0-5]|iis 6\.0|apache 2\.[0-2]\.",
                               m.group(3), re.I):
                ctx.report.finding("high", "nmap", "vulnerable service",
                    f"Vulnerable service on port {m.group(1)}",
                    f"{t}:{m.group(1)}", m.group(2), m.group(3))
