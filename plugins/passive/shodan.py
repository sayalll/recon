from core.orchestrator import Plugin
import os, socket


class ShodanPlugin(Plugin):
    name, phase = "shodan", "passive"
    requires, produces = ["subdomains"], ["shodan_cves"]

    def run(self, ctx):
        key = os.environ.get("RM_SHODAN_KEY", "")
        if not key:
            print("[*] shodan: RM_SHODAN_KEY unset, skip")
            return
        # Shodan host lookup needs an IP, not a hostname — resolve first.
        ips = ctx.scope._resolve(ctx.target)
        if not ips:
            try:
                ips = [socket.gethostbyname(ctx.target)]
            except Exception:
                ips = []
        cves = []
        for ip in ips[:2]:              # limit credit spend
            r = ctx.http_get(f"https://api.shodan.io/shodan/host/{ip}?key={key}",
                             timeout=30)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            for cve in data.get("vulns", []):
                cves.append(cve)
                ctx.report.finding("high", "shodan", f"shodan {cve}",
                    f"Shodan-reported CVE {cve}", ip,
                    "Historically observed on this IP by Shodan")
        ctx.shared["shodan_cves"] = cves
