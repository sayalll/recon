from core.orchestrator import Plugin
import re

class WhoisPlugin(Plugin):
    name, phase, produces = "whois", "passive", ["whois"]
    def run(self, ctx):
        out = ctx.run_tool(f"whois {ctx.target}", 60)
        info = dict(re.findall(r"^\s*(\w[\w .-]*?):\s*(.+)$", out, re.M)[:40])
        ctx.shared["whois"] = info
        ctx.report.add_asset("whois", ctx.target)
        exp = info.get("Expiry Date") or info.get("Registry Expiry Date", "")
        if exp:
            from datetime import datetime
            try:
                days = (datetime.strptime(exp[:10], "%Y-%m-%d") - datetime.now()).days
                if days < 45:
                    ctx.report.finding("medium", "whois", "domain expiry",
                        "Domain expiring soon", ctx.target, f"{days} days", exp)
            except Exception: pass
