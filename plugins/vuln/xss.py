from core.orchestrator import Plugin

class XssPlugin(Plugin):
    name, phase = "xss", "vuln"
    requires, produces = ["wayback_urls"], ["xss_done"]
    def run(self, ctx):
        targets = [u for u in ctx.shared.get("wayback_urls", [])
                   if "=" in u][:30]
        if targets:
            open("/tmp/rm_xss_urls.txt", "w").write("\n".join(targets))
            out = ctx.run_tool("dalfox file /tmp/rm_xss_urls.txt --skip-bav "
                               "-o /tmp/rm_xss.txt --silent", 600)
        else:
            out = ctx.run_tool(f"dalfox url https://{ctx.target} --skip-bav "
                               f"-o /tmp/rm_xss.txt --silent", 400)
        try:
            for line in open("/tmp/rm_xss.txt"):
                if "[V]" in line or "PoC" in line:
                    ctx.report.finding("high", "dalfox", "Reflected XSS",
                        "Reflected XSS candidate", line.strip()[:120],
                        "Verify manually", line.strip()[:300])
        except Exception: pass
