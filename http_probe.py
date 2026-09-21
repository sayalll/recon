from core.orchestrator import Plugin
import json


class HttpProbePlugin(Plugin):
    name, phase = "http_probe", "active"
    requires, produces = ["subdomains"], ["live"]

    def run(self, ctx):
        subs = ctx.shared.get("subdomains", [])
        ctx.shared.setdefault("live", {})
        if not subs:
            return
        subs_file = ctx.tmp("subs.txt")
        with open(subs_file, "w") as f:
            f.write("\n".join(subs))
        out = ctx.run_tool(f"httpx -l {subs_file} -silent -status-code "
                           f"-title -tech-detect -json", 300)
        live = {}
        for line in out.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            url = j.get("url") or f"http://{j.get('input')}"
            if ctx.scope.validate_url(url):
                key = j.get("input", url)
                live[key] = {"url": url, "status": j.get("status_code"),
                             "title": j.get("title"), "tech": j.get("tech", [])}
        ctx.shared["live"] = live
        for host, d in live.items():
            ctx.report.add_asset("web", host, live=True, tech=d.get("tech"))
        print(f"    live web hosts: {len(live)}")
