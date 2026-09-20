from core.orchestrator import Plugin
import re


class WaybackPlugin(Plugin):
    name, phase = "wayback", "passive"
    produces = ["wayback_urls"]

    def run(self, ctx):
        r = ctx.http_get("http://web.archive.org/cdx/search/cdx?url=*."
                         f"{ctx.target}/*&output=text&fl=original&collapse=urlkey"
                         f"&limit=5000", timeout=60)
        urls = [l for l in r.text.splitlines() if l.startswith("http")] if r else []
        ctx.shared["wayback_urls"] = urls
        for u in urls:
            if re.search(r"\.(sql|bak|zip|tar\.gz|env)$|dump|backup", u, re.I):
                ctx.report.finding("medium", "wayback", "interesting historical file",
                    "Interesting historical file", ctx.target,
                    "May still exist on live server", u)
