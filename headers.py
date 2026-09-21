from core.orchestrator import Plugin
import re


class HeadersPlugin(Plugin):
    name, phase = "headers", "active"
    requires, produces = ["live"], ["headers_done"]

    def run(self, ctx):
        cap = int(ctx.config.get("defaults", {}).get("max_http_targets", 30))
        targets = [d["url"] for d in ctx.shared.get("live", {}).values()] or \
                  [f"https://{ctx.target}"]
        for base in targets[:cap]:
            resp = ctx.http_get(base)
            if resp is None:
                continue
            h = dict(resp.headers)
            for hname in ["Strict-Transport-Security", "Content-Security-Policy",
                          "X-Content-Type-Options", "X-Frame-Options"]:
                if hname not in h:
                    ctx.report.finding("medium", "headers", f"missing {hname}",
                        f"Missing security header: {hname}", base,
                        "Defense-in-depth gap",
                        remediation=f"Add the {hname} header at server/CDN level.")
            srv = h.get("Server", "") + " " + h.get("X-Powered-By", "")
            if re.search(r"\d+\.\d+", srv):
                ctx.report.finding("low", "headers", "version disclosure",
                    "Server version disclosure", base, "", srv)
            for c in h.get("Set-Cookie", "").split(","):
                if re.search(r"session|token|sid", c, re.I) and "httponly" not in c.lower():
                    ctx.report.finding("medium", "headers", "cookie httponly",
                        "Session cookie without HttpOnly", base, "", c)
