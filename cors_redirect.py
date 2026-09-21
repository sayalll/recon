from core.orchestrator import Plugin

PROBE = "https://rm-probe.example.com"


class CorsRedirectPlugin(Plugin):
    name, phase = "cors_redirect", "active"
    requires, produces = ["live"], ["cors_done"]

    def run(self, ctx):
        bases = [d["url"] for d in ctx.shared.get("live", {}).values()] or \
                [f"https://{ctx.target}"]
        for base in bases[:10]:
            r = ctx.http_get(base, headers={"Origin": PROBE}, timeout=12)
            if r is not None and r.headers.get("Access-Control-Allow-Origin") == PROBE:
                ctx.report.finding("high", "cors", "CORS reflect",
                    "CORS reflects arbitrary origin", base,
                    "Credential theft possible", PROBE)
            for p in ["url", "redirect", "next", "return", "returnUrl"]:
                rr = ctx.http_get(base, params={p: PROBE}, timeout=12,
                                  allow_redirects=False)
                if rr is None:
                    continue
                loc = rr.headers.get("Location", "")
                if rr.status_code in (301, 302, 307) and "rm-probe.example.com" in loc:
                    ctx.report.finding("medium", "redirect", "open redirect",
                        "Open redirect", f"{base}?{p}=", "", loc)
