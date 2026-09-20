from core.orchestrator import Plugin

# body fingerprints (host resolves + serves the tell-tale error page)
BODY_FINGERPRINTS = [
    ("S3 bucket",    "NoSuchBucket"),
    ("GitHub Pages", "There isn't a GitHub Pages site here"),
    ("Azure",        "404 Web Site not found"),
    ("Heroku",       "No such app"),
    ("Shopify",      "Sorry, this shop is currently unavailable"),
    ("Fastly",       "Fastly error: unknown domain"),
    ("CloudFront",   "Bad request. (CloudFront)"),
]

# CNAME suffixes that point at a takeover-prone third party
CNAME_SIGS = {
    "s3.amazonaws.com":        "S3 bucket",
    "github.io":               "GitHub Pages",
    "herokuapp.com":           "Heroku",
    "herokudns.com":           "Heroku",
    "azurewebsites.net":       "Azure",
    "cloudapp.net":            "Azure",
    "myshopify.com":           "Shopify",
    "fastly.net":              "Fastly",
    "cloudfront.net":          "CloudFront",
    "ghost.io":                "Ghost",
    "wpengine.com":            "WP Engine",
}


class TakeoverPlugin(Plugin):
    """Two real detection paths (the old one was a no-op):
      1. Dangling CNAME — subdomain has a CNAME to a known service but does not
         resolve to a live host (classic takeover candidate).
      2. Live fingerprint — host resolves and serves the service's 'not found' page.
    """
    name, phase = "takeover", "active"
    requires, produces = ["live"], ["takeover_done"]

    def _cname(self, ctx, host):
        out = ctx.run_tool(f"dig +short CNAME {host}", 15).strip()
        return out.splitlines()[-1].rstrip(".").lower() if out else ""

    def run(self, ctx):
        subs = set(ctx.shared.get("subdomains", [])) | set(ctx.shared.get("live", {}))
        checked = 0
        for host in sorted(subs):
            if checked >= 300:
                break
            checked += 1
            if not ctx.scope.is_in_scope_name(host):
                continue
            resolves = bool(ctx.scope._resolve(host))
            cname = self._cname(ctx, host)

            # path 1: dangling CNAME to a known service
            if cname and not resolves:
                for suf, svc in CNAME_SIGS.items():
                    if cname.endswith(suf):
                        ctx.report.finding("high", "takeover", "Takeover",
                            f"Dangling CNAME → {svc} (name does not resolve)", host,
                            f"CNAME: {cname}", cname, confidence="possible",
                            remediation="Remove the dangling DNS record or claim the service.")
                        break
                continue

            # path 2: live host serving a takeover fingerprint
            if resolves:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    if not ctx.scope.validate_url(url):
                        continue
                    r = ctx.http_get(url, timeout=10)
                    if r is None:
                        continue
                    body = r.text[:3000]
                    hit = next((svc for svc, sig in BODY_FINGERPRINTS if sig in body), None)
                    if hit:
                        ctx.report.finding("critical", "takeover", "Takeover",
                            f"Subdomain takeover possible via {hit}", url,
                            "Service fingerprint present on a live host", body[:300],
                            confidence="confirmed",
                            remediation="Remove the dangling DNS record or claim the service.")
                    break
