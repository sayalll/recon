from core.orchestrator import Plugin
import concurrent.futures as cf, re
from urllib.parse import urljoin

PATTERNS = {
    "AWS Key":     r"AKIA[0-9A-Z]{16}",
    "Google API":  r"AIza[0-9A-Za-z\-_]{35}",
    "JWT":         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Slack token": r"xox[baprs]-[0-9a-zA-Z]{10,}",
    "Private key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Stripe key":  r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}",
    "Generic pwd": r"(?i)(password|passwd|api_key|secret)\s*[:=]\s*['\"][^'\"]{8,}",
}


class JsSecretsPlugin(Plugin):
    name, phase = "js_secrets", "active"
    requires, produces = ["live", "wayback_urls"], ["js_done"]

    def run(self, ctx):
        urls = {u for u in ctx.shared.get("wayback_urls", []) if u.endswith(".js")}
        for d in ctx.shared.get("live", {}).values():
            r = ctx.http_get(d["url"], timeout=12)
            if r is None:
                continue
            urls |= {urljoin(d["url"], m) for m in
                     re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text)}
        urls = [u for u in urls if ctx.scope.validate_url(u)][:100]

        def scan(url):
            r = ctx.http_get(url, timeout=10)
            if r is None:
                return []
            body = r.text
            return [(n, m) for n, p in PATTERNS.items()
                    for m in set(re.findall(p, body))][:5]

        with cf.ThreadPoolExecutor(10) as ex:
            for url, hits in zip(urls, ex.map(scan, urls)):
                for name, m in hits:
                    hit = m if isinstance(m, str) else (m[0] if m else "")
                    sev = "medium" if name == "Generic pwd" else "high"
                    ctx.report.finding(sev, "jssecrets", f"secret {name}",
                        f"Secret in JS: {name}", url, "Rotate immediately",
                        str(hit)[:200],
                        remediation="Rotate the leaked credential; purge history.")
