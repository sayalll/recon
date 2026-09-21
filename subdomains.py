from core.orchestrator import Plugin
import os, socket


class SubdomainPlugin(Plugin):
    name, phase = "subdomains", "passive"
    produces = ["subdomains"]
    requires = []                       # no deps -> runs in wave 1

    def _crtsh(self, ctx, d):
        r = ctx.http_get(f"https://crt.sh/?q=%25.{d}&output=json", timeout=40)
        if not r:
            return set()
        try:
            j = r.json()
            return {n.replace("*.", "").strip() for e in j
                    for n in e["name_value"].split("\n") if d in n}
        except Exception:
            return set()

    def _otx(self, ctx, d):
        r = ctx.http_get(f"https://otx.alienvault.com/api/v1/indicators/"
                         f"domain/{d}/passive_dns", timeout=30)
        if not r:
            return set()
        try:
            return {e["hostname"] for e in r.json().get("passive_dns", [])
                    if d in e["hostname"]}
        except Exception:
            return set()

    def _hackertarget(self, ctx, d):
        r = ctx.http_get(f"https://api.hackertarget.com/hostsearch/?q={d}", timeout=20)
        if not r:
            return set()
        return {l.split(",")[0] for l in r.text.splitlines() if "." in l}

    def run(self, ctx):
        d, rep = ctx.target, ctx.report
        # wildcard fingerprint
        rand = f"rm-{os.urandom(4).hex()}.{d}"
        try:
            socket.gethostbyname(rand)
            wildcard = True
        except Exception:
            wildcard = False
        if wildcard:
            print("[!] Wildcard DNS — validating every sub by IP fingerprint")

        subs = self._crtsh(ctx, d) | self._otx(ctx, d) | self._hackertarget(ctx, d)
        subs.add(d)
        if wildcard:                    # drop wildcard twins (compare IP sets)
            rand_ip = set(ctx.scope._resolve(rand))
            subs = {s for s in subs
                    if not rand_ip or set(ctx.scope._resolve(s)) != rand_ip}
        subs = {s for s in subs if ctx.scope.is_in_scope_name(s)}
        ctx.shared["subdomains"] = sorted(subs)
        for s in subs:
            rep.add_asset("subdomain", s)
        print(f"    subdomains: {len(subs)} in scope")
