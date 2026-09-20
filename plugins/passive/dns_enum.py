from core.orchestrator import Plugin

class DnsPlugin(Plugin):
    name, phase = "dns", "passive"
    produces = ["dns"]
    def run(self, ctx):
        recs = {}
        for t in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            out = ctx.run_tool(f"dig +short {ctx.target} {t}", 20)
            if out.strip(): recs[t] = out.strip().splitlines()
        txt = " ".join(recs.get("TXT", []))
        r = ctx.report
        if "v=spf1" in txt and "+all" in txt:
            r.finding("medium", "dns", "spf +all", "Permissive SPF (+all)",
                      ctx.target, "Email spoofing possible", txt)
        elif "v=spf1" not in txt:
            r.finding("low", "dns", "no spf", "No SPF record", ctx.target)
        dmarc = ctx.run_tool(f"dig +short _dmarc.{ctx.target} TXT", 15)
        if "v=DMARC1" not in dmarc:
            r.finding("low", "dns", "no dmarc", "No DMARC record", ctx.target)
        for ns in recs.get("NS", []):
            axfr = ctx.run_tool(f"dig axfr {ctx.target} @{ns}", 30)
            if "failed" not in axfr.lower() and "XFR size" in axfr:
                r.finding("high", "dns", "zone transfer",
                          f"DNS zone transfer via {ns}", ctx.target,
                          "Full zone disclosure", axfr[:500], remediation=
                          "Restrict AXFR: allow-transfer { trusted; };")
        ctx.shared["dns"] = recs
