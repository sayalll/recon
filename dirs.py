from core.orchestrator import Plugin
import json, os, re


class DirsPlugin(Plugin):
    name, phase = "dirs", "active"
    requires, produces = ["live"], ["dirs_done"]

    def _wordlist(self, ctx, techs):
        wl_cfg = ctx.config.get("defaults", {}).get("wordlists", {})
        base = wl_cfg.get("base", "/usr/share/seclists/Discovery/Web-Content")
        common = os.path.join(base, wl_cfg.get("common", "common.txt"))
        joined = " ".join(techs).lower()
        for tech, rel in wl_cfg.get("tech_map", {}).items():
            if tech in joined and re.match(r"[\w./-]+$", rel):
                cand = os.path.join(base, rel)
                if os.path.isfile(cand):
                    return cand
        return common if os.path.isfile(common) else None

    def run(self, ctx):
        live = ctx.shared.get("live", {})
        targets = [d["url"] for d in live.values()] or [f"https://{ctx.target}"]
        techs = [t for d in live.values() for t in d.get("tech", [])]
        wl = self._wordlist(ctx, techs)
        if not wl:
            print("[*] dirs: no usable wordlist found (install seclists?), skip")
            return
        out_json = ctx.tmp("ffuf.json")
        for base_url in targets[:15]:
            ctx.run_tool(f"ffuf -w '{wl}' -u {base_url}/FUZZ -mc 200,204,"
                         f"301,302,307,401,403 -of json -o {out_json} -t 20 -s", 400)
            try:
                results = json.load(open(out_json)).get("results", [])
            except Exception:
                continue
            for res in results:
                p = f"{res['url']} [{res['status']}]"
                if re.search(r"\.git|\.env|\.htpasswd|backup|phpmyadmin|\.sql$|"
                             r"\.svn|actuator|debug", p, re.I):
                    ctx.report.finding("high", "ffuf", "sensitive path exposed",
                        "Sensitive path exposed", p, "Validate contents", p)
