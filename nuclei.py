from core.orchestrator import Plugin
import re
SEV = {"critical", "high", "medium", "low", "info"}

class NucleiPlugin(Plugin):
    name, phase = "nuclei", "vuln"
    requires, produces = ["live"], ["nuclei_done"]
    def run(self, ctx):
        bases = [d["url"] for d in ctx.shared.get("live", {}).values()] or \
                [f"https://{ctx.target}"]
        for base in bases[:15]:
            out = ctx.run_tool(f"nuclei -u {base} -severity low,medium,high,"
                               f"critical -silent -timeout 10", 1200)
            for line in out.splitlines():
                m = re.match(r"\[.+\]\s*\[(\w+)\]\s*(.+)", line)
                if m and m.group(1).lower() in SEV:
                    ctx.report.finding(m.group(1).lower(), "nuclei",
                        f"nuclei {m.group(2).strip()[:40]}", m.group(2).strip(),
                        base, "nuclei template match", line.strip())
