"""Plain-text export: writes one folder per scan under ./loot/ containing a
separate .txt for every search (subdomains, live hosts, wayback, dns, whois)
plus a readable findings report and a summary."""
import os, time

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text.rstrip("\n") + "\n" if text else "")


def write_txt_reports(ctx, report, findings=None, base="loot"):
    findings = findings if findings is not None else report.all_findings()
    shared = getattr(ctx, "shared", {}) or {}
    d = os.path.join(base, f"{report.target}_{report.scan_id}")
    os.makedirs(d, exist_ok=True)

    # ---- one file per "search" ----
    subs = shared.get("subdomains", [])
    _write(os.path.join(d, "subdomains.txt"), "\n".join(subs))

    live = shared.get("live", {}) or {}
    live_lines = [f"{v.get('url','')}\t{v.get('status','')}\t{(v.get('title') or '')}"
                  for v in live.values()]
    _write(os.path.join(d, "live_hosts.txt"), "\n".join(live_lines))
    _write(os.path.join(d, "live_urls.txt"),
           "\n".join(v.get("url", "") for v in live.values()))

    _write(os.path.join(d, "wayback_urls.txt"),
           "\n".join(shared.get("wayback_urls", [])))

    dns = shared.get("dns", {}) or {}
    if dns:
        dns_txt = "\n".join(f"{rt}:\n  " + "\n  ".join(vals)
                            for rt, vals in dns.items())
        _write(os.path.join(d, "dns.txt"), dns_txt)

    whois = shared.get("whois", {}) or {}
    if whois:
        _write(os.path.join(d, "whois.txt"),
               "\n".join(f"{k}: {v}" for k, v in whois.items()))

    shodan = shared.get("shodan_cves", [])
    if shodan:
        _write(os.path.join(d, "shodan_cves.txt"), "\n".join(shodan))

    # ---- findings (severity/score sorted) ----
    ordered = sorted(findings,
                     key=lambda x: (-x.get("score", 0),
                                    -SEV_ORDER.get(x.get("severity", "info"), 0)))
    blocks = []
    for f in ordered:
        score = f.get("score")
        head = f"[{f.get('severity', '').upper():<8}] {f.get('title', '')}"
        if score is not None:
            head += f"   (score {score}, {f.get('confidence', 'possible')})"
        blocks.append(
            head + "\n" +
            f"  asset      : {f.get('asset', '')}\n" +
            (f"  detail     : {f['detail']}\n" if f.get("detail") else "") +
            (f"  evidence   : {f.get('evidence', '')[:300]}\n" if f.get("evidence") else "") +
            (f"  remediation: {f['remediation']}\n" if f.get("remediation") else ""))
    header = (f"ReconMaster v3 — {report.target}  (scan #{report.scan_id})\n"
              f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"{'=' * 60}\n")
    _write(os.path.join(d, "findings.txt"), header + "\n".join(blocks))

    # ---- summary ----
    counts = {}
    for f in findings:
        counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1
    summary = [f"Target      : {report.target}",
               f"Scan ID     : {report.scan_id}",
               f"Subdomains  : {len(subs)}",
               f"Live hosts  : {len(live)}",
               f"Wayback URLs: {len(shared.get('wayback_urls', []))}",
               f"Findings    : {len(findings)}", ""]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev):
            summary.append(f"  {sev:<9}: {counts[sev]}")
    _write(os.path.join(d, "summary.txt"), "\n".join(summary))
    return d
