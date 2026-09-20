"""Authenticated dashboard — localhost-bound, cookie-gated.

Fixes vs. the original:
  * real do_scan() driving the shared pipeline (no phantom import),
  * findings streamed via the Report listener queue,
  * correct auth guard on '/', raise (not return) on rejected /stream,
  * stream closes cleanly when the scan finishes.
"""
import os, sys, json, queue, secrets, threading, ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

ADMIN_PASS = os.environ.get("RM_DASHBOARD_PASS") or secrets.token_urlsafe(12)
print(f"[dashboard] password: {ADMIN_PASS}")

sessions: set[str] = set()
app = FastAPI()
_here = os.path.dirname(__file__)
tpl = Jinja2Templates(directory=os.path.join(_here, "templates"))
DASHBOARD = os.path.join(_here, "templates", "dashboard.html")


def _authed(request: Request) -> bool:
    return request.cookies.get("rm_auth") in sessions


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not _authed(request):
        return tpl.TemplateResponse("login.html", {"request": request, "error": ""})
    with open(DASHBOARD) as f:
        return HTMLResponse(f.read())


@app.post("/login")
def login(request: Request, password: str = Form(...)):
    if not secrets.compare_digest(password, ADMIN_PASS):
        return tpl.TemplateResponse(
            "login.html", {"request": request, "error": "Wrong password."}, status_code=401)
    tok = secrets.token_urlsafe(24)
    sessions.add(tok)
    resp = RedirectResponse("/", 303)
    resp.set_cookie("rm_auth", tok, httponly=True, samesite="strict")
    return resp


def do_scan(target: str, q: "queue.Queue"):
    """Run a full scan, streaming findings into q via the report listener."""
    import yaml
    from core.scope import ScopeGuard
    from core.report import Report
    from core.context import ScanContext
    from core.runner import run_pipeline
    from core.triage import run_triage
    cfg = yaml.safe_load(open("config.yaml"))
    report = Report(target)
    report.listeners.append(q)
    ctx = ScanContext(target, ScopeGuard(target), cfg, report)
    try:
        run_pipeline(ctx, ("passive", "active", "vuln"))
        run_triage(report, cfg, ctx)
    finally:
        report.finish()
        q.put({"type": "done"})


@app.get("/stream")
def stream(request: Request, t: str):
    if not _authed(request):
        raise HTTPException(403)
    # reject raw IPs and obviously-local names from the web entrypoint
    try:
        ipaddress.ip_address(t)
        raise HTTPException(400, "raw IPs are not accepted via the dashboard")
    except ValueError:
        pass
    if "." not in t or t.endswith(".local"):
        raise HTTPException(400, "invalid target")

    q: "queue.Queue" = queue.Queue()

    def bg():
        try:
            do_scan(t, q)
        except Exception as e:
            q.put({"type": "finding", "severity": "high", "title": "scan error",
                   "detail": str(e), "asset": t, "evidence": ""})
            q.put({"type": "done"})

    threading.Thread(target=bg, daemon=True).start()

    def gen():
        yield "retry: 5000\n\n"
        while True:
            try:
                item = q.get(timeout=30)
            except Exception:
                yield ": keepalive\n\n"
                continue
            yield f"data: {json.dumps(item)}\n\n"
            if isinstance(item, dict) and item.get("type") == "done":
                break

    return StreamingResponse(gen(), media_type="text/event-stream")
