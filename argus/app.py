"""Argus SIEM — FastAPI application (REST API + WebSocket + web console)."""
from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any, Optional

from fastapi import (Depends, FastAPI, File, Form, HTTPException, Request,
                     UploadFile, WebSocket, WebSocketDisconnect)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from fastapi.responses import FileResponse

from . import agent_registry, ai, database as db, net_telemetry
from .collectors.winevent import winevent_collector
from .collectors.syslog import syslog_collector

# the OS log collector for this host (Windows Event Log or Linux syslog/journald)
os_log_collector = winevent_collector if winevent_collector.available else syslog_collector
from .config import settings
from .core.bus import bus
from .core.detection import block_indicator
from .core.pipeline import ingest_event
from .forensics import backup, cases as casemgr, integrity, iocs, timeline, triage
from .integrations import virustotal as vt
from .knowledge import EVENT_IDS, describe
from .network import discovery, scanner as netscanner
from .scanners import file_scanner
from .scanners.watcher import scan_directory, watch_service
from .network.discovery import monitor_service
from .security import create_token, hash_password, verify_password, verify_token
from .seed import seed_all

templates = Jinja2Templates(directory=str(settings.WEB_DIR / "templates"))

app = FastAPI(title="Biggy SIEM", version="1.0.0", docs_url="/api/docs")
app.mount("/static", StaticFiles(directory=str(settings.WEB_DIR / "static")), name="static")


@app.middleware("http")
async def _no_cache_static(request: Request, call_next):
    """Tell browsers to always revalidate CSS/JS so UI updates never get stuck
    behind a stale cache (revalidation is cheap: a 304 when unchanged)."""
    resp = await call_next(request)
    if request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-cache, max-age=0"
    return resp


# --------------------------------------------------------------------------- #
# Lifespan: seed DB, wire the bus to the running loop, start background workers
# --------------------------------------------------------------------------- #
@app.on_event("startup")
async def _startup() -> None:
    seed_all()
    integrity.init_chain()  # load the tamper-evident audit chain head
    bus.bind_loop(asyncio.get_running_loop())
    import os as _os
    if _os.environ.get("ARGUS_NO_BACKGROUND") != "1":
        if _os.environ.get("ARGUS_NO_WATCH") != "1":
            watch_service.start()
        if _os.environ.get("ARGUS_NO_MONITOR") != "1":
            monitor_service.start()
        if _os.environ.get("ARGUS_NO_WINEVENT") != "1":
            winevent_collector.start()   # Windows only (no-op elsewhere)
            syslog_collector.start()     # Linux only (no-op elsewhere)
        if _os.environ.get("ARGUS_NO_SAMPLER") != "1":
            net_telemetry.sampler.start()
        backup.backup_service.start()

    def _agent_sweeper() -> None:
        while True:
            time.sleep(60)
            try:
                agent_registry.sweep_stale()
            except Exception:
                pass

    threading.Thread(target=_agent_sweeper, name="argus-agent-sweeper", daemon=True).start()


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #
def _current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("argus_token")
    if not token:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:]
    return verify_token(token) if token else None


def require_user(request: Request) -> dict:
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_agent(request: Request) -> None:
    key = request.headers.get("x-agent-key", "")
    if key != settings.AGENT_KEY:
        raise HTTPException(status_code=403, detail="Invalid agent key")


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    if _current_user(request):
        return RedirectResponse("/dashboard")
    return RedirectResponse("/login")


AGENT_SCRIPT = Path(__file__).resolve().parent.parent / "agent" / "argus_agent.py"


@app.get("/agent.py")
def download_agent():
    """Serve the host-agent script so a device can fetch it directly:
    curl http://<server>:<port>/agent.py -o argus_agent.py"""
    if not AGENT_SCRIPT.exists():
        raise HTTPException(404, "agent script not found")
    return FileResponse(AGENT_SCRIPT, filename="argus_agent.py", media_type="text/x-python")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _current_user(request):
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not _current_user(request):
        return RedirectResponse("/login")
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": _current_user(request),
         "vt_enabled": settings.virustotal_enabled,
         "nmap": netscanner.nmap_available(),
         "watch_dir": settings.WATCH_DIR,
         "lan_ip": discovery.local_ip(),
         "server_port": settings.PORT,
         "agent_key": settings.AGENT_KEY},
    )


# --------------------------------------------------------------------------- #
# Auth API
# --------------------------------------------------------------------------- #
@app.post("/api/login")
async def api_login(username: str = Form(...), password: str = Form(...)):
    row = db.query_one("SELECT * FROM users WHERE username = ?", (username,))
    if not row or not verify_password(password, row["password_hash"]):
        ingest_event(source="auth", category="authentication", severity=3,
                     message=f"Failed login for {username} (console)", user=username)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(row["username"], row["role"])
    ingest_event(source="auth", category="authentication", severity=1,
                 message=f"Successful login for {username} (console)", user=username)
    resp = JSONResponse({"ok": True, "user": {"username": row["username"], "role": row["role"]}})
    resp.set_cookie("argus_token", token, httponly=True, samesite="lax",
                    max_age=settings.TOKEN_TTL_SECONDS)
    return resp


@app.post("/api/logout")
async def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("argus_token")
    return resp


@app.get("/api/me")
async def api_me(user: dict = Depends(require_user)):
    return {"user": user}


# --------------------------------------------------------------------------- #
# Overview / metrics
# --------------------------------------------------------------------------- #
@app.get("/api/overview")
def overview(user: dict = Depends(require_user)):
    day_ago = db.now() - 86400
    sev = {r["severity"]: r["c"] for r in db.query(
        "SELECT severity, COUNT(*) c FROM events WHERE ts >= ? GROUP BY severity", (day_ago,))}
    cats = db.query(
        "SELECT category, COUNT(*) c FROM events WHERE ts >= ? GROUP BY category ORDER BY c DESC LIMIT 6",
        (day_ago,))
    timeline = db.query(
        """SELECT CAST((? - ts)/3600 AS INT) AS hours_ago, COUNT(*) c, MAX(severity) sev
           FROM events WHERE ts >= ? GROUP BY hours_ago ORDER BY hours_ago DESC""",
        (db.now(), day_ago))
    return {
        "counts": {
            "events_24h": sum(sev.values()),
            "open_alerts": db.query_one("SELECT COUNT(*) c FROM alerts WHERE status='open'")["c"],
            "critical_alerts": db.query_one(
                "SELECT COUNT(*) c FROM alerts WHERE status='open' AND severity>=5")["c"],
            "devices": db.query_one("SELECT COUNT(*) c FROM devices")["c"],
            "devices_down": db.query_one("SELECT COUNT(*) c FROM devices WHERE status='down'")["c"],
            "agents": db.query_one("SELECT COUNT(*) c FROM agents WHERE status='active'")["c"],
            "blocked": db.query_one("SELECT COUNT(*) c FROM blocklist WHERE active=1")["c"],
            "malicious_files": db.query_one(
                "SELECT COUNT(*) c FROM scans WHERE kind='file' AND verdict='malicious'")["c"],
            "open_cases": db.query_one("SELECT COUNT(*) c FROM cases WHERE status != 'closed'")["c"],
            "iocs": db.query_one("SELECT COUNT(*) c FROM iocs WHERE active=1")["c"],
            "evidence": db.query_one("SELECT COUNT(*) c FROM artifacts")["c"],
        },
        "severity": {str(k): sev.get(k, 0) for k in range(1, 6)},
        "categories": cats,
        "timeline": timeline,
        "integrations": {
            "virustotal": settings.virustotal_enabled,
            "nmap": netscanner.nmap_available(),
            "watch_dir": settings.WATCH_DIR,
            "watch_last_run": watch_service.last_run,
            "winlog": winevent_collector.available,
            "winlog_ingested": winevent_collector.total_ingested,
        },
        "network": net_telemetry.summary(),
    }


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #
@app.get("/api/events")
def list_events(user: dict = Depends(require_user), limit: int = 100,
                severity: int = 0, category: str = "", q: str = ""):
    sql = "SELECT * FROM events WHERE 1=1"
    params: list[Any] = []
    if severity:
        sql += " AND severity >= ?"; params.append(severity)
    if category:
        sql += " AND category = ?"; params.append(category)
    if q:
        sql += " AND (message LIKE ? OR host LIKE ? OR src_ip LIKE ? OR user LIKE ?)"
        like = f"%{q}%"; params += [like, like, like, like]
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(min(limit, 500))
    return {"events": db.query(sql, params)}


@app.get("/api/events/{event_id}")
def get_event(event_id: int, user: dict = Depends(require_user)):
    """Full detail for one event: all fields + parsed raw + decoded code + chain."""
    row = db.query_one("SELECT * FROM events WHERE id = ?", (event_id,))
    if not row:
        raise HTTPException(404, "event not found")
    row["raw"] = db.loads(row.get("raw"), {})
    if row.get("event_id") is not None:
        row["event_meta"] = describe(row["event_id"])
    row["severity_label"] = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(row["severity"], "medium")
    # was this event escalated into any alerts?
    row["alerts"] = db.query(
        "SELECT id, ts, title, severity, rule_id, status FROM alerts WHERE event_id = ? ORDER BY ts DESC", (event_id,))
    return row


@app.post("/api/events")
async def create_event(request: Request, user: dict = Depends(require_user)):
    body = await request.json()
    event = ingest_event(
        source=body.get("source", "manual"),
        message=body.get("message", ""),
        category=body.get("category", "general"),
        severity=int(body.get("severity", 3)),
        host=body.get("host"), src_ip=body.get("src_ip"),
        dst_ip=body.get("dst_ip"), user=body.get("user"),
        event_id=body.get("event_id"), provider=body.get("provider"),
        level=body.get("level"), raw=body,
    )
    return {"ok": True, "event": event}


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
@app.get("/api/alerts")
def list_alerts(user: dict = Depends(require_user), status: str = "", limit: int = 100):
    sql = "SELECT * FROM alerts"
    params: list[Any] = []
    if status:
        sql += " WHERE status = ?"; params.append(status)
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(min(limit, 500))
    return {"alerts": db.query(sql, params)}


@app.post("/api/alerts/{alert_id}/status")
async def set_alert_status(alert_id: int, request: Request, user: dict = Depends(require_user)):
    body = await request.json()
    status = body.get("status", "open")
    if status not in ("open", "investigating", "closed"):
        raise HTTPException(400, "invalid status")
    db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Detection rules
# --------------------------------------------------------------------------- #
@app.get("/api/rules")
def list_rules(user: dict = Depends(require_user)):
    return {"rules": db.query("SELECT * FROM rules ORDER BY severity DESC, id")}


@app.post("/api/rules")
async def create_rule(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    rid = b.get("id") or f"C{int(time.time())}"
    db.execute(
        """INSERT OR REPLACE INTO rules (id, name, description, category, severity, enabled,
           match_field, match_type, match_value, threshold, window_sec, action, mitre)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (rid, b.get("name", "Custom rule"), b.get("description", ""), b.get("category", "custom"),
         int(b.get("severity", 3)), 1 if b.get("enabled", True) else 0,
         b.get("match_field", "message"), b.get("match_type", "contains"),
         b.get("match_value", ""), int(b.get("threshold", 0)),
         int(b.get("window_sec", 60)), b.get("action", "alert"), b.get("mitre", "")),
    )
    return {"ok": True, "id": rid}


@app.patch("/api/rules/{rule_id}")
async def toggle_rule(rule_id: str, request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    db.execute("UPDATE rules SET enabled = ? WHERE id = ?",
               (1 if b.get("enabled") else 0, rule_id))
    return {"ok": True}


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str, user: dict = Depends(require_user)):
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    return {"ok": True}


# --------------------------------------------------------------------------- #
# File scanning (self-built engine + optional VirusTotal enrichment)
# --------------------------------------------------------------------------- #
@app.post("/api/scan/file")
async def scan_uploaded_file(user: dict = Depends(require_user),
                             file: UploadFile = File(...), virustotal: bool = Form(False)):
    content = await file.read()
    report = file_scanner.scan_bytes(file.filename, content)
    if virustotal and settings.virustotal_enabled:
        report["virustotal"] = await vt.lookup_hash(report["sha256"])
        vtv = report["virustotal"].get("verdict")
        if vtv == "malicious" and report["verdict"] != "malicious":
            report["verdict"] = "malicious"; report["score"] = max(report["score"], 80)
    db.execute(
        """INSERT INTO scans (ts, kind, target, verdict, engine, positives, total, sha256, details)
           VALUES (?, 'file', ?, ?, 'local+vt', ?, ?, ?, ?)""",
        (db.now(), file.filename, report["verdict"], len(report.get("reasons", [])),
         len(report.get("reasons", [])), report["sha256"], db.dumps(report)),
    )
    if report["verdict"] in ("malicious", "suspicious"):
        ingest_event(source="scanner", category="malware",
                     severity=5 if report["verdict"] == "malicious" else 4,
                     message=f"{report['verdict'].title()} file uploaded: {file.filename}",
                     host="argus-console", raw={"sha256": report["sha256"]})
    return report


@app.post("/api/scan/folder")
async def scan_folder(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    path = b.get("path") or settings.WATCH_DIR
    deep = bool(b.get("deep", False))
    result = await asyncio.to_thread(scan_directory, path, deep)
    return result


@app.get("/api/scans")
def list_scans(user: dict = Depends(require_user), kind: str = "", limit: int = 100):
    sql = "SELECT id, ts, kind, target, verdict, engine, positives, total, sha256 FROM scans"
    params: list[Any] = []
    if kind:
        sql += " WHERE kind = ?"; params.append(kind)
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(min(limit, 300))
    return {"scans": db.query(sql, params)}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, user: dict = Depends(require_user)):
    row = db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
    if not row:
        raise HTTPException(404, "not found")
    row["details"] = db.loads(row.get("details"), {})
    return row


# --------------------------------------------------------------------------- #
# Threat intelligence (VirusTotal)
# --------------------------------------------------------------------------- #
@app.get("/api/intel/hash/{value}")
async def intel_hash(value: str, user: dict = Depends(require_user)):
    return await vt.lookup_hash(value)


@app.get("/api/intel/ip/{value}")
async def intel_ip(value: str, user: dict = Depends(require_user)):
    return await vt.lookup_ip(value)


@app.get("/api/intel/domain/{value}")
async def intel_domain(value: str, user: dict = Depends(require_user)):
    return await vt.lookup_domain(value)


@app.post("/api/intel/url")
async def intel_url(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return await vt.lookup_url(b.get("url", ""))


@app.post("/api/intel/submit")
async def intel_submit(user: dict = Depends(require_user), file: UploadFile = File(...)):
    content = await file.read()
    return await vt.upload_file("", file.filename, content)


# --------------------------------------------------------------------------- #
# Network: discovery, monitoring, port scans
# --------------------------------------------------------------------------- #
@app.get("/api/devices")
def list_devices(user: dict = Depends(require_user)):
    devices = db.query("SELECT * FROM devices ORDER BY status DESC, ip")
    for d in devices:
        d["open_ports"] = db.loads(d.get("open_ports"), [])
    return {"devices": devices, "subnet": discovery.local_subnet(), "local_ip": discovery.local_ip()}


@app.post("/api/network/discover")
async def net_discover(request: Request, user: dict = Depends(require_user)):
    b = await request.json() if await _has_body(request) else {}
    subnet = b.get("subnet")
    result = await asyncio.to_thread(discovery.discover, subnet, True)
    return result


@app.post("/api/network/monitor")
async def net_monitor(user: dict = Depends(require_user)):
    return await asyncio.to_thread(discovery.monitor_known)


@app.post("/api/network/scan")
async def net_scan(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    target = b.get("target") or discovery.local_ip()
    args = b.get("arguments")  # None -> default -T4 -F -Pn --open
    result = await asyncio.to_thread(netscanner.scan_target, target, args)
    # persist open ports on the device record if we know it
    if result.get("ports"):
        db.execute("UPDATE devices SET open_ports = ?, last_seen = ? WHERE ip = ?",
                   (db.dumps(result["ports"]), db.now(), target))
    return result


async def _has_body(request: Request) -> bool:
    try:
        return bool(await request.body())
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Endpoint logs (Windows Event Log) + Event ID glossary
# --------------------------------------------------------------------------- #
@app.get("/api/eventids")
def event_id_glossary(user: dict = Depends(require_user)):
    """The Event ID knowledge base used for the hover tooltips."""
    return {"event_ids": {str(k): v for k, v in EVENT_IDS.items()}}


@app.get("/api/logs")
def endpoint_logs(user: dict = Depends(require_user), host: str = "",
                  category: str = "", limit: int = 200):
    """Device/endpoint security log: events carrying an event code, or coming
    from the OS log / agent / auth sources. Each row is enriched with the
    knowledge-base meaning for its code."""
    src_filter = "source IN ('winlog','syslog','agent','auth')"
    sql = ("SELECT id, ts, source, host, category, severity, message, src_ip, user, "
           f"event_id, provider, count, last_ts FROM events WHERE (event_id IS NOT NULL OR {src_filter})")
    params: list[Any] = []
    if host:
        sql += " AND host = ?"; params.append(host)
    if category:
        sql += " AND category = ?"; params.append(category)
    sql += " ORDER BY ts DESC LIMIT ?"; params.append(min(limit, 500))
    rows = db.query(sql, params)
    for r in rows:
        if r.get("event_id") is not None:
            r["meta"] = describe(r["event_id"])
    hosts = db.query(f"SELECT DISTINCT host FROM events WHERE host IS NOT NULL "
                     f"AND (event_id IS NOT NULL OR {src_filter}) ORDER BY host")
    return {"logs": rows, "hosts": [h["host"] for h in hosts],
            "collector": {"available": os_log_collector.available,
                          "source": "Windows Event Log" if os_log_collector is winevent_collector else "Linux syslog/journald",
                          "last_run": os_log_collector.last_run,
                          "ingested": os_log_collector.total_ingested}}


@app.post("/api/logs/pull")
async def pull_winlog(user: dict = Depends(require_user)):
    return await asyncio.to_thread(os_log_collector.pull, 3600, 200)


# --------------------------------------------------------------------------- #
# Network telemetry (interfaces, throughput/packets, connections, quality)
# --------------------------------------------------------------------------- #
@app.get("/api/net/interfaces")
def net_interfaces(user: dict = Depends(require_user)):
    return net_telemetry.interfaces()


@app.get("/api/net/throughput")
def net_throughput(user: dict = Depends(require_user)):
    return net_telemetry.throughput()


@app.get("/api/net/connections")
def net_connections(user: dict = Depends(require_user), limit: int = 200):
    return net_telemetry.connections(limit)


@app.get("/api/net/quality")
def net_quality(user: dict = Depends(require_user)):
    return net_telemetry.link_quality()


# --------------------------------------------------------------------------- #
# Blocklist (IPS)
# --------------------------------------------------------------------------- #
@app.get("/api/blocklist")
def get_blocklist(user: dict = Depends(require_user)):
    return {"blocklist": db.query("SELECT * FROM blocklist ORDER BY ts DESC")}


@app.post("/api/blocklist")
async def add_block(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    block_indicator(b.get("indicator", ""), b.get("kind", "ip"),
                    b.get("reason", "Manually blocked by analyst"), "manual")
    return {"ok": True}


@app.delete("/api/blocklist/{block_id}")
async def remove_block(block_id: int, user: dict = Depends(require_user)):
    db.execute("UPDATE blocklist SET active = 0 WHERE id = ?", (block_id,))
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Agents
# --------------------------------------------------------------------------- #
@app.get("/api/agents")
def get_agents(user: dict = Depends(require_user)):
    agents = db.query("SELECT * FROM agents ORDER BY status DESC, hostname")
    for a in agents:
        a["metrics"] = db.loads(a.get("metrics"), {})
    return {"agents": agents}


@app.post("/api/agent/enroll")
async def agent_enroll(request: Request):
    require_agent(request)
    b = await request.json()
    return agent_registry.enroll(b.get("hostname", "unknown"), b.get("os_info", ""),
                                 b.get("ip", request.client.host if request.client else ""),
                                 b.get("version", "1.0"))


@app.post("/api/agent/heartbeat")
async def agent_heartbeat(request: Request):
    require_agent(request)
    b = await request.json()
    return agent_registry.heartbeat(b.get("agent_id", ""), b.get("metrics", {}), b.get("events", []))


# --------------------------------------------------------------------------- #
# Forensics · audit-chain integrity
# --------------------------------------------------------------------------- #
@app.get("/api/forensics/integrity")
def forensics_integrity(user: dict = Depends(require_user)):
    return integrity.verify()


# --------------------------------------------------------------------------- #
# Forensics · evidence backups & exports
# --------------------------------------------------------------------------- #
@app.get("/api/forensics/artifacts")
def forensics_artifacts(user: dict = Depends(require_user), kind: str = ""):
    return {"artifacts": backup.list_artifacts(kind),
            "evidence_dir": str(settings.EVIDENCE_DIR),
            "chain_head": integrity.head(),
            "backup_last_run": backup.backup_service.last_run}


@app.post("/api/forensics/backup")
async def forensics_backup(user: dict = Depends(require_user)):
    return await asyncio.to_thread(backup.run_backup, 0, "manual")


@app.post("/api/forensics/export")
async def forensics_export(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return await asyncio.to_thread(
        lambda: backup.export_events(severity=int(b.get("severity", 0) or 0),
                                     category=b.get("category", ""),
                                     source=b.get("source", ""), q=b.get("q", "")))


@app.get("/api/forensics/artifacts/{aid}/verify")
def forensics_verify_artifact(aid: int, user: dict = Depends(require_user)):
    return backup.verify_artifact(aid)


@app.get("/api/forensics/artifacts/{aid}/download")
def forensics_download(aid: int, user: dict = Depends(require_user)):
    a = db.query_one("SELECT * FROM artifacts WHERE id = ?", (aid,))
    if not a or not Path(a["path"]).exists():
        raise HTTPException(404, "artifact file not found")
    return FileResponse(a["path"], filename=a["name"], media_type="application/gzip")


@app.delete("/api/forensics/artifacts/{aid}")
def forensics_delete_artifact(aid: int, user: dict = Depends(require_user)):
    backup.delete_artifact(aid)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Forensics · host triage snapshot
# --------------------------------------------------------------------------- #
@app.post("/api/forensics/triage")
async def forensics_triage(user: dict = Depends(require_user)):
    return await asyncio.to_thread(triage.collect, "manual")


# --------------------------------------------------------------------------- #
# IOC watchlist
# --------------------------------------------------------------------------- #
@app.get("/api/iocs")
def list_iocs_ep(user: dict = Depends(require_user)):
    return {"iocs": iocs.list_iocs()}


@app.post("/api/iocs")
async def add_ioc_ep(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return iocs.add_ioc(b.get("kind", "ip"), b.get("value", ""),
                        int(b.get("severity", 4)), b.get("source", "manual"), b.get("note", ""))


@app.post("/api/iocs/import")
async def import_iocs_ep(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return iocs.import_bulk(b.get("text", ""), b.get("kind", "auto"))


@app.patch("/api/iocs/{iid}")
async def toggle_ioc_ep(iid: int, request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    iocs.set_active(iid, bool(b.get("active")))
    return {"ok": True}


@app.delete("/api/iocs/{iid}")
def delete_ioc_ep(iid: int, user: dict = Depends(require_user)):
    iocs.delete_ioc(iid)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Investigation cases
# --------------------------------------------------------------------------- #
@app.get("/api/cases")
def list_cases_ep(user: dict = Depends(require_user), status: str = ""):
    return {"cases": casemgr.list_cases(status)}


@app.post("/api/cases")
async def create_case_ep(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return casemgr.create_case(b.get("title", "Untitled case"), int(b.get("severity", 3)),
                               b.get("assignee", ""), b.get("summary", ""))


@app.get("/api/cases/{cid}")
def get_case_ep(cid: int, user: dict = Depends(require_user)):
    c = casemgr.get_case(cid)
    if not c:
        raise HTTPException(404, "case not found")
    return c


@app.patch("/api/cases/{cid}")
async def update_case_ep(cid: int, request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    casemgr.update_case(cid, **{k: b[k] for k in ("title", "status", "severity", "assignee", "summary") if k in b})
    return {"ok": True}


@app.post("/api/cases/{cid}/items")
async def add_case_item_ep(cid: int, request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return casemgr.add_item(cid, b.get("kind", "note"), b.get("ref_id", ""),
                            b.get("title", ""), b.get("note", ""),
                            user.get("sub", "analyst"), b.get("data"))


@app.delete("/api/cases/items/{item_id}")
def delete_case_item_ep(item_id: int, user: dict = Depends(require_user)):
    casemgr.delete_item(item_id)
    return {"ok": True}


@app.post("/api/cases/{cid}/export")
async def export_case_ep(cid: int, user: dict = Depends(require_user)):
    return await asyncio.to_thread(casemgr.export_bundle, cid)


# --------------------------------------------------------------------------- #
# Entity timeline
# --------------------------------------------------------------------------- #
@app.get("/api/timeline")
def timeline_ep(user: dict = Depends(require_user), entity: str = ""):
    return timeline.entity_timeline(entity)


# --------------------------------------------------------------------------- #
# AI analyst (built-in, offline)
# --------------------------------------------------------------------------- #
@app.get("/api/ai/status")
def ai_status(user: dict = Depends(require_user)):
    return ai.status()


@app.post("/api/ai/ask")
async def ai_ask(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return await asyncio.to_thread(ai.answer, b.get("question", ""))


@app.get("/api/ai/insights")
def ai_insights(user: dict = Depends(require_user)):
    return ai.insights()


@app.post("/api/ai/explain")
async def ai_explain(request: Request, user: dict = Depends(require_user)):
    b = await request.json()
    return await asyncio.to_thread(ai.explain, b.get("kind", "event"), int(b.get("id")))


# --------------------------------------------------------------------------- #
# System / health
# --------------------------------------------------------------------------- #
@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version, "time": db.now(),
            "virustotal": settings.virustotal_enabled, "nmap": netscanner.nmap_available()}


# --------------------------------------------------------------------------- #
# WebSocket live stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def ws_stream(ws: WebSocket):
    token = ws.query_params.get("token", "")
    # cookie fallback
    if not token:
        cookie = ws.cookies.get("argus_token", "")
        token = cookie
    if not verify_token(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    q = bus.subscribe()
    try:
        await ws.send_json({"type": "hello", "data": {"msg": "connected to Argus live feed"}})
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(q)
