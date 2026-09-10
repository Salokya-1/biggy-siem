"""Biggy's built-in AI analyst — a self-contained reasoning engine.

No external LLM, no model download, no cloud: this runs entirely offline on the
standard library. It combines three things:

  * a natural-language Q&A router that answers questions from live SIEM data,
  * an unsupervised anomaly model (statistical, per-entity) that surfaces the
    unusual out of the normal, and
  * a triage/explain generator that turns one event or alert into a plain-English
    assessment with reasoning and recommended actions.

It is deterministic and instant, and it is honest about what it is: an expert
analyst engine grounded in your data, not a neural network.
"""
from __future__ import annotations

import re
import statistics
import time
from typing import Any, Optional

from . import database as db
from .config import settings
from .integrations import virustotal as vt
from .knowledge import describe

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b")
URL_RE = re.compile(r"https?://[^\s\"']+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
SEV_WORD = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def status() -> dict[str, Any]:
    return {
        "available": True,
        "engine": "Biggy Analyst",
        "kind": "built-in · offline",
        "note": "Self-contained reasoning engine. No external LLM or model download required.",
        "virustotal": settings.virustotal_enabled,
    }


# --------------------------------------------------------------------------- #
# small data helpers
# --------------------------------------------------------------------------- #
def _counts(hours: int = 24) -> dict[str, Any]:
    since = time.time() - hours * 3600
    ev = db.query("SELECT severity, COUNT(*) c FROM events WHERE ts >= ? GROUP BY severity", (since,))
    sev = {r["severity"]: r["c"] for r in ev}
    return {
        "events": sum(sev.values()),
        "sev": sev,
        "critical": sev.get(5, 0), "high": sev.get(4, 0),
        "open_alerts": db.query_one("SELECT COUNT(*) c FROM alerts WHERE status='open'")["c"],
        "blocked": db.query_one("SELECT COUNT(*) c FROM blocklist WHERE active=1")["c"],
        "devices": db.query_one("SELECT COUNT(*) c FROM devices")["c"],
        "down": db.query_one("SELECT COUNT(*) c FROM devices WHERE status='down'")["c"],
        "agents": db.query_one("SELECT COUNT(*) c FROM agents WHERE status='active'")["c"],
        "malware": db.query_one("SELECT COUNT(*) c FROM scans WHERE kind='file' AND verdict='malicious'")["c"],
    }


def _top_categories(hours: int = 24, n: int = 4) -> list[dict]:
    since = time.time() - hours * 3600
    return db.query("SELECT category, COUNT(*) c FROM events WHERE ts >= ? "
                    "GROUP BY category ORDER BY c DESC LIMIT ?", (since, n))


def _fmt_ago(ts: float) -> str:
    s = time.time() - ts
    if s < 60: return f"{int(s)}s ago"
    if s < 3600: return f"{int(s/60)}m ago"
    if s < 86400: return f"{int(s/3600)}h ago"
    return f"{int(s/86400)}d ago"


_NOT_DOMAIN = (".exe", ".dll", ".py", ".txt", ".log", ".gz", ".zip", ".pdf",
               ".doc", ".docx", ".png", ".jpg", ".scr", ".bat", ".ps1")


def _first_domain(q: str):
    for m in DOMAIN_RE.finditer(q):
        d = m.group(0).lower()
        if not IPV4.fullmatch(d) and not d.endswith(_NOT_DOMAIN):
            return d
    return None


def _is_public_ip(ip: str) -> bool:
    return bool(IPV4.fullmatch(ip or "")) and not ip.startswith(("10.", "127.", "192.168.", "169.254.")) \
        and not re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)


def _vt_report(indicator: str, kind: str) -> dict[str, Any]:
    """Scan one indicator against VirusTotal and format the verdict + advice."""
    label = {"hash": "file hash", "ip": "IP address", "domain": "domain", "url": "URL"}[kind]
    if not settings.virustotal_enabled:
        return {"intent": "vt", "answer":
                f"VirusTotal isn't configured, so I can't scan the {label} **{indicator}** against the "
                f"cloud. Add `VIRUSTOTAL_API_KEY` to `.env` to enable it. I can still check your local "
                f"data \u2014 ask \u201ctell me about {indicator}\u201d."}
    fn = {"hash": vt.lookup_hash_sync, "ip": vt.lookup_ip_sync,
          "domain": vt.lookup_domain_sync, "url": vt.lookup_url_sync}[kind]
    r = fn(indicator)
    v = r.get("verdict")
    lines = [f"**VirusTotal scan** of the {label} `{indicator}`:"]
    if r.get("total"):
        lines.append(f"Verdict: **{v}** \u2014 {r['positives']}/{r['total']} engines flagged it.")
    elif v and v != "error":
        lines.append(f"Verdict: **{v}**.")
    if r.get("threat_label"):
        lines.append(f"Threat label: {r['threat_label']}.")
    if r.get("names"):
        lines.append("Also seen as: " + ", ".join(r["names"][:4]) + ".")
    if r.get("reputation") is not None:
        lines.append(f"Community reputation score: {r['reputation']}.")
    if r.get("message") and (not r.get("total")):
        lines.append(r["message"])
    if v == "malicious":
        if kind == "ip":
            lines.append(f"\u25b8 Recommend: block {indicator} now (Active Response) and add it to the IOC watchlist.")
        elif kind == "hash":
            lines.append("\u25b8 Recommend: quarantine and isolate any host with this file; add the hash to the watchlist.")
        else:
            lines.append(f"\u25b8 Recommend: block access to {indicator} and hunt for hosts that reached it.")
    elif v == "suspicious":
        lines.append("\u25b8 A couple of engines flagged it \u2014 treat with caution and corroborate before acting.")
    elif v == "clean":
        lines.append("\u25b8 No engines flagged it. Looks clean (though clean \u2260 guaranteed safe).")
    if r.get("cached"):
        lines.append("_(cached VirusTotal result)_")
    return {"intent": "vt", "answer": "\n".join(lines), "vt": r, "indicator": indicator, "kind": kind}


def _vt_scan_latest_file() -> dict[str, Any]:
    row = (db.query_one("SELECT target, sha256 FROM scans WHERE kind='file' AND sha256 IS NOT NULL "
                        "AND verdict IN ('malicious','suspicious') ORDER BY ts DESC LIMIT 1")
           or db.query_one("SELECT target, sha256 FROM scans WHERE kind='file' AND sha256 IS NOT NULL "
                           "ORDER BY ts DESC LIMIT 1"))
    if not row or not row.get("sha256"):
        return {"intent": "vt", "answer": "I don't have a scanned file with a hash on record yet. Scan a "
                "file in the Malware Scanner, or paste a SHA-256 here and I'll check it on VirusTotal."}
    rep = _vt_report(row["sha256"], "hash")
    name = (row["target"] or "").split("\\")[-1].split("/")[-1]
    rep["answer"] = f"Checking the most recent scanned file **{name}** on VirusTotal:\n" + rep["answer"]
    return rep


# --------------------------------------------------------------------------- #
# 1. Natural-language Q&A
# --------------------------------------------------------------------------- #
def answer(question: str) -> dict[str, Any]:
    q = (question or "").strip()
    ql = q.lower()
    if not ql:
        return {"answer": "Ask me about your events, alerts, an IP, malware, the network, or type "
                          "\u201chelp\u201d to see what I can do.", "intent": "empty"}

    def has(*words): return any(w in ql for w in words)

    # ---- VirusTotal scan intent (IP / file hash / domain / URL) ----
    vt_intent = has("scan", "virustotal", " vt", "reputation", "malicious?",
                    "is it safe", "is this safe", "look up", "lookup", "analyse", "analyze", "threat intel")
    hashm, urlm, ipm = HASH_RE.search(q), URL_RE.search(q), IPV4.search(q)
    if hashm:                                   # a hash is an unambiguous scan target
        return _vt_report(hashm.group(0), "hash")
    if vt_intent and urlm:
        return _vt_report(urlm.group(0), "url")
    if vt_intent and ipm:
        return _vt_report(ipm.group(0), "ip")
    if vt_intent and ("file" in ql or "malware" in ql):
        return _vt_scan_latest_file()
    if vt_intent and not ipm and not urlm:
        dom = _first_domain(q)
        if dom:
            return _vt_report(dom, "domain")

    # entity lookup if an IP is present (local activity, enriched with VT)
    if ipm:
        return _entity_report(ipm.group(0))

    if has("help", "what can you", "commands", "capabilities"):
        return {"intent": "help", "answer": _help_text()}
    if has("brute", "failed login", "password guess", "bruteforce"):
        return _brute_report()
    if has("malware", "virus", "malicious", "infected", "file scan", "trojan", "ransom"):
        return _malware_report()
    if has("network", "device", "asset", "port", "nmap", "subnet", "open port"):
        return _network_report()
    if has("agent", "endpoint", "host telemetry", "cpu", "which machines"):
        return _agent_report()
    if has("block", "ioc", "watchlist", "contain", "quarantin"):
        return _containment_report()
    if has("alert", "threat", "risk", "worst", "top", "priority", "urgent"):
        return _threat_report()
    if has("summary", "summarise", "summarize", "overview", "posture", "last 24", "happening",
           "status", "brief", "how are we", "sitrep"):
        return _summary_report()

    # fallback: keyword search over recent events
    return _search_report(q)


def _help_text() -> str:
    return ("I'm Biggy's built-in analyst. Try asking:\n"
            "\u2022 \u201cSummarise the last 24 hours\u201d\n"
            "\u2022 \u201cWhat are my top threats?\u201d\n"
            "\u2022 \u201cAny brute force activity?\u201d\n"
            "\u2022 \u201cTell me about 45.146.164.12\u201d (any IP)\n"
            "\u2022 \u201cScan 8.8.8.8 with VirusTotal\u201d (IP / domain / URL / file hash)\n"
            "\u2022 \u201cCheck this hash <sha256>\u201d or \u201cscan the latest file\u201d\n"
            "\u2022 \u201cWhat's on my network?\u201d  \u2022  \u201cWhat have we blocked?\u201d\n"
            "You can also click \u201cExplain with AI\u201d on any event or alert.")


def _summary_report() -> dict[str, Any]:
    c = _counts()
    cats = _top_categories()
    lines = [f"In the last 24h I processed **{c['events']} events**: "
             f"{c['critical']} critical, {c['high']} high."]
    if c["open_alerts"]:
        lines.append(f"There are **{c['open_alerts']} open alert(s)** awaiting triage"
                     + (f", {c['critical']} critical" if c['critical'] else "") + ".")
    else:
        lines.append("No open alerts \u2014 the queue is clear.")
    if cats:
        lines.append("Busiest categories: " + ", ".join(f"{r['category']} ({r['c']})" for r in cats) + ".")
    lines.append(f"Assets: {c['devices']} known ({c['down']} offline). "
                 f"Active agents: {c['agents']}. Contained indicators: {c['blocked']}. "
                 f"Malicious files found: {c['malware']}.")
    # lead with the single most urgent thing
    top = db.query_one("SELECT title, entity, severity, ts FROM alerts WHERE status='open' "
                       "ORDER BY severity DESC, ts DESC LIMIT 1")
    if top:
        lines.append(f"\u26a0 Most urgent: **{top['title']}** on {top['entity'] or 'an entity'} "
                     f"({SEV_WORD.get(top['severity'],'?')}, {_fmt_ago(top['ts'])}).")
    return {"intent": "summary", "answer": "\n".join(lines)}


def _threat_report() -> dict[str, Any]:
    alerts = db.query("SELECT * FROM alerts WHERE status='open' ORDER BY severity DESC, ts DESC LIMIT 6")
    if not alerts:
        return {"intent": "threats", "answer": "No open alerts right now. Nothing is demanding attention."}
    lines = [f"Your top {len(alerts)} open threat(s), most severe first:"]
    for a in alerts:
        mitre = f" [{a['mitre']}]" if a.get("mitre") else ""
        lines.append(f"\u2022 **{a['title']}**{mitre} \u2014 {a['entity'] or 'n/a'} "
                     f"({SEV_WORD.get(a['severity'],'?')}, {_fmt_ago(a['ts'])})")
    lines.append("Ask me to \u201cexplain\u201d any of these, or open a case from the Alerts view.")
    return {"intent": "threats", "answer": "\n".join(lines)}


def _brute_report() -> dict[str, Any]:
    since = time.time() - 24 * 3600
    rows = db.query("SELECT src_ip, COUNT(*) c, SUM(count) tot FROM events "
                    "WHERE ts >= ? AND lower(message) LIKE '%failed log%' AND src_ip IS NOT NULL "
                    "GROUP BY src_ip ORDER BY tot DESC LIMIT 6", (since,))
    if not rows:
        return {"intent": "brute", "answer": "No failed-logon activity in the last 24h \u2014 no brute-force signs."}
    lines = ["Failed-logon sources in the last 24h (possible brute force):"]
    for r in rows:
        n = r["tot"] or r["c"]
        blocked = db.query_one("SELECT 1 FROM blocklist WHERE indicator=? AND active=1", (r["src_ip"],))
        tag = " \u2014 already blocked \u2713" if blocked else " \u2014 not blocked"
        flag = " \u26a0" if n >= 5 else ""
        lines.append(f"\u2022 **{r['src_ip']}**: {n} failed attempt(s){flag}{tag}")
    lines.append("Sources with 5+ attempts fit the SSH/RDP brute-force pattern (ATT&CK T1110).")
    return {"intent": "brute", "answer": "\n".join(lines)}


def _malware_report() -> dict[str, Any]:
    scans = db.query("SELECT target, verdict, positives, total, ts FROM scans "
                     "WHERE verdict IN ('malicious','suspicious') ORDER BY ts DESC LIMIT 6")
    mal = db.query_one("SELECT COUNT(*) c FROM scans WHERE verdict='malicious'")["c"]
    if not scans:
        return {"intent": "malware", "answer": "No malicious or suspicious files found in any scan so far."}
    lines = [f"{mal} malicious verdict(s) on record. Most recent flagged files:"]
    for s in scans:
        name = (s["target"] or "").split("\\")[-1].split("/")[-1]
        vt = f" ({s['positives']}/{s['total']})" if s.get("total") else ""
        lines.append(f"\u2022 **{name}** \u2014 {s['verdict']}{vt}, {_fmt_ago(s['ts'])}")
    lines.append("Open the Malware Scanner to quarantine or re-scan, or add a hash to the IOC watchlist.")
    return {"intent": "malware", "answer": "\n".join(lines)}


def _network_report() -> dict[str, Any]:
    d = db.query_one("SELECT COUNT(*) c, SUM(status='up') up FROM devices") or {}
    risky = db.query("SELECT target, positives, ts FROM scans WHERE kind='network' AND verdict='risky' "
                     "ORDER BY ts DESC LIMIT 5")
    lines = [f"I know of **{d.get('c',0)} device(s)** on the network ({d.get('up',0) or 0} up)."]
    if risky:
        lines.append("Hosts with risky exposed services:")
        for r in risky:
            lines.append(f"\u2022 {r['target']} \u2014 {r['positives']} risky port(s), {_fmt_ago(r['ts'])}")
    else:
        lines.append("No risky exposed services flagged in recent port scans.")
    lines.append("Run discovery or a port scan from the Network view for a fresh sweep.")
    return {"intent": "network", "answer": "\n".join(lines)}


def _agent_report() -> dict[str, Any]:
    agents = db.query("SELECT hostname, ip, status, last_seen, metrics FROM agents ORDER BY status DESC LIMIT 8")
    if not agents:
        return {"intent": "agents", "answer": "No host agents are enrolled yet. Deploy one from the Host Agents view."}
    lines = [f"{sum(1 for a in agents if a['status']=='active')} active agent(s):"]
    for a in agents:
        m = db.loads(a.get("metrics"), {})
        cpu = f", CPU {m.get('cpu_percent')}%" if m.get("cpu_percent") is not None else ""
        lines.append(f"\u2022 **{a['hostname']}** ({a['ip'] or '?'}) \u2014 {a['status']}{cpu}, seen {_fmt_ago(a['last_seen'])}")
    return {"intent": "agents", "answer": "\n".join(lines)}


def _containment_report() -> dict[str, Any]:
    bl = db.query("SELECT indicator, kind, reason, ts FROM blocklist WHERE active=1 ORDER BY ts DESC LIMIT 8")
    iocs = db.query_one("SELECT COUNT(*) c FROM iocs WHERE active=1")
    if not bl:
        return {"intent": "contain", "answer": "Nothing is currently blocked. "
                f"{iocs['c'] if iocs else 0} IOC(s) are on the watchlist."}
    lines = [f"**{len(bl)} active block(s)**" + (f" and {iocs['c']} watchlist IOC(s)" if iocs else "") + ":"]
    for b in bl:
        lines.append(f"\u2022 {b['indicator']} ({b['kind']}) \u2014 {b['reason'] or 'manual'}, {_fmt_ago(b['ts'])}")
    return {"intent": "contain", "answer": "\n".join(lines)}


def _entity_report(entity: str) -> dict[str, Any]:
    like = f"%{entity}%"
    evs = db.query("SELECT ts, severity, category, message, source FROM events "
                   "WHERE src_ip=? OR dst_ip=? OR host=? OR message LIKE ? "
                   "ORDER BY ts DESC LIMIT 8", (entity, entity, entity, like))
    if not evs:
        # no local trace — but for a public IP, VirusTotal may still know it
        if _is_public_ip(entity) and settings.virustotal_enabled:
            rep = _vt_report(entity, "ip")
            rep["answer"] = f"No local records involve **{entity}**, but here's its VirusTotal reputation:\n" + rep["answer"]
            return rep
        return {"intent": "entity", "answer": f"I have no records involving **{entity}**."}
    alerts = db.query("SELECT title, severity FROM alerts WHERE entity=? ORDER BY ts DESC LIMIT 4", (entity,))
    blocked = db.query_one("SELECT reason FROM blocklist WHERE indicator=? AND active=1", (entity,))
    total = db.query_one("SELECT COUNT(*) c FROM events WHERE src_ip=? OR dst_ip=? OR host=? OR message LIKE ?",
                         (entity, entity, entity, like))["c"]
    maxsev = max((e["severity"] for e in evs), default=1)
    lines = [f"**{entity}** \u2014 {total} related event(s), peak severity {SEV_WORD.get(maxsev,'?')}."]
    if blocked:
        lines.append(f"\U0001f6ab Currently blocked: {blocked['reason']}.")
    if alerts:
        lines.append("Alerts: " + "; ".join(f"{a['title']} ({SEV_WORD.get(a['severity'],'?')})" for a in alerts))
    lines.append("Recent activity:")
    for e in evs[:6]:
        lines.append(f"\u2022 {_fmt_ago(e['ts'])} [{SEV_WORD.get(e['severity'],'?')}] {e['message'][:90]}")
    # VirusTotal reputation for public IPs
    if _is_public_ip(entity) and settings.virustotal_enabled:
        vr = vt.lookup_ip_sync(entity)
        if vr.get("total"):
            lines.append(f"VirusTotal: **{vr['verdict']}** ({vr['positives']}/{vr['total']} engines)"
                         + (f" \u2014 {vr['threat_label']}" if vr.get("threat_label") else "") + ".")
    # verdict
    if maxsev >= 4 or blocked or alerts:
        lines.append("\u25b8 Assessment: this entity shows hostile or high-risk behaviour. "
                     "Consider blocking it (if not already) and opening a case.")
    else:
        lines.append("\u25b8 Assessment: activity looks routine so far.")
    return {"intent": "entity", "answer": "\n".join(lines), "entity": entity}


def _search_report(q: str) -> dict[str, Any]:
    like = f"%{q}%"
    evs = db.query("SELECT ts, severity, message FROM events WHERE message LIKE ? ORDER BY ts DESC LIMIT 6", (like,))
    if not evs:
        return {"intent": "search",
                "answer": f"I couldn't find anything matching \u201c{q}\u201d. Type \u201chelp\u201d to see what I can answer."}
    lines = [f"{len(evs)} event(s) mentioning \u201c{q}\u201d:"]
    for e in evs:
        lines.append(f"\u2022 {_fmt_ago(e['ts'])} [{SEV_WORD.get(e['severity'],'?')}] {e['message'][:90]}")
    return {"intent": "search", "answer": "\n".join(lines)}


# --------------------------------------------------------------------------- #
# 2. Anomaly model (unsupervised, statistical, per-entity)
# --------------------------------------------------------------------------- #
def insights(hours: int = 24) -> dict[str, Any]:
    """Surface the unusual: volume spikes, noisy/new sources, failed-login ratios."""
    since = time.time() - hours * 3600
    findings: list[dict] = []

    # (a) hourly volume spike via z-score over the window
    rows = db.query("SELECT CAST((? - ts)/3600 AS INT) h, COUNT(*) c FROM events "
                    "WHERE ts >= ? GROUP BY h", (time.time(), since))
    counts = [r["c"] for r in rows]
    if len(counts) >= 4:
        mean = statistics.mean(counts); sd = statistics.pstdev(counts) or 1
        peak = max(rows, key=lambda r: r["c"])
        z = (peak["c"] - mean) / sd
        if z >= 2.2 and peak["c"] >= 8:
            findings.append({"severity": 4, "title": "Event-volume spike",
                             "detail": f"A one-hour burst of {peak['c']} events ({z:.1f}\u03c3 above the "
                                       f"{mean:.0f}/h baseline) \u2014 investigate that window."})

    # (b) top talkers with a hostile signature
    talkers = db.query("SELECT src_ip, COUNT(*) c, SUM(count) tot, MAX(severity) ms, "
                       "SUM(lower(message) LIKE '%failed log%') fails FROM events "
                       "WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
                       "GROUP BY src_ip ORDER BY tot DESC LIMIT 20", (since,))
    for t in talkers:
        n = t["tot"] or t["c"]
        score = 0
        why = []
        if t["fails"] and t["fails"] >= 5:
            score += 40; why.append(f"{t['fails']} failed logons")
        if t["ms"] and t["ms"] >= 4:
            score += 25; why.append(f"peak severity {SEV_WORD.get(t['ms'])}")
        if n >= 20:
            score += 15; why.append(f"{n} events")
        if score >= 40:
            blocked = db.query_one("SELECT 1 FROM blocklist WHERE indicator=? AND active=1", (t["src_ip"],))
            findings.append({"severity": 5 if score >= 60 else 4,
                             "title": f"Suspicious source {t['src_ip']}",
                             "detail": ", ".join(why) + ("" if blocked else " \u2014 not yet blocked"),
                             "entity": t["src_ip"], "score": min(score, 100)})

    # (c) new sources first seen recently
    recent_since = time.time() - min(hours, 3) * 3600
    new_ips = db.query(
        "SELECT DISTINCT src_ip FROM events WHERE ts >= ? AND src_ip IS NOT NULL AND src_ip != '' "
        "AND src_ip NOT IN (SELECT src_ip FROM events WHERE ts < ? AND src_ip IS NOT NULL) LIMIT 5",
        (recent_since, recent_since))
    for r in new_ips:
        if not r["src_ip"].startswith(("10.", "192.168.", "127.")):
            findings.append({"severity": 3, "title": f"New external source {r['src_ip']}",
                             "detail": "First observed in the recent window \u2014 worth a reputation check.",
                             "entity": r["src_ip"]})

    findings.sort(key=lambda f: (-f["severity"], -f.get("score", 0)))
    if not findings:
        findings.append({"severity": 1, "title": "Nothing anomalous",
                         "detail": "Traffic and authentication patterns look within normal range."})
    return {"findings": findings[:8], "window_hours": hours,
            "model": "per-entity statistical anomaly detection (z-score + weighted signals)"}


# --------------------------------------------------------------------------- #
# 3. Explain / triage a single event or alert
# --------------------------------------------------------------------------- #
def explain(kind: str, rec_id: int) -> dict[str, Any]:
    if kind == "alert":
        r = db.query_one("SELECT * FROM alerts WHERE id=?", (rec_id,))
        if not r:
            return {"text": "That alert no longer exists."}
        entity = r.get("entity"); sev = r["severity"]; title = r["title"]
        mitre = r.get("mitre"); msg = r.get("description") or title
        source = f"rule {r.get('rule_id')}"
    else:
        r = db.query_one("SELECT * FROM events WHERE id=?", (rec_id,))
        if not r:
            return {"text": "That event no longer exists."}
        entity = r.get("src_ip") or r.get("host") or r.get("user"); sev = r["severity"]
        title = r["message"]; source = r.get("source"); msg = r["message"]
        meta = describe(r["event_id"]) if r.get("event_id") is not None else None
        mitre = meta.get("mitre") if meta else None

    sevw = SEV_WORD.get(sev, "medium")
    lines = [f"**What it is** \u2014 {title}."]
    if kind == "event" and r.get("event_id") is not None:
        m = describe(r["event_id"])
        lines[0] = f"**What it is** \u2014 {m['name']} (code {r['event_id']}). {m['hint']}"
    lines.append(f"**Severity** \u2014 {sevw}" + (f", mapped to ATT&CK {mitre}" if mitre else "") + ".")

    # context: related activity for the entity
    if entity:
        rel = db.query_one("SELECT COUNT(*) c, MAX(severity) ms FROM events "
                           "WHERE src_ip=? OR host=? OR user=?", (entity, entity, entity))
        blocked = db.query_one("SELECT 1 FROM blocklist WHERE indicator=? AND active=1", (entity,))
        ctx = f"**Context** \u2014 {entity} appears in {rel['c']} event(s)"
        if rel["ms"] and rel["ms"] >= 4:
            ctx += f", peaking at {SEV_WORD.get(rel['ms'])} severity"
        ctx += ". It is already blocked." if blocked else "."
        lines.append(ctx)

    # recommended actions by category / severity
    actions = _recommend(r, kind, entity, sev)
    if actions:
        lines.append("**Recommended actions:**\n" + "\n".join(f"  {i}. {a}" for i, a in enumerate(actions, 1)))
    return {"text": "\n".join(lines), "entity": entity}


def _recommend(r: dict, kind: str, entity: Optional[str], sev: int) -> list[str]:
    cat = (r.get("category") or "").lower()
    title = (r.get("title") or r.get("message") or "").lower()
    acts: list[str] = []
    is_ip = bool(entity and IPV4.fullmatch(entity or ""))
    if "brute" in title or "failed log" in title or cat == "authentication":
        if is_ip: acts.append(f"Block {entity} at the firewall / add to the blocklist.")
        acts.append("Confirm the targeted account isn't compromised; force a password reset if in doubt.")
        acts.append("Verify MFA is enforced on the exposed service (RDP/SSH).")
    if "malware" in cat or "malicious" in title or "ransom" in title:
        acts.append("Quarantine the file and isolate the host from the network.")
        acts.append("Check the file hash on the Threat Intel (VirusTotal) view and add it to the IOC watchlist.")
    if cat in ("network", "discovery") or "port scan" in title:
        if is_ip: acts.append(f"Block {entity} if the scan is unsolicited.")
        acts.append("Review the risky exposed ports and close or firewall anything unnecessary.")
    if "audit log cleared" in title or "1102" in title:
        acts.append("Treat as high priority \u2014 log clearing often follows compromise; preserve a triage snapshot now.")
    if sev >= 4:
        acts.append("Open a case and attach this record for chain-of-custody.")
    if not acts:
        acts.append("Monitor for repeat occurrences; escalate if the pattern grows.")
    return acts[:5]
