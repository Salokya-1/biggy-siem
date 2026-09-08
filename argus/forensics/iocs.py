"""Indicator-of-Compromise (IOC) watchlist.

Analysts add indicators (IPs, file hashes, domains, URLs, usernames, file paths)
seen in threat intel or a prior incident. Every ingested event is matched against
the active watchlist; a hit raises an alert (and auto-blocks IP indicators),
increments the indicator's hit counter, and feeds the timeline. IOCs are cached
in memory and matching is a cheap set/substring test, so it stays fast under load.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .. import database as db
from ..core.bus import bus
from ..core.detection import SEVERITY_LABELS, block_indicator

_cache: list[dict] | None = None
_cache_ts = 0.0
_TTL = 5.0
_lock = threading.Lock()

EXACT_KINDS = {"ip", "user"}        # match on exact field equality
SUBSTR_KINDS = {"hash", "domain", "url", "file"}  # match anywhere in the event text


def _invalidate() -> None:
    global _cache
    with _lock:
        _cache = None


def active_iocs() -> list[dict]:
    global _cache, _cache_ts
    now = time.time()
    with _lock:
        if _cache is None or (now - _cache_ts) > _TTL:
            _cache = db.query("SELECT * FROM iocs WHERE active = 1")
            _cache_ts = now
        return _cache


def _haystack(event: dict) -> str:
    return " ".join(str(event.get(k, "") or "") for k in
                    ("message", "src_ip", "dst_ip", "user", "host")).lower()


def match(event: dict, event_id: int | None) -> list[dict]:
    iocs = active_iocs()
    if not iocs:
        return []
    hay = _haystack(event)
    src = str(event.get("src_ip") or "")
    dst = str(event.get("dst_ip") or "")
    usr = str(event.get("user") or "").lower()
    raised: list[dict] = []
    for ioc in iocs:
        val = ioc["value"]
        vl = val.lower()
        hit = False
        if ioc["kind"] == "ip":
            hit = val in (src, dst) or vl in hay
        elif ioc["kind"] == "user":
            hit = usr == vl
        else:  # hash / domain / url / file
            hit = vl in hay
        if not hit:
            continue
        raised.append(_raise(ioc, event, event_id))
        db.execute("UPDATE iocs SET hits = hits + 1, last_hit = ? WHERE id = ?",
                   (db.now(), ioc["id"]))
        if ioc["kind"] == "ip":
            block_indicator(val, "ip", f"Matched IOC watchlist ({ioc.get('source') or 'manual'})", "ioc")
    if raised:
        _invalidate()  # refresh hit counts
    return raised


def _raise(ioc: dict, event: dict, event_id: int | None) -> dict:
    title = f"IOC match: {ioc['kind']} {ioc['value']}"
    alert_id = db.execute(
        """INSERT INTO alerts (ts, rule_id, title, severity, description, entity, event_id, status, mitre)
           VALUES (?, 'IOC', ?, ?, ?, ?, ?, 'open', 'T1071')""",
        (db.now(), title, ioc["severity"],
         f"Watchlist indicator observed in: {event.get('message','')}",
         ioc["value"], event_id),
    )
    alert = {"id": alert_id, "ts": db.now(), "rule_id": "IOC", "title": title,
             "severity": ioc["severity"], "severity_label": SEVERITY_LABELS.get(ioc["severity"], "high"),
             "entity": ioc["value"], "status": "open", "mitre": "T1071"}
    bus.publish_threadsafe({"type": "alert", "data": alert})
    return alert


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
def list_iocs() -> list[dict]:
    return db.query("SELECT * FROM iocs ORDER BY active DESC, hits DESC, added_ts DESC")


def add_ioc(kind: str, value: str, severity: int = 4, source: str = "manual",
            note: str = "") -> dict:
    value = value.strip()
    if not value:
        return {"ok": False, "error": "empty indicator"}
    existing = db.query_one("SELECT id FROM iocs WHERE kind = ? AND value = ?", (kind, value))
    if existing:
        db.execute("UPDATE iocs SET active = 1, severity = ?, source = ?, note = ? WHERE id = ?",
                   (severity, source, note, existing["id"]))
    else:
        db.execute("""INSERT INTO iocs (kind, value, severity, source, note, active, hits, added_ts)
                      VALUES (?,?,?,?,?,1,0,?)""",
                   (kind, value, severity, source, note, db.now()))
    _invalidate()
    return {"ok": True}


def set_active(ioc_id: int, active: bool) -> None:
    db.execute("UPDATE iocs SET active = ? WHERE id = ?", (1 if active else 0, ioc_id))
    _invalidate()


def delete_ioc(ioc_id: int) -> None:
    db.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    _invalidate()


def import_bulk(text: str, kind: str = "auto", source: str = "import") -> dict[str, Any]:
    """Import newline-separated indicators; kind auto-detected when 'auto'."""
    import re
    added = 0
    for line in text.splitlines():
        v = line.strip()
        if not v or v.startswith("#"):
            continue
        k = kind
        if kind == "auto":
            if re.fullmatch(r"[a-fA-F0-9]{32,64}", v):
                k = "hash"
            elif re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
                k = "ip"
            elif v.startswith(("http://", "https://")):
                k = "url"
            elif "." in v:
                k = "domain"
            else:
                k = "user"
        add_ioc(k, v, source=source)
        added += 1
    return {"ok": True, "added": added}
