"""Event ingestion pipeline: normalise -> coalesce -> persist -> detect -> stream.

Repeated identical events (e.g. a service spamming the same Windows event code)
are *coalesced*: instead of storing a new row each time, the existing row's
`count` and `last_ts` are bumped, so the console shows one entry with a ×N badge
rather than a wall of duplicates. Coalescing is time- and size-bounded so a very
long-running spam still rolls into fresh "combos" of up to COALESCE_MAX.

count / last_ts are deliberately NOT part of the tamper-evident chain hash, so
bumping them never invalidates the audit chain.
"""
from __future__ import annotations

import threading
from typing import Any, Optional

from .. import database as db
from ..forensics import integrity, iocs
from ..knowledge import describe, enrich
from .bus import bus
from .detection import SEVERITY_LABELS, evaluate

COALESCE_WINDOW = 120.0   # seconds an identical event keeps folding into one row
COALESCE_MAX = 30         # cap per combo, then start a fresh one (~"25-30 per combo")

_lock = threading.Lock()
# signature -> {"id": row_id, "last": ts, "count": n}
_recent: dict[tuple, dict] = {}


def _signature(source, host, event_id, message, severity) -> tuple:
    return (source, host, event_id, (message or "")[:200], severity)


def _prune(now: float) -> None:
    if len(_recent) > 500:
        for k in [k for k, v in _recent.items() if now - v["last"] > COALESCE_WINDOW]:
            _recent.pop(k, None)


def ingest_event(
    *,
    source: str,
    message: str,
    category: str = "general",
    severity: int = 3,
    host: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    user: Optional[str] = None,
    event_id: Optional[int] = None,
    provider: Optional[str] = None,
    level: Optional[str] = None,
    raw: Optional[dict[str, Any]] = None,
) -> dict:
    """Single entry point used by every subsystem. Coalesces duplicates,
    persists (and hash-chains) new events, runs detection, and streams live."""
    if event_id is not None:
        meta = enrich(event_id, level)
        if category in ("general", "endpoint", ""):
            category = meta["category"]
        severity = max(int(severity), int(meta["severity"])) if severity else meta["severity"]

    severity = max(1, min(5, int(severity)))
    ts = db.now()
    event = {
        "ts": ts, "source": source, "host": host, "category": category,
        "severity": severity, "message": message, "src_ip": src_ip,
        "dst_ip": dst_ip, "user": user, "event_id": event_id, "provider": provider,
    }
    sig = _signature(source, host, event_id, message, severity)

    with _lock:
        prior = _recent.get(sig)
        coalesce = prior is not None and (ts - prior["last"]) < COALESCE_WINDOW and prior["count"] < COALESCE_MAX

        if coalesce:
            prior["count"] += 1
            prior["last"] = ts
            row_id = prior["id"]
            count = prior["count"]
            db.execute("UPDATE events SET count = ?, last_ts = ? WHERE id = ?", (count, ts, row_id))
        else:
            def _store(prev_hash: str, chain_hash: str) -> int:
                return db.execute(
                    """INSERT INTO events (ts, source, host, category, severity, message,
                                           src_ip, dst_ip, user, event_id, provider,
                                           count, last_ts, prev_hash, chain_hash, raw)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)""",
                    (ts, source, host, category, severity, message, src_ip, dst_ip, user,
                     event_id, provider, ts, prev_hash, chain_hash, db.dumps(raw or {})),
                )
            row_id, _, chain_hash = integrity.link_and_store(event, _store)
            _recent[sig] = {"id": row_id, "last": ts, "count": 1}
            count = 1
            event["chain_hash"] = chain_hash
        _prune(ts)

    event["id"] = row_id
    event["count"] = count
    event["last_ts"] = ts
    event["severity_label"] = SEVERITY_LABELS.get(severity, "medium")
    if event_id is not None:
        event["event_meta"] = describe(event_id)

    if coalesce:
        # tell the UI to bump the existing row's ×count rather than add a new one
        bus.publish_threadsafe({"type": "event_update", "data": {
            "id": row_id, "count": count, "last_ts": ts, "severity": severity,
            "host": host or source, "message": message}})
        # keep threshold detections accurate without re-raising per-hit alerts
        evaluate(event, row_id, threshold_only=True)
    else:
        bus.publish_threadsafe({"type": "event", "data": event})
        alerts = evaluate(event, row_id)
        alerts += iocs.match(event, row_id)
        event["alerts"] = len(alerts)
    return event
