"""Entity timeline — reconstruct everything that touched an IP, host or user.

Pivoting on a single entity and seeing every event, alert and scan involving it,
in order, is the core move in an investigation ("what did this IP do?", "what
happened on this host?"). This merges the relevant records across the whole
pipeline into one chronological view.
"""
from __future__ import annotations

from typing import Any

from .. import database as db


def entity_timeline(entity: str, limit: int = 400) -> dict[str, Any]:
    entity = entity.strip()
    if not entity:
        return {"entity": entity, "items": [], "count": 0}
    like = f"%{entity}%"
    items: list[dict] = []

    for e in db.query(
        """SELECT id, ts, source, severity, message, host, src_ip, dst_ip, user, event_id, category
           FROM events
           WHERE src_ip = ? OR dst_ip = ? OR host = ? OR user = ? OR message LIKE ?
           ORDER BY ts DESC LIMIT ?""",
        (entity, entity, entity, entity, like, limit),
    ):
        items.append({"ts": e["ts"], "kind": "event", "ref_id": e["id"],
                      "severity": e["severity"], "source": e["source"],
                      "title": e["message"], "event_id": e["event_id"],
                      "detail": f"{e['category']} · {e['host'] or ''}".strip(" ·")})

    for a in db.query(
        """SELECT id, ts, title, severity, entity, description, rule_id, mitre
           FROM alerts WHERE entity = ? OR description LIKE ? OR entity LIKE ?
           ORDER BY ts DESC LIMIT ?""",
        (entity, like, like, limit),
    ):
        items.append({"ts": a["ts"], "kind": "alert", "ref_id": a["id"],
                      "severity": a["severity"], "source": "detection",
                      "title": a["title"], "mitre": a["mitre"],
                      "detail": a["description"] or a["entity"]})

    for s in db.query(
        """SELECT id, ts, kind, target, verdict, engine, positives, total
           FROM scans WHERE target LIKE ? ORDER BY ts DESC LIMIT ?""",
        (like, limit),
    ):
        sev = 5 if s["verdict"] == "malicious" else 4 if s["verdict"] in ("suspicious", "risky") else 2
        items.append({"ts": s["ts"], "kind": "scan", "ref_id": s["id"],
                      "severity": sev, "source": s["engine"],
                      "title": f"{s['kind']} scan: {s['target']}",
                      "detail": f"{s['verdict']} ({s['positives']}/{s['total']})"})

    items.sort(key=lambda x: x["ts"], reverse=True)
    items = items[:limit]
    return {
        "entity": entity,
        "count": len(items),
        "first_seen": min((i["ts"] for i in items), default=None),
        "last_seen": max((i["ts"] for i in items), default=None),
        "by_kind": {k: sum(1 for i in items if i["kind"] == k) for k in ("event", "alert", "scan")},
        "max_severity": max((i["severity"] for i in items), default=0),
        "items": items,
    }
