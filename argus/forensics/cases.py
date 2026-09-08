"""Investigation case management.

A case is the investigator's workspace: a titled, tracked investigation with a
severity, assignee and status, to which you pin evidence — events, alerts, IOCs,
free-text notes and artifacts (triage snapshots, exports). Every addition is
time-stamped, giving a chain-of-custody trail. A case can be exported as a
single compressed evidence bundle (with the resolved underlying events/alerts,
the chain head and a SHA-256) suitable for handover.
"""
from __future__ import annotations

from typing import Any, Optional

from .. import database as db
from . import backup, integrity


def _next_ref() -> str:
    n = db.query_one("SELECT COUNT(*) c FROM cases")["c"] + 1
    return f"CASE-{n:04d}"


def create_case(title: str, severity: int = 3, assignee: str = "",
                summary: str = "") -> dict:
    ref = _next_ref()
    cid = db.execute(
        """INSERT INTO cases (ref, title, status, severity, assignee, summary, created, updated)
           VALUES (?,?, 'open', ?,?,?,?,?)""",
        (ref, title, severity, assignee, summary, db.now(), db.now()),
    )
    return {"id": cid, "ref": ref}


def list_cases(status: str = "") -> list[dict]:
    sql = "SELECT * FROM cases"
    params: list[Any] = []
    if status:
        sql += " WHERE status = ?"; params.append(status)
    sql += " ORDER BY updated DESC"
    cases = db.query(sql, params)
    for c in cases:
        c["item_count"] = db.query_one(
            "SELECT COUNT(*) n FROM case_items WHERE case_id = ?", (c["id"],))["n"]
    return cases


def get_case(case_id: int) -> Optional[dict]:
    case = db.query_one("SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case:
        return None
    case["items"] = db.query(
        "SELECT * FROM case_items WHERE case_id = ? ORDER BY added_ts ASC", (case_id,))
    return case


def update_case(case_id: int, **fields) -> None:
    allowed = {"title", "status", "severity", "assignee", "summary"}
    sets, params = [], []
    for k, v in fields.items():
        if k in allowed and v is not None:
            sets.append(f"{k} = ?"); params.append(v)
    if not sets:
        return
    sets.append("updated = ?"); params.append(db.now())
    params.append(case_id)
    db.execute(f"UPDATE cases SET {', '.join(sets)} WHERE id = ?", params)


def add_item(case_id: int, kind: str, ref_id: str = "", title: str = "",
             note: str = "", added_by: str = "analyst", data: Any = None) -> dict:
    # auto-title linked evidence
    if not title and ref_id:
        if kind == "event":
            r = db.query_one("SELECT message FROM events WHERE id = ?", (ref_id,))
            title = r["message"] if r else f"event {ref_id}"
        elif kind == "alert":
            r = db.query_one("SELECT title FROM alerts WHERE id = ?", (ref_id,))
            title = r["title"] if r else f"alert {ref_id}"
    iid = db.execute(
        """INSERT INTO case_items (case_id, kind, ref_id, title, note, added_by, added_ts, data)
           VALUES (?,?,?,?,?,?,?,?)""",
        (case_id, kind, str(ref_id), title, note, added_by, db.now(), db.dumps(data or {})),
    )
    db.execute("UPDATE cases SET updated = ? WHERE id = ?", (db.now(), case_id))
    return {"id": iid}


def delete_item(item_id: int) -> None:
    db.execute("DELETE FROM case_items WHERE id = ?", (item_id,))


def export_bundle(case_id: int) -> dict[str, Any]:
    """Export the case + resolved evidence as one compressed, hashed bundle."""
    case = get_case(case_id)
    if not case:
        return {"ok": False, "error": "case not found"}
    events, alerts = [], []
    for it in case["items"]:
        if it["kind"] == "event" and it["ref_id"].isdigit():
            r = db.query_one("SELECT * FROM events WHERE id = ?", (it["ref_id"],))
            if r:
                events.append(r)
        elif it["kind"] == "alert" and it["ref_id"].isdigit():
            r = db.query_one("SELECT * FROM alerts WHERE id = ?", (it["ref_id"],))
            if r:
                alerts.append(r)
    bundle = {
        "bundle_type": "argus-case", "exported": db.now(),
        "chain_head": integrity.head(),
        "case": {k: v for k, v in case.items() if k != "items"},
        "items": case["items"], "events": events, "alerts": alerts,
    }
    art = backup.write_backup([bundle], "case-bundle", f"{case['ref']}",
                              note=f"case {case['ref']} — {case['title']}")
    return {"ok": True, "artifact": art, "events": len(events), "alerts": len(alerts)}
