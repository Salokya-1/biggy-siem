"""Tamper-evident audit chain over the event log.

Every event is linked into a hash chain: chain_hash = SHA-256(prev_hash | body).
Because each entry commits to the one before it, you cannot alter or delete a
past event without breaking every entry after it — the classic forensic property
"can I trust these logs?". Attackers routinely clear logs (Windows event 1102),
so the SIEM's own record must be verifiable.

`verify()` walks the chain and reports the first break (a modified row, or a gap
from a deleted/inserted row). The current chain head is embedded in every backup
manifest, giving an external anchor point in time.
"""
from __future__ import annotations

import hashlib
import threading
from typing import Any, Callable

from .. import database as db

GENESIS = "ARGUS-CHAIN-GENESIS"
_lock = threading.Lock()
_last_hash: str | None = None


def _canonical(ev: dict) -> str:
    """Stable serialisation of the immutable fields of an event."""
    f = lambda k: "" if ev.get(k) is None else str(ev.get(k))
    return "|".join(f(k) for k in (
        "ts", "source", "host", "category", "severity", "message",
        "src_ip", "dst_ip", "user", "event_id", "provider"))


def _hash(prev: str, body: str) -> str:
    return hashlib.sha256(f"{prev}|{body}".encode("utf-8", "replace")).hexdigest()


def init_chain() -> None:
    """Load the current chain head from the DB at startup."""
    global _last_hash
    row = db.query_one("SELECT chain_hash FROM events WHERE chain_hash IS NOT NULL "
                       "ORDER BY id DESC LIMIT 1")
    _last_hash = row["chain_hash"] if row else None


def link_and_store(event: dict, store: Callable[[str, str], int]) -> tuple[int, str, str]:
    """Atomically compute this event's (prev, chain) hashes and persist it via
    `store(prev_hash, chain_hash) -> row_id`, keeping chain order == insert order."""
    global _last_hash
    with _lock:
        prev = _last_hash or GENESIS
        chain = _hash(prev, _canonical(event))
        row_id = store(prev, chain)
        _last_hash = chain
        return row_id, prev, chain


def head() -> str:
    return _last_hash or GENESIS


def verify(limit: int = 0) -> dict[str, Any]:
    """Recompute the chain and report integrity. O(n) over the events table."""
    sql = "SELECT * FROM events ORDER BY id ASC"
    rows = db.query(sql)
    checked = 0
    running = GENESIS
    for r in rows:
        checked += 1
        stored_prev = r.get("prev_hash")
        stored_chain = r.get("chain_hash")
        if stored_chain is None:
            # pre-chain legacy row — skip but carry running forward if present
            running = stored_chain or running
            continue
        # (a) content integrity: does the stored chain hash match the row body?
        if _hash(stored_prev or GENESIS, _canonical(r)) != stored_chain:
            return {"ok": False, "checked": checked, "total": len(rows),
                    "break": {"event_id": r["id"], "type": "modified",
                              "detail": "Event content does not match its chain hash — the row was altered."}}
        # (b) continuity: does this row link to the previous surviving row?
        if stored_prev != running:
            return {"ok": False, "checked": checked, "total": len(rows),
                    "break": {"event_id": r["id"], "type": "gap",
                              "detail": "Chain link broken — an event was deleted or inserted before this one."}}
        running = stored_chain
    return {"ok": True, "checked": checked, "total": len(rows), "head": running}
