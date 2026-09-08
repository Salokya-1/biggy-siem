"""Compressed log backups + evidence exports.

Backups are written as gzip-compressed NDJSON (`.jsonl.gz`) — a very small,
append-friendly, universally-readable format. Each file is accompanied by a
JSON manifest recording the record count, the file's SHA-256, and the current
tamper-evident chain head (an external anchor for the audit chain).

A background service writes an incremental backup on an interval and keeps only
the most recent N (rotation). Analysts can also export a filtered slice of the
event log on demand as an evidence file. Every file is registered in the
`artifacts` table so the Evidence view can list, verify and reveal them.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

from .. import database as db
from ..config import settings
from . import integrity

MAX_BACKUPS = 20            # rotation: keep this many auto backups
_lock = threading.Lock()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _register(kind: str, path: Path, records: int, host: str = "", note: str = "") -> dict:
    sha = _sha256_file(path)
    size = path.stat().st_size
    aid = db.execute(
        """INSERT INTO artifacts (kind, name, path, sha256, size, host, records, note, created)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (kind, path.name, str(path), sha, size, host, records, note, db.now()),
    )
    return {"id": aid, "kind": kind, "name": path.name, "path": str(path),
            "sha256": sha, "size": size, "records": records, "note": note}


def _write_jsonl_gz(path: Path, rows: list[dict]) -> None:
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=9) as gz:
        for r in rows:
            gz.write(json.dumps(r, default=str, separators=(",", ":")) + "\n")


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.localtime())


def write_backup(rows: list[dict], kind: str, label: str, note: str = "") -> Optional[dict]:
    """Write rows to a compressed evidence file + manifest, register it."""
    if not rows:
        return None
    settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    name = f"argus-{label}-{_stamp()}.jsonl.gz"
    path = settings.EVIDENCE_DIR / name
    _write_jsonl_gz(path, rows)
    art = _register(kind, path, len(rows), note=note)
    manifest = {
        "tool": "Argus SIEM", "kind": kind, "created": time.time(),
        "created_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "records": len(rows), "file": name, "sha256": art["sha256"],
        "size_bytes": art["size"], "chain_head": integrity.head(),
        "first_id": rows[0].get("id"), "last_id": rows[-1].get("id"),
    }
    (settings.EVIDENCE_DIR / (name + ".manifest.json")).write_text(
        json.dumps(manifest, indent=2), encoding="utf-8")
    art["manifest"] = manifest
    return art


def run_backup(since_id: int = 0, reason: str = "auto") -> dict[str, Any]:
    """Back up events with id > since_id. Returns the artifact + new max id."""
    with _lock:
        rows = db.query("SELECT * FROM events WHERE id > ? ORDER BY id ASC", (since_id,))
        if not rows:
            return {"backed_up": 0, "max_id": since_id}
        art = write_backup(rows, "backup", "backup", note=f"reason={reason}")
        _rotate()
        return {"backed_up": len(rows), "max_id": rows[-1]["id"], "artifact": art}


def export_events(*, severity: int = 0, category: str = "", source: str = "",
                  q: str = "", limit: int = 100000) -> dict[str, Any]:
    """On-demand filtered evidence export."""
    sql = "SELECT * FROM events WHERE 1=1"
    params: list[Any] = []
    if severity:
        sql += " AND severity >= ?"; params.append(severity)
    if category:
        sql += " AND category = ?"; params.append(category)
    if source:
        sql += " AND source = ?"; params.append(source)
    if q:
        sql += " AND (message LIKE ? OR host LIKE ? OR src_ip LIKE ? OR user LIKE ?)"
        like = f"%{q}%"; params += [like, like, like, like]
    sql += " ORDER BY id ASC LIMIT ?"; params.append(limit)
    rows = db.query(sql, params)
    if not rows:
        return {"ok": False, "records": 0, "message": "No events matched the filter."}
    art = write_backup(rows, "export", "export",
                       note=f"filter sev>={severity} cat={category or '*'} q={q or '*'}")
    return {"ok": True, "records": len(rows), "artifact": art}


def _rotate() -> None:
    backups = db.query("SELECT * FROM artifacts WHERE kind = 'backup' ORDER BY created DESC")
    for old in backups[MAX_BACKUPS:]:
        _delete_file(old)
        db.execute("DELETE FROM artifacts WHERE id = ?", (old["id"],))


def _delete_file(art: dict) -> None:
    try:
        p = Path(art["path"])
        if p.exists():
            p.unlink()
        man = Path(str(p) + ".manifest.json")
        if man.exists():
            man.unlink()
    except OSError:
        pass


def list_artifacts(kind: str = "") -> list[dict]:
    sql = "SELECT * FROM artifacts"
    params: list[Any] = []
    if kind:
        sql += " WHERE kind = ?"; params.append(kind)
    sql += " ORDER BY created DESC"
    arts = db.query(sql, params)
    for a in arts:
        a["exists"] = Path(a["path"]).exists()
    return arts


def verify_artifact(art_id: int) -> dict[str, Any]:
    """Recompute a file's SHA-256 and compare to what was recorded at creation."""
    a = db.query_one("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    if not a:
        return {"ok": False, "error": "not found"}
    p = Path(a["path"])
    if not p.exists():
        return {"ok": False, "error": "file missing", "expected": a["sha256"]}
    current = _sha256_file(p)
    return {"ok": current == a["sha256"], "expected": a["sha256"], "current": current,
            "name": a["name"]}


def delete_artifact(art_id: int) -> None:
    a = db.query_one("SELECT * FROM artifacts WHERE id = ?", (art_id,))
    if a:
        _delete_file(a)
        db.execute("DELETE FROM artifacts WHERE id = ?", (art_id,))


# --------------------------------------------------------------------------- #
# Rotating backup service
# --------------------------------------------------------------------------- #
class BackupService:
    def __init__(self, interval: int = 600) -> None:  # every 10 min
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_id = 0
        self.last_run: Optional[float] = None

    def _loop(self) -> None:
        # baseline: don't re-dump the whole history on first tick
        row = db.query_one("SELECT MAX(id) m FROM events")
        self._last_id = (row["m"] or 0) if row else 0
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break
            try:
                res = run_backup(self._last_id, "scheduled")
                if res.get("backed_up"):
                    self._last_id = res["max_id"]
                    self.last_run = db.now()
            except Exception:
                pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-backup", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


backup_service = BackupService()
