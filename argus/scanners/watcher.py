"""Automated folder scanner + background watch loop.

Scans a directory (default: the user's Downloads folder), records every result
in `scans`, and raises SIEM events/alerts for anything suspicious or malicious.
Runs on demand (API) and on a periodic background thread.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Optional

from .. import database as db
from ..config import settings
from ..core.pipeline import ingest_event
from .file_scanner import scan_file

SKIP_DIRS = {"$recycle.bin", "system volume information", ".git", "node_modules"}
MAX_FILE_BYTES = 512 * 1024 * 1024        # on-demand scans: skip files larger than 512 MB
WATCH_MAX_FILE_BYTES = 100 * 1024 * 1024  # background watcher: skip files larger than 100 MB
MAX_FILES_PER_SCAN = 400                  # bound how many files ACTUALLY scanned per cycle
YIELD_EVERY = 4                           # yield the GIL every N files so requests never stall

# Incremental state: path -> (mtime, size). The background watcher scans a file
# once, then skips it until it changes, so steady-state work is near zero even on
# a huge Downloads folder. Cleared on restart (a fresh first pass is cheap enough).
_seen_files: dict[str, tuple] = {}


def _record_scan(report: dict) -> int:
    return db.execute(
        """INSERT INTO scans (ts, kind, target, verdict, engine, positives, total, sha256, details)
           VALUES (?, 'file', ?, ?, 'local', ?, ?, ?, ?)""",
        (db.now(), report.get("path") or report.get("name"), report.get("verdict"),
         len(report.get("reasons", [])), len(report.get("reasons", [])),
         report.get("sha256"), db.dumps(report)),
    )


def _emit_event(report: dict) -> None:
    verdict = report.get("verdict")
    if verdict == "malicious":
        sev = 5
    elif verdict == "suspicious":
        sev = 4
    else:
        return  # don't spam the timeline with clean files
    top = ", ".join(r["name"] for r in report.get("reasons", [])[:3]) or "heuristics"
    ingest_event(
        source="scanner",
        category="malware",
        severity=sev,
        message=f"{verdict.title()} file detected: {report.get('name')} ({top})",
        host="argus-scanner",
        raw={"sha256": report.get("sha256"), "path": report.get("path"),
             "score": report.get("score"), "reasons": report.get("reasons")},
    )


def scan_path(report_path: str | Path) -> dict:
    report = scan_file(report_path)
    if report.get("verdict") != "error":
        _record_scan(report)
        _emit_event(report)
    return report


def scan_directory(directory: Optional[str] = None, deep: bool = False,
                   incremental: bool = False, max_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    root = Path(directory or settings.WATCH_DIR)
    started = time.time()
    results = {"scanned": 0, "skipped": 0, "clean": 0, "suspicious": 0, "malicious": 0,
               "errors": 0, "findings": [], "directory": str(root)}
    if not root.exists():
        results["message"] = f"Directory not found: {root}"
        return results

    walker = root.rglob("*") if deep else root.glob("*")
    scanned = 0
    for entry in walker:
        if not entry.is_file():
            continue
        if any(part.lower() in SKIP_DIRS for part in entry.parts):
            continue
        try:
            st = entry.stat()
        except OSError:
            results["errors"] += 1
            continue
        if st.st_size > max_bytes:
            continue

        # Incremental: skip files already scanned and unchanged (cheap stat only).
        key = str(entry)
        sig = (int(st.st_mtime), st.st_size)
        if incremental and _seen_files.get(key) == sig:
            results["skipped"] += 1
            continue

        scanned += 1
        if scanned > MAX_FILES_PER_SCAN:
            results["capped"] = True
            break
        # Yield the GIL periodically so background scanning never starves the
        # web server's request threads (files can be large / CPU-heavy).
        if scanned % YIELD_EVERY == 0:
            time.sleep(0.003)
        _seen_files[key] = sig

        report = scan_file(entry)
        verdict = report.get("verdict", "error")
        results["scanned"] += 1
        if verdict == "error":
            results["errors"] += 1
            continue
        results[verdict] = results.get(verdict, 0) + 1
        # Only persist non-clean results — writing a row per clean file floods
        # the DB and slows everything down. Clean files are counted, not stored.
        if verdict != "clean":
            _record_scan(report)
            _emit_event(report)
            results["findings"].append({
                "name": report["name"], "path": report.get("path"),
                "verdict": verdict, "score": report["score"],
                "reasons": [r["name"] for r in report["reasons"]],
            })

    results["duration"] = round(time.time() - started, 2)
    # Only log a "scan complete" event when files were actually inspected, so a
    # quiet incremental cycle (nothing new) doesn't spam the pipeline every run.
    if results["scanned"] > 0:
        ingest_event(
            source="scanner", category="scan", severity=2,
            message=(f"Directory scan: {results['scanned']} file(s) inspected, "
                     f"{results['malicious']} malicious / {results['suspicious']} suspicious"),
            host="argus-scanner", raw=results,
        )
    return results


# --------------------------------------------------------------------------- #
# Background watch loop
# --------------------------------------------------------------------------- #
class WatchService:
    def __init__(self, interval: int = 900) -> None:  # 15 min — gentle background cadence
        self.interval = interval
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.last_run: Optional[float] = None
        self.enabled = True

    def _loop(self) -> None:
        # wait a full minute so the console loads instantly before any scanning
        self._stop.wait(60)
        while not self._stop.is_set():
            if self.enabled:
                try:
                    # incremental + 100 MB cap: each file is read once, unchanged
                    # files are skipped, huge installers/videos are ignored.
                    scan_directory(settings.WATCH_DIR, deep=False,
                                   incremental=True, max_bytes=WATCH_MAX_FILE_BYTES)
                    self.last_run = db.now()
                except Exception as exc:  # keep the watcher alive no matter what
                    ingest_event(source="scanner", category="error", severity=2,
                                 message=f"Watch scan failed: {exc}", host="argus-scanner")
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


watch_service = WatchService()
