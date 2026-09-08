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
MAX_FILE_BYTES = 512 * 1024 * 1024  # skip files larger than 512 MB (only first 4 MB is read anyway)
MAX_FILES_PER_SCAN = 800            # bound how many files one cycle inspects
YIELD_EVERY = 4                     # yield the GIL every N files so requests never stall


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


def scan_directory(directory: Optional[str] = None, deep: bool = False) -> dict[str, Any]:
    root = Path(directory or settings.WATCH_DIR)
    started = time.time()
    results = {"scanned": 0, "clean": 0, "suspicious": 0, "malicious": 0,
               "errors": 0, "findings": [], "directory": str(root)}
    if not root.exists():
        results["message"] = f"Directory not found: {root}"
        return results

    walker = root.rglob("*") if deep else root.glob("*")
    seen = 0
    for entry in walker:
        if not entry.is_file():
            continue
        if any(part.lower() in SKIP_DIRS for part in entry.parts):
            continue
        try:
            if entry.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            results["errors"] += 1
            continue

        seen += 1
        if seen > MAX_FILES_PER_SCAN:
            results["capped"] = True
            break
        # Yield the GIL periodically so background scanning never starves the
        # web server's request threads (files can be large / CPU-heavy).
        if seen % YIELD_EVERY == 0:
            time.sleep(0.003)

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
    ingest_event(
        source="scanner", category="scan", severity=2,
        message=(f"Directory scan complete: {results['scanned']} files, "
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
        # small delay so the web server is up before the first scan event
        self._stop.wait(15)
        while not self._stop.is_set():
            if self.enabled:
                try:
                    scan_directory(settings.WATCH_DIR, deep=False)
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
