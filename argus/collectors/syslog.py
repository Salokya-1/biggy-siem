"""Linux system-log collector (the cross-platform counterpart to winevent).

On Linux it feeds the event pipeline from the OS logs so the Endpoint Log view
and live feed are populated exactly as on Windows. It prefers `journalctl`
(systemd, incl. Kali) and falls back to /var/log/auth.log + /var/log/syslog.

Security-relevant lines are normalised so existing detections keep working, e.g.
an SSH "Failed password ... from <ip>" is tagged as a failed login so the
brute-force threshold rule (R001) fires on Linux just like on Windows.
On non-Linux hosts this is a harmless no-op.
"""
from __future__ import annotations

import hashlib
import platform
import re
import shutil
import socket
import subprocess
import threading
from collections import deque
from typing import Any

from .. import database as db
from ..core.pipeline import ingest_event

IS_LINUX = platform.system().lower() == "linux"
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# (compiled matcher, severity, category, normaliser) — first match wins
_RULES = [
    (re.compile(r"Failed password|authentication failure|Invalid user|Failed publickey", re.I),
     4, "authentication", "failed login"),
    (re.compile(r"POSSIBLE BREAK-?IN ATTEMPT", re.I), 4, "authentication", "possible break-in"),
    (re.compile(r"Accepted (password|publickey|keyboard)", re.I), 2, "authentication", "successful login"),
    (re.compile(r"\bsudo\b.*COMMAND=", re.I), 3, "process", "sudo command"),
    (re.compile(r"session opened for user root", re.I), 3, "authentication", "root session opened"),
    (re.compile(r"\b(useradd|usermod|groupadd|passwd)\b", re.I), 4, "account-mgmt", "account change"),
    (re.compile(r"\b(segfault|oom-killer|kernel panic)\b", re.I), 3, "system", "system fault"),
    (re.compile(r"new device|USB disconnect|Link is (Up|Down)", re.I), 2, "system", "device event"),
]


class LinuxLogCollector:
    def __init__(self, interval: int = 60) -> None:
        self.interval = interval
        self.available = IS_LINUX
        self._seen: deque[str] = deque(maxlen=6000)
        self._seen_set: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_run: float | None = None
        self.total_ingested = 0

    def _is_new(self, key: str) -> bool:
        if key in self._seen_set:
            return False
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(key); self._seen_set.add(key)
        return True

    def _read_lines(self, seconds: int, maxlines: int) -> list[str]:
        # prefer journalctl (systemd); fall back to classic log files
        if shutil.which("journalctl"):
            try:
                out = subprocess.run(
                    ["journalctl", "--since", f"-{seconds}s", "-n", str(maxlines),
                     "-o", "short-iso", "--no-pager"],
                    capture_output=True, text=True, timeout=30).stdout
                if out.strip():
                    return out.splitlines()
            except (OSError, subprocess.TimeoutExpired):
                pass
        lines: list[str] = []
        for path in ("/var/log/auth.log", "/var/log/syslog", "/var/log/secure", "/var/log/messages"):
            try:
                with open(path, "r", errors="replace") as fh:
                    lines += fh.readlines()[-maxlines:]
            except OSError:
                continue
        return lines

    def _classify(self, line: str):
        for pat, sev, cat, norm in _RULES:
            if pat.search(line):
                return sev, cat, norm
        return None

    def pull(self, seconds: int = 120, maxlines: int = 200) -> dict[str, Any]:
        if not IS_LINUX:
            return {"available": False, "ingested": 0,
                    "message": "Linux log collection only runs on Linux hosts."}
        host = socket.gethostname()
        ingested = 0
        for raw in self._read_lines(seconds, maxlines):
            line = raw.strip()
            if not line:
                continue
            hit = self._classify(line)
            if not hit:
                continue
            key = hashlib.sha1(line.encode("utf-8", "replace")).hexdigest()[:16]
            if not self._is_new(key):
                continue
            sev, cat, norm = hit
            ipm = _IP.search(line)
            src = ipm.group(1) if ipm else None
            um = re.search(r"for (?:invalid user )?(\w[\w.-]*)", line)
            user = um.group(1) if um else None
            # normalise so cross-platform detections (e.g. brute force) still match
            msg = f"{norm}: {line[-200:]}" if norm == "failed login" else line[-240:]
            ingest_event(source="syslog", category=cat, severity=sev, message=msg,
                         host=host, src_ip=src, user=user, provider="syslog",
                         raw={"line": line[:400]})
            ingested += 1
        self.last_run = db.now()
        self.total_ingested += ingested
        return {"available": True, "ingested": ingested}

    def _loop(self) -> None:
        self._stop.wait(10)
        first = True
        while not self._stop.is_set():
            try:
                self.pull(seconds=1800 if first else self.interval + 30, maxlines=200 if first else 120)
            except Exception:
                pass
            first = False
            self._stop.wait(self.interval)

    def start(self) -> None:
        if not IS_LINUX or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-syslog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


syslog_collector = LinuxLogCollector()
