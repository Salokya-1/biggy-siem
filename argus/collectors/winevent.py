"""Windows Event Log collector.

Reads recent entries from the Windows Event Viewer (via `Get-WinEvent`) and
feeds them into the Argus pipeline, tagged with their event code so the console
can show a one-line summary plus a hover tooltip explaining what the code means.

Channels read by default are readable **without administrator rights**
(System / Application / Defender / PowerShell). The Security channel is included
opportunistically and simply skipped if access is denied. On non-Windows hosts
the collector is a harmless no-op.
"""
from __future__ import annotations

import json
import platform
import socket
import subprocess
import threading
from collections import deque
from typing import Any

from .. import database as db
from ..core.pipeline import ingest_event
from ..knowledge import describe

IS_WINDOWS = platform.system().lower().startswith("win")

DEFAULT_CHANNELS = [
    "System",
    "Application",
    "Security",  # opportunistic — needs admin; skipped gracefully otherwise
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]

# PowerShell: pull events newer than N seconds, first line of each message only,
# emit compact JSON. -ErrorAction SilentlyContinue drops channels we can't read.
_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddSeconds(-{seconds})
$logs=@({logs})
$rows=@()
foreach($log in $logs){{
  $ev=Get-WinEvent -FilterHashtable @{{LogName=$log; StartTime=$start}} -MaxEvents {maxev} -ErrorAction SilentlyContinue
  foreach($e in $ev){{
    $msg=''
    if($e.Message){{ $msg=(($e.Message -split "`r?`n") | Where-Object {{$_ -match '\S'}} | Select-Object -First 1) }}
    $rows+=[pscustomobject]@{{
      Id=$e.Id; Level=$e.LevelDisplayName; Provider=$e.ProviderName; Channel=$e.LogName;
      Record=$e.RecordId; ts=([DateTimeOffset]$e.TimeCreated).ToUnixTimeSeconds();
      Machine=$e.MachineName; Msg=$msg
    }}
  }}
}}
$rows | Sort-Object ts | ConvertTo-Json -Compress -Depth 3
"""


def _run_powershell(seconds: int, channels: list[str], maxev: int) -> list[dict]:
    logs = ",".join(f"'{c}'" for c in channels)
    script = _PS.format(seconds=seconds, logs=logs, maxev=maxev)
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    out = (proc.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


class WinEventCollector:
    """Polls the Event Viewer and forwards new entries into the pipeline."""

    def __init__(self, interval: int = 60, channels: list[str] | None = None) -> None:
        self.interval = interval
        self.channels = channels or DEFAULT_CHANNELS
        self._seen: deque[str] = deque(maxlen=6000)
        self._seen_set: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.available = IS_WINDOWS
        self.last_run: float | None = None
        self.total_ingested = 0

    # -- dedup helper -------------------------------------------------------
    def _is_new(self, key: str) -> bool:
        if key in self._seen_set:
            return False
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(key)
        self._seen_set.add(key)
        return True

    # -- one collection pass ------------------------------------------------
    def pull(self, seconds: int = 120, maxev: int = 60) -> dict[str, Any]:
        if not IS_WINDOWS:
            return {"available": False, "ingested": 0,
                    "message": "Windows Event Log collection only runs on Windows hosts."}
        rows = _run_powershell(seconds, self.channels, maxev)
        ingested = 0
        for r in rows:
            try:
                eid = int(r.get("Id"))
            except (TypeError, ValueError):
                continue
            key = f"{r.get('Channel')}:{r.get('Record')}"
            if not self._is_new(key):
                continue
            meta = describe(eid)
            first_line = (r.get("Msg") or "").strip()
            message = meta["name"] if not first_line else f"{meta['name']} — {first_line}"
            ingest_event(
                source="winlog",
                message=message[:400],
                category="endpoint",
                severity=meta["severity"],
                host=r.get("Machine") or socket.gethostname(),
                event_id=eid,
                provider=r.get("Provider") or r.get("Channel"),
                level=r.get("Level"),
                raw={"channel": r.get("Channel"), "record": r.get("Record"),
                     "provider": r.get("Provider"), "level": r.get("Level")},
            )
            ingested += 1
        self.last_run = db.now()
        self.total_ingested += ingested
        return {"available": True, "ingested": ingested, "scanned_channels": len(self.channels)}

    # -- background loop ----------------------------------------------------
    def _loop(self) -> None:
        self._stop.wait(12)  # let the web server settle before the first pull
        first = True
        while not self._stop.is_set():
            try:
                self.pull(seconds=1800 if first else self.interval + 30,
                          maxev=30 if first else 25)
            except Exception:
                pass
            first = False
            self._stop.wait(self.interval)

    def start(self) -> None:
        if not IS_WINDOWS or (self._thread and self._thread.is_alive()):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-winevent", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


winevent_collector = WinEventCollector()
