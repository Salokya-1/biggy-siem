"""Volatile-evidence triage collection.

Captures a point-in-time forensic snapshot of the host: running processes (with
command lines and hashes-of-interest), network connections, listening ports,
logged-on users, the ARP table, DNS cache and autorun/persistence locations.
The snapshot is written as a compressed, SHA-256-stamped artifact so it can be
attached to a case as evidence. This is the "grab RAM-resident state before it
changes" step every investigation starts with.
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess
import time
from typing import Any

import psutil

from .. import database as db
from ..core.pipeline import ingest_event
from . import backup

IS_WINDOWS = platform.system().lower().startswith("win")


def _run(cmd: list[str], timeout: int = 15) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _processes() -> list[dict]:
    out = []
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "exe",
                                   "cmdline", "create_time"]):
        try:
            info = p.info
            out.append({
                "pid": info.get("pid"), "ppid": info.get("ppid"),
                "name": info.get("name"), "user": info.get("username"),
                "exe": info.get("exe"),
                "cmdline": " ".join(info.get("cmdline") or [])[:400],
                "started": info.get("create_time"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def _connections() -> list[dict]:
    out = []
    try:
        for c in psutil.net_connections(kind="inet"):
            proc = None
            if c.pid:
                try:
                    proc = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc = None
            out.append({
                "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status, "pid": c.pid, "process": proc,
            })
    except (psutil.AccessDenied, PermissionError):
        pass
    return out


def _autoruns() -> list[dict]:
    """Common persistence locations (Windows Run keys / Linux cron & systemd)."""
    runs = []
    if IS_WINDOWS:
        for hive in (r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                     r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"):
            out = _run(["reg", "query", hive])
            for m in re.finditer(r"^\s{4,}(\S.+?)\s+REG_\w+\s+(.+)$", out, re.M):
                runs.append({"location": hive, "name": m.group(1).strip(),
                             "command": m.group(2).strip()})
    else:
        # Linux/macOS persistence: user crontab, system cron, enabled systemd units
        cron = _run(["crontab", "-l"])
        for ln in cron.splitlines():
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                runs.append({"location": "crontab -l", "name": "cron job", "command": ln[:200]})
        for path in ("/etc/crontab",):
            try:
                for ln in open(path, errors="replace").read().splitlines():
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and " " in ln:
                        runs.append({"location": path, "name": "system cron", "command": ln[:200]})
            except OSError:
                pass
        units = _run(["systemctl", "list-unit-files", "--state=enabled",
                      "--type=service", "--no-legend", "--no-pager"])
        for ln in units.splitlines()[:40]:
            name = ln.split()[0] if ln.split() else ""
            if name:
                runs.append({"location": "systemd (enabled)", "name": name, "command": "enabled service"})
    return runs


def collect(reason: str = "manual") -> dict[str, Any]:
    started = time.time()
    hostname = socket.gethostname()
    procs = _processes()
    conns = _connections()
    snapshot = {
        "collected": time.time(),
        "collected_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "host": hostname,
        "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "boot_time": psutil.boot_time(),
        "logged_on_users": [{"name": u.name, "terminal": u.terminal,
                             "started": u.started} for u in psutil.users()],
        "process_count": len(procs),
        "processes": procs,
        "connections": conns,
        "listening_ports": sorted({c["laddr"].rsplit(":", 1)[-1]
                                   for c in conns if c["status"] == "LISTEN" and c["laddr"]}),
        "external_connections": [c for c in conns if c["raddr"]
                                 and not c["raddr"].startswith(("127.", "::1", "0.0.0.0"))],
        "arp_table": _run(["arp", "-a"])[:8000],
        "dns_cache": _run(["ipconfig", "/displaydns"])[:8000] if IS_WINDOWS else "",
        "autoruns": _autoruns(),
    }
    # store as a single-row compressed artifact
    art = backup.write_backup([snapshot], "triage", "triage",
                              note=f"host={hostname} reason={reason}")
    duration = round(time.time() - started, 2)
    ingest_event(
        source="forensics", category="triage", severity=2,
        message=(f"Triage snapshot captured on {hostname}: {len(procs)} processes, "
                 f"{len(snapshot['external_connections'])} external connections"),
        host=hostname, raw={"artifact": art.get("name") if art else None},
    )
    summary = {
        "host": hostname, "duration": duration,
        "process_count": len(procs), "connection_count": len(conns),
        "external_connections": len(snapshot["external_connections"]),
        "listening": len(snapshot["listening_ports"]),
        "autoruns": len(snapshot["autoruns"]),
        "artifact": art,
    }
    return summary
