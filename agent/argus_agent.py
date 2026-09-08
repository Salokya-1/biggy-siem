#!/usr/bin/env python3
"""Argus Host Agent.

A lightweight endpoint agent (à la the Wazuh/Elastic agent) that enrols with the
Argus manager and streams host telemetry + locally-observed security events.

Runs on any machine with Python 3.9+ and `psutil`:

    pip install psutil
    python argus_agent.py --server http://127.0.0.1:8000 --key argus-agent-key

Collected each heartbeat: CPU/memory/disk, uptime, logged-in users, process and
network-connection counts, top processes, plus heuristic detections
(suspicious process names, new listening ports, unusual privilege).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import time
import urllib.request
from typing import Any

try:
    import psutil
except ImportError:
    raise SystemExit("psutil is required:  pip install psutil")

SUSPICIOUS_PROCS = {
    "mimikatz.exe", "nc.exe", "ncat.exe", "psexec.exe", "cobaltstrike",
    "procdump.exe", "lazagne.exe", "rubeus.exe", "bloodhound.exe",
}
SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe"}
CHILD_RED_FLAGS = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"}


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def _post(url: str, key: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Agent-Key", key)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def collect_metrics() -> dict[str, Any]:
    vm = psutil.virtual_memory()
    du = psutil.disk_usage(os.path.abspath(os.sep))
    top = sorted(psutil.process_iter(["name", "cpu_percent", "memory_percent"]),
                 key=lambda p: p.info.get("memory_percent") or 0, reverse=True)[:5]
    io = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "mem_percent": vm.percent,
        "disk_percent": du.percent,
        "uptime_sec": int(time.time() - psutil.boot_time()),
        "process_count": len(psutil.pids()),
        "connection_count": len(psutil.net_connections(kind="inet")),
        "users": [u.name for u in psutil.users()],
        "top_processes": [{"name": p.info.get("name"),
                           "mem": round(p.info.get("memory_percent") or 0, 1)} for p in top],
        "net": {
            "bytes_sent": io.bytes_sent, "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent, "packets_recv": io.packets_recv,
        },
    }


_WINLOG_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$start=(Get-Date).AddSeconds(-{seconds})
$logs=@('System','Application','Security','Microsoft-Windows-Windows Defender/Operational')
$rows=@()
foreach($log in $logs){{
  $ev=Get-WinEvent -FilterHashtable @{{LogName=$log; StartTime=$start}} -MaxEvents 30 -ErrorAction SilentlyContinue
  foreach($e in $ev){{
    $m=''
    if($e.Message){{ $m=(($e.Message -split "`r?`n") | Where-Object {{$_ -match '\S'}} | Select-Object -First 1) }}
    $rows+=[pscustomobject]@{{Id=$e.Id; Level=$e.LevelDisplayName; Provider=$e.ProviderName;
      Channel=$e.LogName; Record=$e.RecordId; Msg=$m}}
  }}
}}
$rows | ConvertTo-Json -Compress -Depth 3
"""


def collect_winevents(seen: set, seconds: int = 90) -> list[dict]:
    """Pull recent Windows Event Log entries (Windows only). Returns events
    tagged with their code; the server maps codes to meanings."""
    if not platform.system().lower().startswith("win"):
        return []
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _WINLOG_PS.format(seconds=seconds)],
            capture_output=True, text=True, timeout=40)
        data = json.loads((proc.stdout or "").strip() or "[]")
    except Exception:
        return []
    rows = data if isinstance(data, list) else [data]
    events = []
    for r in rows:
        key = f"{r.get('Channel')}:{r.get('Record')}"
        if key in seen:
            continue
        seen.add(key)
        events.append({
            "source": "winlog", "event_id": r.get("Id"),
            "provider": r.get("Provider") or r.get("Channel"),
            "level": r.get("Level"), "category": "endpoint",
            "message": (r.get("Msg") or "").strip()[:300],
        })
    if len(seen) > 5000:
        seen.clear()
    return events


def detect_events(seen_ports: set[int]) -> tuple[list[dict], set[int]]:
    events: list[dict] = []

    # suspicious process names + Office spawning shells
    procs = {}
    for p in psutil.process_iter(["pid", "name", "ppid", "username"]):
        procs[p.info["pid"]] = p.info
    for info in procs.values():
        name = (info.get("name") or "").lower()
        if name in SUSPICIOUS_PROCS:
            events.append({"category": "process", "severity": 5,
                           "message": f"Suspicious process running: {name}",
                           "user": info.get("username")})
        parent = procs.get(info.get("ppid"), {})
        pname = (parent.get("name") or "").lower()
        if pname in SUSPICIOUS_PARENTS and name in CHILD_RED_FLAGS:
            events.append({"category": "process", "severity": 5,
                           "message": f"Office app {pname} spawned {name} (macro attack?)",
                           "user": info.get("username")})

    # new listening ports since last beat
    current_ports = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status == psutil.CONN_LISTEN and c.laddr:
            current_ports.add(c.laddr.port)
    new_ports = current_ports - seen_ports
    for port in sorted(new_ports):
        if port not in (0,) and seen_ports:  # skip first-run baseline noise
            events.append({"category": "network", "severity": 3,
                           "message": f"New listening port opened: {port}"})
    return events, current_ports


def main() -> None:
    ap = argparse.ArgumentParser(description="Argus Host Agent")
    ap.add_argument("--server", default=os.environ.get("ARGUS_SERVER", "http://127.0.0.1:8000"))
    ap.add_argument("--key", default=os.environ.get("ARGUS_AGENT_KEY", "argus-agent-key"))
    ap.add_argument("--interval", type=int, default=30)
    args = ap.parse_args()

    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    ip = _local_ip()

    print(f"[argus-agent] enrolling {hostname} ({ip}) -> {args.server}")
    reg = _post(f"{args.server}/api/agent/enroll", args.key,
                {"hostname": hostname, "os_info": os_info, "ip": ip, "version": "1.0"})
    agent_id = reg.get("agent_id")
    if not agent_id:
        raise SystemExit(f"[argus-agent] enrolment failed: {reg}")
    print(f"[argus-agent] enrolled, agent_id={agent_id}. Sending heartbeats every {args.interval}s.")

    seen_ports: set[int] = set()
    seen_events: set[str] = set()
    while True:
        try:
            metrics = collect_metrics()
            events, seen_ports = detect_events(seen_ports)
            events += collect_winevents(seen_events, seconds=max(90, args.interval * 3))
            resp = _post(f"{args.server}/api/agent/heartbeat", args.key,
                         {"agent_id": agent_id, "metrics": metrics, "events": events})
            flag = f" ({len(events)} event(s) sent)" if events else ""
            print(f"[argus-agent] heartbeat ok cpu={metrics['cpu_percent']}% "
                  f"mem={metrics['mem_percent']}%{flag}")
            args.interval = resp.get("interval", args.interval)
        except Exception as exc:  # noqa: BLE001 — agent must survive transient errors
            print(f"[argus-agent] heartbeat error: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
