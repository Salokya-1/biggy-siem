"""Port scanning.

Uses the real `nmap` binary when it's on PATH (default arguments `-T4 -F`,
the fast top-100-port scan). When nmap isn't installed, a pure-Python TCP
connect scanner over a curated port list is used so the feature still works
out of the box on any machine.
"""
from __future__ import annotations

import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .. import database as db
from ..core.pipeline import ingest_event

# service name for common ports (used by the fallback scanner + display)
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

RISKY_PORTS = {23: "Telnet (cleartext)", 21: "FTP (cleartext)", 3389: "RDP exposed",
               445: "SMB exposed", 5900: "VNC exposed", 6379: "Redis (often no auth)",
               9200: "Elasticsearch exposed", 27017: "MongoDB exposed",
               1433: "MSSQL exposed", 3306: "MySQL exposed"}


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _default_nmap_args() -> list[str]:
    # -T4 aggressive timing, -F fast (top 100 ports), -Pn treat host as up,
    # --open only report open ports, -sV light version detection.
    return ["-T4", "-F", "-Pn", "--open"]


def _parse_nmap(output: str) -> dict[str, Any]:
    ports = []
    for m in re.finditer(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([\w\-/.]+)?", output, re.M):
        ports.append({"port": int(m.group(1)), "proto": m.group(2),
                      "state": m.group(3), "service": (m.group(4) or "").strip() or
                      COMMON_PORTS.get(int(m.group(1)), "unknown")})
    os_match = re.search(r"OS details:\s*(.+)", output)
    mac_match = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*\(([^)]*)\)", output)
    return {
        "ports": [p for p in ports if p["state"] == "open"],
        "os_guess": os_match.group(1).strip() if os_match else None,
        "mac": mac_match.group(1) if mac_match else None,
        "vendor": mac_match.group(2) if mac_match else None,
    }


def _nmap_scan(target: str, arguments: str | None) -> dict[str, Any]:
    args = arguments.split() if arguments else _default_nmap_args()
    cmd = ["nmap", *args, target]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    parsed = _parse_nmap(proc.stdout)
    parsed["engine"] = "nmap"
    parsed["command"] = " ".join(cmd)
    parsed["raw"] = proc.stdout[-4000:]
    return parsed


def _check_port(target: str, port: int, timeout: float = 0.6) -> tuple[int, bool]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port, s.connect_ex((target, port)) == 0
    except OSError:
        return port, False


def _python_scan(target: str, ports: list[int] | None = None) -> dict[str, Any]:
    ports = ports or list(COMMON_PORTS.keys())
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        return {"ports": [], "engine": "python-fallback", "error": "resolve failed"}
    open_ports = []
    with ThreadPoolExecutor(max_workers=64) as pool:
        for port, is_open in pool.map(lambda p: _check_port(ip, p), ports):
            if is_open:
                open_ports.append({"port": port, "proto": "tcp", "state": "open",
                                   "service": COMMON_PORTS.get(port, "unknown")})
    return {"ports": sorted(open_ports, key=lambda p: p["port"]),
            "engine": "python-fallback", "resolved_ip": ip,
            "command": f"tcp-connect {target} ({len(ports)} ports)"}


def scan_target(target: str, arguments: str | None = None,
                force_python: bool = False) -> dict[str, Any]:
    """Scan a host. Prefers nmap; falls back to the built-in scanner."""
    try:
        if nmap_available() and not force_python:
            result = _nmap_scan(target, arguments)
        else:
            result = _python_scan(target)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        result = _python_scan(target)
        result["note"] = f"nmap unavailable ({exc}); used fallback"

    open_ports = result.get("ports", [])
    risky = [{"port": p["port"], "why": RISKY_PORTS[p["port"]]}
             for p in open_ports if p["port"] in RISKY_PORTS]
    result.update({"target": target, "open_count": len(open_ports), "risky": risky})

    db.execute(
        """INSERT INTO scans (ts, kind, target, verdict, engine, positives, total, details)
           VALUES (?, 'network', ?, ?, ?, ?, ?, ?)""",
        (db.now(), target, "risky" if risky else "ok", result.get("engine"),
         len(risky), len(open_ports), db.dumps(result)),
    )

    sev = 4 if risky else 2
    ingest_event(
        source="network", category="network", severity=sev,
        message=(f"Port scan of {target}: {len(open_ports)} open port(s)" +
                 (f", {len(risky)} risky" if risky else "")),
        dst_ip=result.get("resolved_ip") or target, host="argus-scanner",
        raw=result,
    )
    return result
