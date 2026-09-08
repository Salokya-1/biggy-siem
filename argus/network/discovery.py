"""Device discovery + monitoring for the network infrastructure view.

Discovery methods (best-effort, no admin required):
  * read the OS ARP cache (`arp -a`) for known neighbours
  * ping-sweep the local /24 to populate the cache and detect live hosts
  * reverse-DNS + MAC-vendor hints for identification

Discovered hosts are upserted into the `devices` table with first/last seen,
status and open ports, so the dashboard shows a live asset inventory.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

from .. import database as db
from ..core.pipeline import ingest_event


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def local_subnet() -> str:
    ip = local_ip()
    net = ipaddress.ip_network(f"{ip}/24", strict=False)
    return str(net)


def _read_arp() -> list[dict]:
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    hosts = []
    for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}"
                         r"(?:[:-][0-9a-fA-F]{2}){4})", out):
        mac = m.group(2).replace("-", ":").lower()
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        hosts.append({"ip": m.group(1), "mac": mac})
    return hosts


def _ping(ip: str, timeout_ms: int = 500) -> bool:
    # Windows uses -n/-w; POSIX uses -c/-W(seconds). Try Windows first.
    import platform
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return r.returncode == 0 and ("ttl=" in r.stdout.lower() or "ttl=" in r.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return False


def _hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _vendor_from_mac(mac: str) -> Optional[str]:
    # A tiny built-in OUI table for common vendors (extend as needed).
    oui = {
        "00:1a:11": "Google", "3c:5a:b4": "Google", "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi", "00:0c:29": "VMware", "00:50:56": "VMware",
        "08:00:27": "VirtualBox", "00:15:5d": "Microsoft (Hyper-V)",
        "f0:9f:c2": "Ubiquiti", "00:1d:aa": "TP-Link", "ac:de:48": "Apple",
        "a4:83:e7": "Apple", "d8:3a:dd": "Raspberry Pi",
    }
    return oui.get(mac[:8].lower())


def _upsert_device(rec: dict[str, Any]) -> bool:
    existing = db.query_one("SELECT id, status FROM devices WHERE ip = ?", (rec["ip"],))
    is_new = existing is None
    if is_new:
        db.execute(
            """INSERT INTO devices (ip, mac, hostname, os_guess, vendor, status,
                                    open_ports, risk, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (rec["ip"], rec.get("mac"), rec.get("hostname"), rec.get("os_guess"),
             rec.get("vendor"), rec.get("status", "up"),
             db.dumps(rec.get("open_ports", [])), rec.get("risk", 0),
             db.now(), db.now()),
        )
    else:
        db.execute(
            """UPDATE devices SET mac = COALESCE(?, mac), hostname = COALESCE(?, hostname),
               vendor = COALESCE(?, vendor), status = ?, last_seen = ? WHERE ip = ?""",
            (rec.get("mac"), rec.get("hostname"), rec.get("vendor"),
             rec.get("status", "up"), db.now(), rec["ip"]),
        )
    return is_new


def discover(subnet: Optional[str] = None, sweep: bool = True) -> dict[str, Any]:
    subnet = subnet or local_subnet()
    net = ipaddress.ip_network(subnet, strict=False)
    my_ip = local_ip()

    found: dict[str, dict] = {}
    for entry in _read_arp():
        found[entry["ip"]] = {**entry, "status": "up"}

    # Always include ourselves.
    found.setdefault(my_ip, {"ip": my_ip, "status": "up",
                             "hostname": socket.gethostname(), "os_guess": "this host"})

    if sweep and net.num_addresses <= 512:
        hosts = [str(h) for h in net.hosts()]
        with ThreadPoolExecutor(max_workers=64) as pool:
            for ip, alive in zip(hosts, pool.map(_ping, hosts)):
                if alive:
                    found.setdefault(ip, {"ip": ip, "status": "up"})
        # refresh ARP after the sweep to capture MACs learned during pings
        for entry in _read_arp():
            found.setdefault(entry["ip"], {"ip": entry["ip"], "status": "up"})
            found[entry["ip"]].setdefault("mac", entry["mac"])

    new_count = 0
    for rec in found.values():
        rec.setdefault("hostname", _hostname(rec["ip"]))
        if rec.get("mac"):
            rec.setdefault("vendor", _vendor_from_mac(rec["mac"]))
        if _upsert_device(rec):
            new_count += 1

    ingest_event(
        source="network", category="discovery",
        severity=3 if new_count else 2,
        message=f"Network discovery on {subnet}: {len(found)} host(s), {new_count} new",
        host="argus-scanner", raw={"subnet": subnet, "count": len(found)},
    )
    return {"subnet": subnet, "count": len(found), "new": new_count,
            "devices": list(found.values())}


def monitor_known() -> dict[str, Any]:
    """Ping every known device and flip status up/down, raising an event when a
    previously-up asset goes offline."""
    devices = db.query("SELECT ip, hostname, status FROM devices")
    changed = 0
    with ThreadPoolExecutor(max_workers=32) as pool:
        alive_map = dict(zip((d["ip"] for d in devices),
                             pool.map(lambda d: _ping(d["ip"]), devices)))
    for d in devices:
        new_status = "up" if alive_map.get(d["ip"]) else "down"
        if new_status != d["status"]:
            db.execute("UPDATE devices SET status = ?, last_seen = ? WHERE ip = ?",
                       (new_status, db.now(), d["ip"]))
            changed += 1
            if new_status == "down":
                ingest_event(source="network", category="availability", severity=3,
                             message=f"Asset offline: {d.get('hostname') or d['ip']}",
                             dst_ip=d["ip"], host="argus-monitor")
    return {"checked": len(devices), "changed": changed}


# background monitor loop -----------------------------------------------------
class MonitorService:
    def __init__(self, interval: int = 180) -> None:
        self.interval = interval
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _loop(self) -> None:
        self._stop.wait(30)
        while not self._stop.is_set():
            try:
                monitor_known()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


monitor_service = MonitorService()
