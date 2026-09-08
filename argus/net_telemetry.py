"""Host network telemetry.

Provides the data behind the Network view's live panels:
  * interfaces()   — adapter inventory: type, model/description, link speed,
                     IPv4/IPv6/MAC, gateway and DNS servers ("what infrastructure").
  * throughput()   — bytes & packets sent/received plus the live send/receive
                     rate sampled over a short window ("network power").
  * connections()  — active TCP/UDP connections with the owning process (netstat-alike).
  * link_quality() — latency & loss to the default gateway and the internet.
"""
from __future__ import annotations

import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

import psutil

IS_WINDOWS = platform.system().lower().startswith("win")

# --------------------------------------------------------------------------- #
# Shared state kept warm by a background sampler so the HTTP endpoints never
# block on a sleep/ping. Reads are O(1) dict lookups.
# --------------------------------------------------------------------------- #
_lock = threading.Lock()
_current_tp: dict[str, Any] = {}          # latest throughput sample
_established = 0                          # established socket count
_ifaces_cache: tuple[float, dict] | None = None
_quality_cache: tuple[float, dict] | None = None
_IFACE_TTL = 8.0
_QUALITY_TTL = 20.0


# --------------------------------------------------------------------------- #
# Interface inventory
# --------------------------------------------------------------------------- #
def _iface_type(name: str, desc: str = "") -> str:
    blob = f"{name} {desc}".lower()
    if any(k in blob for k in ("wi-fi", "wifi", "wlan", "wireless", "802.11")):
        return "Wi-Fi"
    if any(k in blob for k in ("ethernet", "gbe", "realtek pcie", "eth")):
        return "Ethernet"
    if any(k in blob for k in ("loopback", "lo ")):
        return "Loopback"
    if any(k in blob for k in ("virtual", "vethernet", "vmware", "hyper-v", "vbox", "tap", "tun", "wsl")):
        return "Virtual"
    if any(k in blob for k in ("bluetooth",)):
        return "Bluetooth"
    if any(k in blob for k in ("cellular", "wwan", "mobile")):
        return "Cellular"
    return "Other"


def _parse_ipconfig_all() -> dict[str, dict]:
    """Parse `ipconfig /all` to get adapter model, gateway and DNS per adapter."""
    adapters: dict[str, dict] = {}
    if not IS_WINDOWS:
        return adapters
    try:
        out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return adapters

    header_re = re.compile(r"^(?:.*adapter)\s+(.+?):\s*$")
    label_re = re.compile(r"^\s+([A-Za-z0-9 \-]+?)[ .]*:\s?(.*)$")
    cont_re = re.compile(r"^\s{15,}(\S.*)$")
    current = None
    field = None  # which multi-value field a continuation line belongs to
    for raw in out.splitlines():
        if not raw.strip():
            continue
        if not raw[0].isspace():  # adapter header line
            m = header_re.match(raw)
            current = m.group(1).strip() if m else None
            if current:
                adapters[current] = {"description": None, "gateway": None, "dns": []}
            field = None
            continue
        if current is None:
            continue
        d = adapters[current]
        lm = label_re.match(raw) if ":" in raw else None
        if lm:
            label = lm.group(1).strip().lower()
            val = lm.group(2).strip()
            field = label
            if "description" in label:
                d["description"] = val
            elif "default gateway" in label:
                if val[:1].isdigit():
                    d["gateway"] = val
            elif "dns servers" in label:
                if val[:1].isdigit():
                    d["dns"].append(val)
        else:  # continuation line — belongs to the previous field
            cm = cont_re.match(raw)
            if not cm:
                continue
            val = cm.group(1).strip()
            if field and "gateway" in field and not d["gateway"] and val[:1].isdigit():
                d["gateway"] = val
            elif field and "dns" in field and val[:1].isdigit():
                d["dns"].append(val)
    return adapters


def _default_gateway_dns() -> tuple[Optional[str], list[str]]:
    """Best-effort default gateway + DNS across platforms."""
    if IS_WINDOWS:
        for a in _parse_ipconfig_all().values():
            if a.get("gateway"):
                return a["gateway"], a.get("dns", [])
        return None, []
    gw = None
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"default via ([\d.]+)", out)
        gw = m.group(1) if m else None
    except (OSError, subprocess.TimeoutExpired):
        pass
    dns: list[str] = []
    try:
        with open("/etc/resolv.conf") as fh:
            dns = re.findall(r"nameserver\s+([\d.]+)", fh.read())
    except OSError:
        pass
    return gw, dns


def interfaces() -> dict[str, Any]:
    """Interface inventory, cached briefly (ipconfig parsing is the cost)."""
    global _ifaces_cache
    with _lock:
        cached = _ifaces_cache
    if cached and (time.time() - cached[0]) < _IFACE_TTL:
        return cached[1]
    data = _build_interfaces()
    with _lock:
        _ifaces_cache = (time.time(), data)
    return data


def _build_interfaces() -> dict[str, Any]:
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    io = psutil.net_io_counters(pernic=True)
    ipcfg = _parse_ipconfig_all()
    gw_default, dns_default = _default_gateway_dns()

    result = []
    for name, st in stats.items():
        a = addrs.get(name, [])
        ipv4 = next((x.address for x in a if x.family == socket.AF_INET), None)
        ipv6 = next((x.address for x in a if x.family == socket.AF_INET6), None)
        mac = next((x.address for x in a if x.family == getattr(psutil, "AF_LINK", -1)), None)
        meta = ipcfg.get(name, {})
        desc = meta.get("description")
        nic = io.get(name)
        result.append({
            "name": name,
            "type": _iface_type(name, desc or ""),
            "description": desc,
            "up": st.isup,
            "speed_mbps": st.speed or None,
            "duplex": str(st.duplex).replace("NIC_DUPLEX_", "").title() if st.duplex else None,
            "mtu": st.mtu,
            "ipv4": ipv4,
            "ipv6": ipv6.split("%")[0] if ipv6 else None,
            "mac": mac,
            "gateway": meta.get("gateway") or (gw_default if ipv4 else None),
            "dns": meta.get("dns") or (dns_default if ipv4 else []),
            "bytes_sent": nic.bytes_sent if nic else 0,
            "bytes_recv": nic.bytes_recv if nic else 0,
        })
    # active, non-loopback interfaces first
    result.sort(key=lambda r: (not (r["up"] and r["ipv4"] and r["type"] != "Loopback"), r["name"]))
    return {"interfaces": result, "gateway": gw_default, "dns": dns_default,
            "hostname": socket.gethostname()}


# --------------------------------------------------------------------------- #
# Throughput ("network power") — computed by the background sampler
# --------------------------------------------------------------------------- #
def _sample_throughput(prev, window: float) -> dict[str, Any]:
    """Compute a throughput sample against a previous counters snapshot."""
    b = psutil.net_io_counters()
    dt = max(window, 1e-3)
    a = prev if prev is not None else b
    return {
        "bytes_sent": b.bytes_sent, "bytes_recv": b.bytes_recv,
        "packets_sent": b.packets_sent, "packets_recv": b.packets_recv,
        "errin": b.errin, "errout": b.errout, "dropin": b.dropin, "dropout": b.dropout,
        "up_bps": max(0, (b.bytes_sent - a.bytes_sent) / dt),
        "down_bps": max(0, (b.bytes_recv - a.bytes_recv) / dt),
        "up_pps": round(max(0, (b.packets_sent - a.packets_sent) / dt), 1),
        "down_pps": round(max(0, (b.packets_recv - a.packets_recv) / dt), 1),
        "ts": time.time(),
    }, b


def throughput() -> dict[str, Any]:
    """Instant read of the latest sampled throughput (no blocking)."""
    with _lock:
        if _current_tp:
            return dict(_current_tp)
    # sampler not warm yet — take a fast one-shot so the first call isn't empty
    sample, _ = _sample_throughput(psutil.net_io_counters(), 1e-3)
    a = psutil.net_io_counters()
    time.sleep(0.3)
    sample, _ = _sample_throughput(a, 0.3)
    return sample


# --------------------------------------------------------------------------- #
# Active connections (netstat-alike)
# --------------------------------------------------------------------------- #
_STATE_ORDER = {"ESTABLISHED": 0, "SYN_SENT": 1, "LISTEN": 2}


def connections(limit: int = 200) -> dict[str, Any]:
    rows = []
    established = 0
    listening = 0
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {"connections": [], "message": "Access denied enumerating connections (try elevated).",
                "established": 0, "listening": 0, "total": 0}
    for c in conns:
        proc = None
        if c.pid:
            try:
                proc = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = None
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        status = c.status
        if status == "ESTABLISHED":
            established += 1
        elif status == "LISTEN":
            listening += 1
        rows.append({
            "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
            "laddr": laddr, "raddr": raddr, "status": status,
            "pid": c.pid, "process": proc,
            "remote_ip": c.raddr.ip if c.raddr else None,
        })
    rows.sort(key=lambda r: (_STATE_ORDER.get(r["status"], 9), r["process"] or "~"))
    return {"connections": rows[:limit], "total": len(rows),
            "established": established, "listening": listening}


# --------------------------------------------------------------------------- #
# Link quality
# --------------------------------------------------------------------------- #
def _ping_latency(host: str, count: int = 3) -> dict[str, Any]:
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "1200", host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
    except (OSError, subprocess.TimeoutExpired):
        return {"host": host, "reachable": False, "avg_ms": None, "loss_pct": 100}
    times = [float(x) for x in re.findall(r"time[=<]([\d.]+)\s*ms", out)]
    loss_m = re.search(r"(\d+)%\s*(?:packet )?loss", out)
    loss = int(loss_m.group(1)) if loss_m else (0 if times else 100)
    avg = round(sum(times) / len(times), 1) if times else None
    return {"host": host, "reachable": bool(times), "avg_ms": avg, "loss_pct": loss,
            "samples": len(times)}


def _measure_quality() -> dict[str, Any]:
    """Ping gateway + internet concurrently and grade the link."""
    gw, _ = _default_gateway_dns()
    result: dict[str, Any] = {"gateway_ip": gw}
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_gw = pool.submit(_ping_latency, gw) if gw else None
        f_net = pool.submit(_ping_latency, "8.8.8.8")
        result["internet"] = f_net.result()
        result["gateway"] = f_gw.result() if f_gw else {"reachable": False, "avg_ms": None, "loss_pct": 100}
    avg = result["internet"].get("avg_ms")
    loss = result["internet"].get("loss_pct", 100)
    if not result["internet"]["reachable"]:
        grade = "offline"
    elif loss > 34 or (avg or 999) > 200:
        grade = "poor"
    elif loss > 0 or (avg or 999) > 80:
        grade = "fair"
    else:
        grade = "good"
    result["grade"] = grade
    result["ts"] = time.time()
    return result


def link_quality() -> dict[str, Any]:
    """Return cached link quality; measure inline only if the cache is cold."""
    global _quality_cache
    with _lock:
        cached = _quality_cache
    if cached and (time.time() - cached[0]) < _QUALITY_TTL:
        return cached[1]
    result = _measure_quality()
    with _lock:
        _quality_cache = (time.time(), result)
    return result


# --------------------------------------------------------------------------- #
# Background sampler — keeps throughput / sockets / quality warm
# --------------------------------------------------------------------------- #
class _Sampler:
    def __init__(self, interval: float = 1.5) -> None:
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _loop(self) -> None:
        global _current_tp, _established, _quality_cache
        prev = psutil.net_io_counters()
        prev_t = time.time()
        last_conn = 0.0
        last_quality = 0.0
        while not self._stop.is_set():
            self._stop.wait(self.interval)
            now = time.time()
            sample, prev = _sample_throughput(prev, now - prev_t)
            prev_t = now
            with _lock:
                _current_tp = sample
            # established socket count is a touch heavier — refresh every ~4s
            if now - last_conn > 4:
                last_conn = now
                try:
                    est = sum(1 for c in psutil.net_connections(kind="inet")
                              if c.status == "ESTABLISHED")
                    with _lock:
                        _established = est
                except (psutil.AccessDenied, PermissionError):
                    pass
            # refresh link quality in the background so the endpoint is instant
            if now - last_quality > _QUALITY_TTL:
                last_quality = now
                try:
                    q = _measure_quality()
                    with _lock:
                        _quality_cache = (time.time(), q)
                except Exception:
                    pass

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="argus-netsampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


sampler = _Sampler()


def summary() -> dict[str, Any]:
    """Compact, non-blocking snapshot for the overview card (reads warm state)."""
    with _lock:
        tp = dict(_current_tp)
        est = _established
    if not tp:
        tp = throughput()
    return {"up_bps": tp.get("up_bps", 0), "down_bps": tp.get("down_bps", 0),
            "packets_sent": tp.get("packets_sent", 0), "packets_recv": tp.get("packets_recv", 0),
            "established": est}
