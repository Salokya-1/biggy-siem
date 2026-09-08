"""Host-agent enrolment, heartbeats and telemetry ingestion.

Agents (see agent/argus_agent.py) authenticate with the shared ARGUS_AGENT_KEY,
enrol once to receive an agent_id, then POST periodic heartbeats carrying system
metrics and locally-observed security events. Agents that miss heartbeats are
marked disconnected by `sweep_stale`.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from . import database as db
from .core.pipeline import ingest_event

STALE_AFTER = 180  # seconds without a heartbeat -> disconnected


def enroll(hostname: str, os_info: str, ip: str, version: str = "1.0") -> dict[str, Any]:
    agent_id = hashlib.sha1(f"{hostname}|{ip}|{os_info}".encode()).hexdigest()[:16]
    existing = db.query_one("SELECT id FROM agents WHERE agent_id = ?", (agent_id,))
    if existing:
        db.execute(
            "UPDATE agents SET hostname=?, os_info=?, ip=?, version=?, status='active', last_seen=? WHERE agent_id=?",
            (hostname, os_info, ip, version, db.now(), agent_id),
        )
    else:
        db.execute(
            """INSERT INTO agents (agent_id, hostname, os_info, ip, version, status, last_seen, enrolled, metrics)
               VALUES (?,?,?,?,?, 'active', ?, ?, '{}')""",
            (agent_id, hostname, os_info, ip, version, db.now(), db.now()),
        )
        ingest_event(source="agent", category="agent", severity=2,
                     message=f"Host agent enrolled: {hostname} ({ip})", host=hostname, src_ip=ip)
    return {"agent_id": agent_id}


def heartbeat(agent_id: str, metrics: dict[str, Any], events: list[dict] | None = None) -> dict[str, Any]:
    agent = db.query_one("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
    if not agent:
        return {"ok": False, "error": "unknown agent — enrol first"}

    db.execute("UPDATE agents SET status='active', last_seen=?, metrics=? WHERE agent_id=?",
               (db.now(), db.dumps(metrics), agent_id))

    hostname = agent["hostname"]
    # derive events from resource anomalies
    cpu = metrics.get("cpu_percent", 0)
    mem = metrics.get("mem_percent", 0)
    if cpu >= 92:
        ingest_event(source="agent", category="performance", severity=3,
                     message=f"Sustained high CPU {cpu}% on {hostname}", host=hostname)
    if mem >= 92:
        ingest_event(source="agent", category="performance", severity=3,
                     message=f"High memory {mem}% on {hostname}", host=hostname)

    # forward agent-observed security events into the pipeline
    for ev in (events or []):
        ingest_event(
            source=ev.get("source", "agent"),
            category=ev.get("category", "endpoint"),
            severity=int(ev.get("severity", 3)),
            message=ev.get("message", "agent event"),
            host=hostname,
            src_ip=ev.get("src_ip") or agent["ip"],
            user=ev.get("user"),
            event_id=ev.get("event_id"),
            provider=ev.get("provider"),
            level=ev.get("level"),
            raw=ev,
        )
    return {"ok": True, "interval": 30}


def sweep_stale() -> int:
    cutoff = db.now() - STALE_AFTER
    stale = db.query("SELECT agent_id, hostname FROM agents WHERE status='active' AND last_seen < ?", (cutoff,))
    for a in stale:
        db.execute("UPDATE agents SET status='disconnected' WHERE agent_id=?", (a["agent_id"],))
        ingest_event(source="agent", category="agent", severity=3,
                     message=f"Host agent disconnected: {a['hostname']}", host=a["hostname"])
    return len(stale)
