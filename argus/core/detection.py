"""IDS rule engine + IPS active response.

The engine evaluates every ingested event against the enabled rules. Rules are
data (stored in the `rules` table), so operators add detections without code.

Match types
-----------
contains   substring match on a field (case-insensitive)
equals     exact match
regex      Python regular expression
threshold  N or more matching events from the same entity within a time window
           (brute-force / port-scan / flood detection)

Actions
-------
alert       raise an alert only
block        alert + add the source IP to the IPS blocklist (active response)
quarantine   alert + flag the file/host indicator for quarantine
"""
from __future__ import annotations

import re
import time
from typing import Optional

from .. import database as db
from .bus import bus

SEVERITY_LABELS = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}


def _field(event: dict, name: str) -> str:
    return str(event.get(name, "") or "")


def _entity(event: dict) -> str:
    return _field(event, "src_ip") or _field(event, "host") or _field(event, "user") or "-"


def _matches(rule: dict, event: dict) -> bool:
    field_val = _field(event, rule["match_field"]).lower()
    target = (rule.get("match_value") or "").lower()
    mt = rule["match_type"]
    if mt == "contains":
        return target in field_val
    if mt == "equals":
        return field_val == target
    if mt == "regex":
        try:
            return re.search(rule["match_value"], _field(event, rule["match_field"]), re.I) is not None
        except re.error:
            return False
    return False


def _threshold_tripped(rule: dict, event: dict) -> bool:
    """True when >= threshold events matched this rule's field/value for the
    same entity within the window."""
    window = rule.get("window_sec") or 60
    since = time.time() - window
    entity = _entity(event)
    like = f"%{rule.get('match_value','')}%"
    # SUM(count) so coalesced repeats still count; last_ts so a coalesced row that
    # keeps firing stays inside the window.
    rows = db.query(
        """SELECT COALESCE(SUM(count), 0) c FROM events
           WHERE COALESCE(last_ts, ts) >= ? AND (src_ip = ? OR host = ? OR user = ?)
             AND message LIKE ?""",
        (since, entity, entity, entity, like),
    )
    return rows and rows[0]["c"] >= (rule.get("threshold") or 1)


def _raise_alert(rule: dict, event: dict, event_id: Optional[int]) -> Optional[dict]:
    entity = _entity(event)
    # de-dup: don't re-raise the same rule+entity alert within 60s (kills bursts)
    dup = db.query_one(
        "SELECT id FROM alerts WHERE rule_id = ? AND entity = ? AND ts > ? AND status = 'open' LIMIT 1",
        (rule["id"], entity, db.now() - 60),
    )
    if dup:
        return None
    alert_id = db.execute(
        """INSERT INTO alerts (ts, rule_id, title, severity, description, entity, event_id, status, mitre)
           VALUES (?,?,?,?,?,?,?, 'open', ?)""",
        (
            db.now(), rule["id"], rule["name"], rule["severity"],
            rule.get("description") or event.get("message"),
            entity, event_id, rule.get("mitre"),
        ),
    )
    alert = {
        "id": alert_id, "ts": db.now(), "rule_id": rule["id"], "title": rule["name"],
        "severity": rule["severity"], "severity_label": SEVERITY_LABELS.get(rule["severity"], "medium"),
        "entity": entity, "description": rule.get("description"), "mitre": rule.get("mitre"),
        "status": "open",
    }
    bus.publish_threadsafe({"type": "alert", "data": alert})
    return alert


def block_indicator(indicator: str, kind: str, reason: str, source: str = "ids") -> None:
    existing = db.query_one(
        "SELECT id FROM blocklist WHERE indicator = ? AND active = 1", (indicator,)
    )
    if existing:
        return
    db.execute(
        "INSERT INTO blocklist (ts, indicator, kind, reason, source, active) VALUES (?,?,?,?,?,1)",
        (db.now(), indicator, kind, reason, source),
    )
    bus.publish_threadsafe(
        {"type": "block", "data": {"indicator": indicator, "kind": kind, "reason": reason}}
    )


def _apply_action(rule: dict, event: dict) -> Optional[str]:
    action = rule.get("action") or "alert"
    if action == "block":
        ip = _field(event, "src_ip")
        if ip:
            block_indicator(ip, "ip", f"Auto-blocked by rule '{rule['name']}'", "ids")
            return f"blocked {ip}"
    elif action == "quarantine":
        path = event.get("file") or event.get("host") or _entity(event)
        block_indicator(path, "file", f"Quarantined by rule '{rule['name']}'", "ids")
        return f"quarantined {path}"
    return None


_rules_cache: Optional[list[dict]] = None
_rules_cache_ts: float = 0.0
_RULES_TTL = 5.0


def _enabled_rules() -> list[dict]:
    """Enabled rules, cached briefly so we don't query per-event under load."""
    global _rules_cache, _rules_cache_ts
    now = time.time()
    if _rules_cache is None or (now - _rules_cache_ts) > _RULES_TTL:
        _rules_cache = db.query("SELECT * FROM rules WHERE enabled = 1")
        _rules_cache_ts = now
    return _rules_cache


def evaluate(event: dict, event_id: Optional[int], threshold_only: bool = False) -> list[dict]:
    """Run enabled rules against an event. Returns the alerts raised.
    `threshold_only` (used for coalesced repeats) evaluates only threshold rules,
    so counters stay accurate without re-firing content/regex alerts on every hit."""
    alerts: list[dict] = []
    for rule in _enabled_rules():
        if threshold_only and rule["match_type"] != "threshold":
            continue
        hit = False
        if rule["match_type"] == "threshold":
            if not rule.get("match_value") or _matches({**rule, "match_type": "contains"}, event):
                hit = _threshold_tripped(rule, event)
        else:
            hit = _matches(rule, event)
        if hit:
            alert = _raise_alert(rule, event, event_id)
            if alert is None:   # de-duplicated
                continue
            response = _apply_action(rule, event)
            if response:
                alert["response"] = response
            alerts.append(alert)
    return alerts
