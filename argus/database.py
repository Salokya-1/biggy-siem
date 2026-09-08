"""SQLite storage layer. One file, WAL mode, thread-safe access."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable, Optional

from .config import settings

_conn: Optional[sqlite3.Connection] = None
_lock = threading.RLock()  # serialises ALL access to the single shared connection

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    source    TEXT NOT NULL,          -- agent | scanner | network | ids | auth | manual
    host      TEXT,
    category  TEXT,                   -- authentication, network, malware, process, fim...
    severity  INTEGER NOT NULL DEFAULT 3,   -- 1 info .. 5 critical
    message   TEXT NOT NULL,
    src_ip    TEXT,
    dst_ip    TEXT,
    user      TEXT,
    event_id  INTEGER,                 -- Windows / source event code (nullable)
    provider  TEXT,                    -- log provider / channel (Security, System...)
    count     INTEGER NOT NULL DEFAULT 1,  -- coalesced repeat count (NOT part of the chain)
    last_ts   REAL,                    -- most recent time this coalesced event fired
    prev_hash TEXT,                    -- tamper-evident chain: hash of the previous event
    chain_hash TEXT,                   -- sha256(prev_hash + canonical(this event))
    raw       TEXT                     -- JSON blob of the original event
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    rule_id     TEXT,
    title       TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    description TEXT,
    entity      TEXT,                  -- ip / host / user / file the alert is about
    event_id    INTEGER,
    status      TEXT NOT NULL DEFAULT 'open',  -- open | investigating | closed
    mitre       TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    category    TEXT,
    severity    INTEGER NOT NULL DEFAULT 3,
    enabled     INTEGER NOT NULL DEFAULT 1,
    match_field TEXT,                  -- event field to test
    match_type  TEXT,                  -- contains | equals | regex | threshold
    match_value TEXT,
    threshold   INTEGER DEFAULT 0,     -- for threshold rules (count in window)
    window_sec  INTEGER DEFAULT 60,
    action      TEXT DEFAULT 'alert',  -- alert | block | quarantine
    mitre       TEXT
);

CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT UNIQUE NOT NULL,
    mac        TEXT,
    hostname   TEXT,
    os_guess   TEXT,
    vendor     TEXT,
    status     TEXT NOT NULL DEFAULT 'up',   -- up | down
    open_ports TEXT,                          -- JSON list
    risk       INTEGER DEFAULT 0,
    first_seen REAL,
    last_seen  REAL
);

CREATE TABLE IF NOT EXISTS agents (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT UNIQUE NOT NULL,
    hostname   TEXT,
    os_info    TEXT,
    ip         TEXT,
    version    TEXT,
    status     TEXT NOT NULL DEFAULT 'active',  -- active | disconnected
    last_seen  REAL,
    enrolled   REAL,
    metrics    TEXT                              -- JSON: cpu, mem, disk, procs...
);

CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    kind      TEXT NOT NULL,           -- file | hash | url | network | port
    target    TEXT NOT NULL,
    verdict   TEXT,                    -- clean | suspicious | malicious | unknown | error
    engine    TEXT,                    -- local | virustotal | nmap
    positives INTEGER DEFAULT 0,
    total     INTEGER DEFAULT 0,
    sha256    TEXT,
    details   TEXT                     -- JSON
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);

CREATE TABLE IF NOT EXISTS blocklist (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    indicator TEXT NOT NULL,           -- ip | file path | hash
    kind      TEXT NOT NULL,           -- ip | file | hash
    reason    TEXT,
    source    TEXT,                    -- ids | manual | scanner
    active    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS signatures (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT NOT NULL,
    kind      TEXT NOT NULL,           -- hash | pattern | ext
    value     TEXT NOT NULL,
    severity  INTEGER DEFAULT 4,
    note      TEXT
);

CREATE TABLE IF NOT EXISTS vt_cache (
    resource TEXT PRIMARY KEY,
    ts       REAL NOT NULL,
    data     TEXT
);

-- ---- Forensics / DFIR ----------------------------------------------------
CREATE TABLE IF NOT EXISTS cases (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ref       TEXT UNIQUE,             -- CASE-0001
    title     TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'open',   -- open | active | contained | closed
    severity  INTEGER NOT NULL DEFAULT 3,
    assignee  TEXT,
    summary   TEXT,
    created   REAL NOT NULL,
    updated   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS case_items (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id  INTEGER NOT NULL,
    kind     TEXT NOT NULL,            -- event | alert | ioc | note | artifact
    ref_id   TEXT,                     -- id of the linked record (if any)
    title    TEXT,
    note     TEXT,
    added_by TEXT,
    added_ts REAL NOT NULL,
    data     TEXT
);
CREATE INDEX IF NOT EXISTS idx_case_items_case ON case_items(case_id);

CREATE TABLE IF NOT EXISTS iocs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,            -- ip | hash | domain | url | user | file
    value    TEXT NOT NULL,
    severity INTEGER NOT NULL DEFAULT 4,
    source   TEXT,
    note     TEXT,
    active   INTEGER NOT NULL DEFAULT 1,
    hits     INTEGER NOT NULL DEFAULT 0,
    last_hit REAL,
    added_ts REAL NOT NULL,
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS artifacts (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,            -- backup | export | triage | case-bundle
    name     TEXT NOT NULL,
    path     TEXT NOT NULL,
    sha256   TEXT,
    size     INTEGER,
    host     TEXT,
    records  INTEGER,
    note     TEXT,
    created  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts(kind);
"""


def get_conn() -> sqlite3.Connection:
    """One shared connection for the whole process. Every read/write goes
    through `_lock`, so operations never contend and there are no WAL-checkpoint
    stalls from many competing connections — each op is a fast, serial <50ms
    call, which is ideal for a single-node SIEM."""
    global _conn
    with _lock:
        if _conn is None:
            conn = sqlite3.connect(settings.DB_PATH, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")   # fast writes, crash-safe in WAL
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA cache_size=-16000")    # ~16 MB page cache
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            conn.execute("PRAGMA foreign_keys=ON")
            _conn = conn
        return _conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns introduced after a database was first created."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)").fetchall()}
    for name, ddl in (("event_id", "event_id INTEGER"), ("provider", "provider TEXT"),
                      ("count", "count INTEGER NOT NULL DEFAULT 1"), ("last_ts", "last_ts REAL"),
                      ("prev_hash", "prev_hash TEXT"), ("chain_hash", "chain_hash TEXT")):
        if name not in cols:
            conn.execute(f"ALTER TABLE events ADD COLUMN {ddl}")
    conn.commit()


def init_db() -> None:
    conn = get_conn()
    conn.executescript(SCHEMA)
    _migrate(conn)
    conn.commit()


def query(sql: str, params: Iterable[Any] = ()) -> list[dict]:
    with _lock:
        cur = get_conn().execute(sql, tuple(params))
        return [dict(r) for r in cur.fetchall()]


def query_one(sql: str, params: Iterable[Any] = ()) -> Optional[dict]:
    with _lock:
        cur = get_conn().execute(sql, tuple(params))
        row = cur.fetchone()
        return dict(row) if row else None


def execute(sql: str, params: Iterable[Any] = ()) -> int:
    with _lock:
        conn = get_conn()
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.lastrowid


def now() -> float:
    return time.time()


def dumps(obj: Any) -> str:
    return json.dumps(obj, default=str)


def loads(text: Optional[str], default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return default
