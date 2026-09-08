"""First-run seeding: admin user, default detection rules, signatures, and a
small amount of realistic demo telemetry so the console isn't empty."""
from __future__ import annotations

import random

from . import database as db
from .config import settings
from .forensics import integrity
from .security import hash_password

DEFAULT_RULES = [
    # id, name, description, category, severity, match_field, match_type, match_value, threshold, window, action, mitre
    ("R001", "SSH/RDP Brute Force", "Multiple failed logins from one source in a short window",
     "authentication", 4, "message", "threshold", "failed login", 5, 120, "block", "T1110"),
    ("R002", "Malware Detected (scanner)", "Argus scan engine flagged a malicious file",
     "malware", 5, "message", "contains", "malicious file detected", 0, 0, "quarantine", "T1204"),
    ("R003", "Suspicious PowerShell", "Encoded / download-cradle PowerShell activity",
     "process", 4, "message", "regex", r"powershell.*(-enc|downloadstring|iex)", 0, 0, "alert", "T1059.001"),
    ("R004", "Port Scan Detected", "Host contacted many ports/hosts rapidly",
     "network", 3, "message", "threshold", "connection to port", 15, 60, "block", "T1046"),
    ("R005", "Risky Service Exposed", "Cleartext or high-risk service reachable on an asset",
     "network", 4, "message", "contains", "risky", 0, 0, "alert", "T1046"),
    ("R006", "Known-Bad IP Contact", "Traffic to/from a flagged threat-intel indicator",
     "network", 4, "message", "contains", "known-bad ip", 0, 0, "block", "T1071"),
    ("R007", "New Admin Account", "A privileged account was created",
     "authentication", 4, "message", "contains", "admin account created", 0, 0, "alert", "T1136"),
    ("R008", "Sensitive File Change (FIM)", "Monitored system file was modified",
     "fim", 3, "message", "contains", "integrity change", 0, 0, "alert", "T1565"),
    ("R009", "Ransomware Behaviour", "Mass file rename / ransom-note indicators",
     "malware", 5, "message", "contains", "ransom", 0, 0, "quarantine", "T1486"),
    ("R010", "Data Exfiltration Volume", "Large outbound transfer from an endpoint",
     "network", 4, "message", "contains", "large outbound", 0, 0, "alert", "T1041"),
]

DEFAULT_SIGNATURES = [
    ("EICAR-Test", "hash", "44d88612fea8a8f36de82e1278abb02f", 5, "EICAR test file MD5"),
    ("Blocked-Screensaver", "ext", ".scr", 4, "Screensaver executables are a common lure"),
    ("Mimikatz-String", "pattern", "sekurlsa|gentilkiwi|mimikatz", 5, "Mimikatz credential dumper"),
    ("Cobalt-Strike-Beacon", "pattern", "ReflectiveLoader|beacon\\.dll", 5, "Cobalt Strike beacon"),
]

DEMO_HOSTS = ["WIN-DC01", "WIN-WKS07", "UBUNTU-WEB1", "MACBOOK-PRO", "FW-EDGE01"]
DEMO_USERS = ["administrator", "j.doe", "svc_backup", "root", "guest"]


def _seed_admin() -> None:
    if db.query_one("SELECT id FROM users LIMIT 1"):
        return
    db.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
        (settings.ADMIN_USER, hash_password(settings.ADMIN_PASSWORD), "admin", db.now()),
    )


def _seed_rules() -> None:
    if db.query_one("SELECT id FROM rules LIMIT 1"):
        return
    for r in DEFAULT_RULES:
        db.execute(
            """INSERT INTO rules (id, name, description, category, severity, enabled,
                                  match_field, match_type, match_value, threshold,
                                  window_sec, action, mitre)
               VALUES (?,?,?,?,?,1,?,?,?,?,?,?,?)""",
            (r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11]),
        )


def _seed_signatures() -> None:
    if db.query_one("SELECT id FROM signatures LIMIT 1"):
        return
    for s in DEFAULT_SIGNATURES:
        db.execute("INSERT INTO signatures (name, kind, value, severity, note) VALUES (?,?,?,?,?)", s)


def _seed_demo_telemetry() -> None:
    if db.query_one("SELECT id FROM events LIMIT 1"):
        return
    now = db.now()
    samples = [
        (2, "authentication", "Successful login for j.doe from 10.0.0.24", "WIN-WKS07", "j.doe", "10.0.0.24"),
        (2, "network", "Outbound HTTPS connection to update.microsoft.com", "WIN-DC01", None, "10.0.0.10"),
        (4, "authentication", "Failed login for administrator from 45.146.164.12", "WIN-DC01", "administrator", "45.146.164.12"),
        (3, "process", "Process launched: chrome.exe by j.doe", "WIN-WKS07", "j.doe", None),
        (2, "fim", "File read: /etc/passwd on UBUNTU-WEB1", "UBUNTU-WEB1", "root", None),
        (5, "malware", "Malicious file detected: invoice.pdf.exe (Embedded_PE)", "argus-scanner", None, None),
        (3, "network", "Connection to port 3389 (RDP) from 185.220.101.7", "FW-EDGE01", None, "185.220.101.7"),
        (2, "authentication", "Successful login for administrator from 10.0.0.5", "WIN-DC01", "administrator", "10.0.0.5"),
    ]
    for i, (sev, cat, msg, host, user, ip) in enumerate(samples):
        ts = now - (len(samples) - i) * 47
        event = {"ts": ts, "source": "demo", "host": host, "category": cat,
                 "severity": sev, "message": msg, "src_ip": ip, "dst_ip": None,
                 "user": user, "event_id": None, "provider": None}

        def _store(prev_hash, chain_hash, ev=event):
            return db.execute(
                """INSERT INTO events (ts, source, host, category, severity, message,
                                       src_ip, user, prev_hash, chain_hash, raw)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (ev["ts"], ev["source"], ev["host"], ev["category"], ev["severity"],
                 ev["message"], ev["src_ip"], ev["user"], prev_hash, chain_hash, "{}"),
            )

        integrity.link_and_store(event, _store)
    # a couple of demo alerts + devices
    db.execute(
        """INSERT INTO alerts (ts, rule_id, title, severity, description, entity, status, mitre)
           VALUES (?,?,?,?,?,?,?,?)""",
        (now - 200, "R001", "SSH/RDP Brute Force", 4,
         "6 failed logins for administrator from 45.146.164.12", "45.146.164.12", "open", "T1110"),
    )
    db.execute(
        """INSERT INTO alerts (ts, rule_id, title, severity, description, entity, status, mitre)
           VALUES (?,?,?,?,?,?,?,?)""",
        (now - 60, "R002", "Malware Detected (scanner)", 5,
         "invoice.pdf.exe flagged malicious (score 90)", "invoice.pdf.exe", "open", "T1204"),
    )
    db.execute("INSERT INTO blocklist (ts, indicator, kind, reason, source, active) VALUES (?,?,?,?,?,1)",
               (now - 55, "45.146.164.12", "ip", "Auto-blocked by rule 'SSH/RDP Brute Force'", "ids"))


DEFAULT_IOCS = [
    ("ip", "185.220.101.7", 4, "threat-intel", "Known Tor exit / scanning source"),
    ("ip", "45.146.164.12", 5, "incident", "Brute-force source from prior incident"),
    ("hash", "44d88612fea8a8f36de82e1278abb02f", 5, "threat-intel", "EICAR test-file MD5"),
    ("domain", "malware-traffic-analysis.net", 3, "threat-intel", "Sample malware traffic domain"),
    ("user", "guest", 3, "policy", "Guest account activity should be reviewed"),
]


def _seed_iocs() -> None:
    if db.query_one("SELECT id FROM iocs LIMIT 1"):
        return
    for kind, value, sev, src, note in DEFAULT_IOCS:
        db.execute("""INSERT OR IGNORE INTO iocs (kind, value, severity, source, note, active, hits, added_ts)
                      VALUES (?,?,?,?,?,1,0,?)""", (kind, value, sev, src, note, db.now()))


def _seed_case() -> None:
    if db.query_one("SELECT id FROM cases LIMIT 1"):
        return
    n = db.now()
    cid = db.execute(
        """INSERT INTO cases (ref, title, status, severity, assignee, summary, created, updated)
           VALUES ('CASE-0001', ?, 'active', 4, 'admin', ?, ?, ?)""",
        ("Suspected brute-force from 45.146.164.12",
         "Multiple failed admin logons followed by an auto-block. Investigating source and scope.",
         n - 300, n - 60),
    )
    db.execute("""INSERT INTO case_items (case_id, kind, ref_id, title, note, added_by, added_ts, data)
                  VALUES (?, 'note', '', 'Opening note', ?, 'admin', ?, '{}')""",
               (cid, "Triage started after brute-force alert. Source IP added to IOC watchlist.", n - 250))


def seed_all() -> None:
    db.init_db()
    _seed_admin()
    _seed_rules()
    _seed_signatures()
    _seed_demo_telemetry()
    _seed_iocs()
    _seed_case()
