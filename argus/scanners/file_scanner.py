"""Argus Engine — a self-contained file/malware scanner.

It does NOT depend on VirusTotal to reach a verdict. Detection combines:

1. Hash signatures      — MD5/SHA1/SHA256 matched against the `signatures` table
                          (and the built-in set, incl. the EICAR test file).
2. Extension / naming    — dangerous extensions, double-extension masquerading.
3. Content heuristics    — YARA-style byte/string patterns: shell one-liners,
                          obfuscation, embedded PEs in documents, macro triggers.
4. Entropy analysis      — high Shannon entropy suggests packing/encryption.

Each hit contributes to a weighted risk score that maps to a verdict:
    0-19  clean   20-49 suspicious   50+ malicious
VirusTotal enrichment (by hash) is layered on top by the API when available.
"""
from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any

from .. import database as db

MAX_READ = 4 * 1024 * 1024        # bytes read/inspected per file (header is enough for heuristics)
CONTENT_SCAN = 1 * 1024 * 1024    # cap regex content scanning to the first 1 MB
ENTROPY_SAMPLE = 64 * 1024        # entropy from a 64 KB sample (representative, cheap)

# Built-in hash signatures (always present, independent of the DB).
BUILTIN_HASHES = {
    # EICAR standard anti-virus test file (harmless, universally recognised)
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": (
        "EICAR-Test-File", 5),
    "3395856ce81f2b7382dee72602f798b642f14140": ("EICAR-Test-File", 5),
    "44d88612fea8a8f36de82e1278abb02f": ("EICAR-Test-File", 5),
}

DANGEROUS_EXT = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".ws", ".wsf", ".wsh", ".ps1", ".psm1", ".jar", ".hta", ".msi",
    ".dll", ".cpl", ".lnk", ".reg", ".sh", ".apk",
}
DOC_EXT = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf"}

# (name, compiled pattern, weight, description)
CONTENT_RULES = [
    ("EICAR_Signature", re.compile(rb"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"), 60,
     "EICAR anti-virus test string"),
    ("PowerShell_EncodedCommand", re.compile(rb"(?i)powershell.{0,40}-enc(odedcommand)?\s"), 35,
     "PowerShell encoded command execution"),
    ("PowerShell_Download", re.compile(rb"(?i)(iex|invoke-expression).{0,60}(downloadstring|webclient|iwr|curl)"), 40,
     "PowerShell in-memory download & execute"),
    ("Obfuscated_Base64", re.compile(rb"(?i)FromBase64String\s*\("), 20,
     "Base64 payload decoding"),
    ("Suspicious_Eval", re.compile(rb"(?i)\beval\s*\(\s*(atob|unescape|String\.fromCharCode)"), 30,
     "Obfuscated eval() payload"),
    ("Shell_Reverse", re.compile(rb"(?i)(/bin/(ba)?sh|cmd\.exe).{0,20}(>&|nc\s|-e\s)"), 45,
     "Reverse-shell command pattern"),
    ("MSHTA_Abuse", re.compile(rb"(?i)mshta\s+(vbscript|javascript|https?):"), 35,
     "mshta script execution"),
    ("Macro_AutoExec", re.compile(rb"(?i)(Auto_?Open|Document_?Open|Workbook_?Open)\b"), 25,
     "Office macro auto-execution trigger"),
    ("Embedded_PE", re.compile(rb"MZ.{0,200}This program cannot be run in DOS mode"), 30,
     "Embedded Windows executable"),
    ("Windows_Persistence", re.compile(rb"(?i)(schtasks|reg\s+add).{0,60}(run|startup)"), 25,
     "Persistence via registry/scheduled task"),
    ("Ransom_Note", re.compile(rb"(?i)(your files (have been|are) encrypted|bitcoin.{0,40}decrypt)"), 40,
     "Ransomware note indicators"),
]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _verdict_for(score: int) -> str:
    if score >= 50:
        return "malicious"
    if score >= 20:
        return "suspicious"
    return "clean"


def scan_bytes(name: str, content: bytes) -> dict[str, Any]:
    """Scan an in-memory buffer. Returns a full report dict."""
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    ext = Path(name).suffix.lower()

    reasons: list[dict] = []
    score = 0

    # 1. hash signatures ---------------------------------------------------
    for h in (sha256, sha1, md5):
        if h in BUILTIN_HASHES:
            sig_name, sev = BUILTIN_HASHES[h]
            score += 60
            reasons.append({"type": "hash", "name": sig_name, "detail": f"Known-bad hash ({h[:12]}…)"})
    for row in db.query("SELECT name, value, severity FROM signatures WHERE kind = 'hash'"):
        if row["value"].lower() in (sha256, sha1, md5):
            score += 55
            reasons.append({"type": "hash", "name": row["name"], "detail": "Custom hash signature"})

    # 2. extension / naming ------------------------------------------------
    stem = Path(name).stem.lower()
    if ext in DANGEROUS_EXT:
        score += 12
        reasons.append({"type": "extension", "name": "Executable content",
                        "detail": f"Potentially dangerous extension '{ext}'"})
    # double extension masquerade e.g. invoice.pdf.exe
    if re.search(r"\.(pdf|doc|docx|xls|jpg|png|txt)$", stem):
        score += 25
        reasons.append({"type": "naming", "name": "Double extension",
                        "detail": f"File masquerades as a document: '{name}'"})
    for row in db.query("SELECT name, value FROM signatures WHERE kind = 'ext'"):
        if ext == row["value"].lower():
            score += 15
            reasons.append({"type": "extension", "name": row["name"], "detail": f"Blocked extension '{ext}'"})

    # 3. content pattern rules --------------------------------------------
    sample = content[:CONTENT_SCAN]
    for rule_name, pattern, weight, desc in CONTENT_RULES:
        if pattern.search(sample):
            score += weight
            reasons.append({"type": "yara", "name": rule_name, "detail": desc})
    for row in db.query("SELECT name, value, severity FROM signatures WHERE kind = 'pattern'"):
        try:
            if re.search(row["value"].encode(), sample, re.I):
                score += 30
                reasons.append({"type": "yara", "name": row["name"], "detail": "Custom content signature"})
        except re.error:
            continue

    # 4. entropy -----------------------------------------------------------
    entropy = _shannon_entropy(sample[:ENTROPY_SAMPLE])
    if entropy >= 7.4 and ext in DANGEROUS_EXT:
        score += 15
        reasons.append({"type": "entropy", "name": "High entropy",
                        "detail": f"Entropy {entropy}/8.0 suggests packing/encryption"})

    verdict = _verdict_for(score)
    return {
        "name": name,
        "size": len(content),
        "sha256": sha256, "sha1": sha1, "md5": md5,
        "extension": ext,
        "entropy": entropy,
        "score": min(score, 100),
        "verdict": verdict,
        "reasons": reasons,
        "engine": "argus-engine",
    }


def scan_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"name": str(p), "verdict": "error", "score": 0, "reasons": [],
                "message": "File not found"}
    try:
        # Read ONLY the first MAX_READ bytes — never pull a multi-GB file into RAM.
        with open(p, "rb") as fh:
            content = fh.read(MAX_READ)
    except (PermissionError, OSError) as exc:
        return {"name": str(p), "verdict": "error", "score": 0, "reasons": [],
                "message": f"Cannot read file: {exc}"}
    report = scan_bytes(p.name, content)
    report["path"] = str(p)
    return report
