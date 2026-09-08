"""VirusTotal API v3 connector.

Docs: https://docs.virustotal.com/reference/overview
Endpoints used:
  GET  /api/v3/files/{sha256}      file reputation by hash
  POST /api/v3/files               upload a file for scanning
  GET  /api/v3/urls/{id}           URL report (id = base64url(url) w/o padding)
  POST /api/v3/urls                submit a URL
  GET  /api/v3/ip_addresses/{ip}   IP reputation
  GET  /api/v3/domains/{domain}    domain reputation

All requests carry the `x-apikey` header. Results are cached in `vt_cache`
so repeated lookups don't burn the (rate-limited) public API quota.
When no API key is configured every call returns a graceful "offline" result.
"""
from __future__ import annotations

import base64
from typing import Any, Optional

import httpx

from .. import database as db
from ..config import settings

BASE = "https://www.virustotal.com/api/v3"
_CACHE_TTL = 3600  # 1h


def _headers() -> dict[str, str]:
    return {"x-apikey": settings.VIRUSTOTAL_API_KEY, "accept": "application/json"}


def _cache_get(resource: str) -> Optional[dict]:
    row = db.query_one("SELECT ts, data FROM vt_cache WHERE resource = ?", (resource,))
    if row and (db.now() - row["ts"]) < _CACHE_TTL:
        return db.loads(row["data"])
    return None


def _cache_put(resource: str, data: dict) -> None:
    db.execute(
        "INSERT OR REPLACE INTO vt_cache (resource, ts, data) VALUES (?,?,?)",
        (resource, db.now(), db.dumps(data)),
    )


def _summarise(attributes: dict) -> dict[str, Any]:
    stats = attributes.get("last_analysis_stats", {}) or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    # Real VT data is noisy: a single low-confidence vendor flag (e.g. 1/91 on a
    # popular domain) shouldn't read as "malicious". Require multiple detections
    # for a hard verdict; 1-2 hits are surfaced as "suspicious" for the analyst.
    if malicious >= 3:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 1:
        verdict = "suspicious"
    elif total:
        verdict = "clean"
    else:
        verdict = "unknown"
    return {
        "verdict": verdict,
        "positives": malicious + suspicious,
        "total": total,
        "stats": stats,
        "reputation": attributes.get("reputation"),
        "names": attributes.get("names", [])[:5],
        "type": attributes.get("type_description"),
        "size": attributes.get("size"),
        "first_seen": attributes.get("first_submission_date"),
        "threat_label": (attributes.get("popular_threat_classification") or {}).get(
            "suggested_threat_label"
        ),
    }


def _offline(resource: str) -> dict[str, Any]:
    return {
        "enabled": False,
        "resource": resource,
        "verdict": "unknown",
        "positives": 0,
        "total": 0,
        "message": "VirusTotal disabled — set VIRUSTOTAL_API_KEY to enable cloud reputation.",
    }


async def _get(path: str, resource_key: str) -> dict[str, Any]:
    if not settings.virustotal_enabled:
        return _offline(resource_key)
    cached = _cache_get(resource_key)
    if cached:
        return {**cached, "cached": True}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{BASE}{path}", headers=_headers())
        if r.status_code == 404:
            result = {"enabled": True, "resource": resource_key, "verdict": "unknown",
                      "positives": 0, "total": 0, "message": "Not found in VirusTotal."}
            return result
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        result = {"enabled": True, "resource": resource_key, **_summarise(attrs)}
        _cache_put(resource_key, result)
        return result
    except httpx.HTTPError as exc:
        return {"enabled": True, "resource": resource_key, "verdict": "error",
                "positives": 0, "total": 0, "message": f"VirusTotal error: {exc}"}


async def lookup_hash(sha256: str) -> dict[str, Any]:
    return await _get(f"/files/{sha256}", sha256)


async def lookup_ip(ip: str) -> dict[str, Any]:
    return await _get(f"/ip_addresses/{ip}", ip)


async def lookup_domain(domain: str) -> dict[str, Any]:
    return await _get(f"/domains/{domain}", domain)


async def lookup_url(url: str) -> dict[str, Any]:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    return await _get(f"/urls/{url_id}", url)


async def upload_file(path: str, filename: str, content: bytes) -> dict[str, Any]:
    """Submit a file to VirusTotal for analysis (returns the analysis id)."""
    if not settings.virustotal_enabled:
        return _offline(filename)
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(
                f"{BASE}/files",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                files={"file": (filename, content)},
            )
        r.raise_for_status()
        analysis_id = r.json().get("data", {}).get("id")
        return {"enabled": True, "submitted": True, "analysis_id": analysis_id,
                "message": "File submitted to VirusTotal for analysis."}
    except httpx.HTTPError as exc:
        return {"enabled": True, "submitted": False, "message": f"Upload failed: {exc}"}
