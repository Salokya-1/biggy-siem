"""Argus — an open-source SIEM / XDR platform.

Modules
-------
config       Environment-driven configuration.
database     SQLite schema + thin data-access helpers.
security     Password hashing and signed session tokens (stdlib only).
integrations VirusTotal and other threat-intelligence connectors.
scanners     The self-built file/malware scanner.
network      nmap wrapper + device discovery / monitoring.
core         Event pipeline, IDS rule engine, IPS active response.
app          FastAPI application (REST API + WebSocket + web UI).
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
