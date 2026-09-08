#!/usr/bin/env python3
"""Argus SIEM launcher.

    python run.py

Reads host/port from the environment (.env) and starts the ASGI server.
"""
from __future__ import annotations

import sys

import uvicorn

from argus.config import settings

# Make box-drawing output safe on legacy Windows codepages.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def main() -> None:
    banner = f"""
    ┌────────────────────────────────────────────────┐
    │   BIGGY  ·  Security Information & Event Mgmt   │
    ├────────────────────────────────────────────────┤
    │  Console : http://{settings.HOST}:{settings.PORT:<5}                   │
    │  Login   : {settings.ADMIN_USER} / {settings.ADMIN_PASSWORD:<12}                    │
    │  VirusTotal : {'enabled ' if settings.virustotal_enabled else 'offline '}                         │
    │  Watch dir  : {settings.WATCH_DIR[:32]:<32} │
    └────────────────────────────────────────────────┘
    """
    print(banner)
    uvicorn.run("argus.app:app", host=settings.HOST, port=settings.PORT, reload=False)


if __name__ == "__main__":
    main()
