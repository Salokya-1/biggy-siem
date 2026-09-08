"""Configuration loaded from environment / .env (no external deps)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
WEB_DIR = BASE_DIR / "web"


def _load_dotenv() -> None:
    """Minimal .env loader so we don't depend on python-dotenv."""
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv()


def _default_watch_dir() -> str:
    downloads = Path.home() / "Downloads"
    return str(downloads if downloads.exists() else Path.home())


class Settings:
    SECRET: str = os.environ.get("ARGUS_SECRET", "argus-dev-secret-change-me")
    ADMIN_USER: str = os.environ.get("ARGUS_ADMIN_USER", "admin")
    ADMIN_PASSWORD: str = os.environ.get("ARGUS_ADMIN_PASSWORD", "argus")
    VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    AGENT_KEY: str = os.environ.get("ARGUS_AGENT_KEY", "argus-agent-key")
    WATCH_DIR: str = os.environ.get("ARGUS_WATCH_DIR", "").strip() or _default_watch_dir()
    HOST: str = os.environ.get("ARGUS_HOST", "127.0.0.1")
    PORT: int = int(os.environ.get("ARGUS_PORT", "8000"))
    DATA_DIR: Path = DATA_DIR
    WEB_DIR: Path = WEB_DIR
    DB_PATH: Path = DATA_DIR / "argus.db"
    EVIDENCE_DIR: Path = DATA_DIR / "evidence"   # compressed backups, exports, triage snapshots

    TOKEN_TTL_SECONDS: int = 60 * 60 * 12  # 12h sessions

    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY)


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
