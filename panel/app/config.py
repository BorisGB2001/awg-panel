"""Настройки из переменных окружения (.env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    return int(v) if v else default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("PANEL_DATA", "/data")))
    panel_host: str = field(default_factory=lambda: os.environ.get("PANEL_HOST", ""))
    panel_port: int = field(default_factory=lambda: _int("PANEL_PORT", 14443))
    admin_user: str = field(default_factory=lambda: os.environ.get("ADMIN_USER", "admin"))
    admin_password_hash: str = field(default_factory=lambda: os.environ.get("ADMIN_PASSWORD_HASH", ""))
    totp_secret: str = field(default_factory=lambda: os.environ.get("TOTP_SECRET", ""))
    session_secret: str = field(default_factory=lambda: os.environ.get("SESSION_SECRET", ""))
    data_key: str = field(default_factory=lambda: os.environ.get("DATA_KEY", ""))
    cookie_secure: bool = field(default_factory=lambda: _bool("COOKIE_SECURE", True))
    session_hours: int = field(default_factory=lambda: _int("SESSION_HOURS", 12))

    public_host: str = field(default_factory=lambda: os.environ.get("PUBLIC_HOST", ""))
    awg_process_match: str = field(default_factory=lambda: os.environ.get("AWG_PROCESS_MATCH", "amneziawg-go awg0"))
    awg_iface: str = field(default_factory=lambda: os.environ.get("AWG_IFACE", "awg0"))
    awg_dir: str = field(default_factory=lambda: os.environ.get("AWG_DIR", "/opt/amnezia/awg"))
    vpn_subnet: str = field(default_factory=lambda: os.environ.get("VPN_SUBNET", "10.8.1.0/24"))
    client_dns: tuple[str, str] = field(default_factory=lambda: tuple(  # type: ignore[assignment]
        (os.environ.get("CLIENT_DNS", "8.8.8.8, 8.8.4.4").replace(",", " ").split() + ["8.8.4.4"])[:2]))
    client_keepalive: str = field(default_factory=lambda: os.environ.get("CLIENT_KEEPALIVE", "25-35"))

    telegram_token: str = field(default_factory=lambda: os.environ.get("TELEGRAM_BOT_TOKEN", "").strip())
    smtp_host: str = field(default_factory=lambda: os.environ.get("SMTP_HOST", "").strip())
    smtp_port: int = field(default_factory=lambda: _int("SMTP_PORT", 587))
    smtp_user: str = field(default_factory=lambda: os.environ.get("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.environ.get("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.environ.get("SMTP_FROM", ""))
    smtp_ssl: bool = field(default_factory=lambda: _bool("SMTP_SSL", False))

    tz: str = field(default_factory=lambda: os.environ.get("TZ", "UTC"))
    poll_interval: int = field(default_factory=lambda: _int("POLL_INTERVAL", 30))
    online_window: int = field(default_factory=lambda: _int("ONLINE_WINDOW", 180))
    collect_hosts: bool = field(default_factory=lambda: _bool("COLLECT_HOSTS", True))
    retention_raw_days: int = field(default_factory=lambda: _int("RETENTION_RAW_DAYS", 30))
    retention_min_days: int = field(default_factory=lambda: _int("RETENTION_MIN_DAYS", 7))
    retention_events_days: int = field(default_factory=lambda: _int("RETENTION_EVENTS_DAYS", 365))

    @property
    def base_url(self) -> str:
        port = "" if self.panel_port == 443 else f":{self.panel_port}"
        return f"https://{self.panel_host or self.public_host}{port}"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "panel.db"

    def problems(self) -> list[str]:
        """Что не настроено для безопасного запуска веб-интерфейса."""
        out = []
        if not self.admin_password_hash:
            out.append("ADMIN_PASSWORD_HASH")
        if not self.totp_secret:
            out.append("TOTP_SECRET")
        if len(self.session_secret) < 32:
            out.append("SESSION_SECRET (32+ characters)")
        return out


settings = Settings()
