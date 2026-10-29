"""Кэш «IP назначения → домен» по DNS-ответам и SNI: сначала пара (клиент, IP), потом общий."""
from __future__ import annotations

import sqlite3
import threading
import time

TTL = 3600
MAX = 200_000


class NameCache:
    def __init__(self):
        self._pair: dict[tuple[str, str], tuple[str, float]] = {}
        self._ip: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        self._dirty: dict[str, tuple[str, float]] = {}

    def put(self, client: str | None, ip: str, name: str, strong: bool = False, now: float | None = None) -> None:
        """strong — имя из SNI: точнее DNS (на одном IP CDN бывает много имён)."""
        now = time.time() if now is None else now
        with self._lock:
            if client:
                old = self._pair.get((client, ip))
                if strong or not old or old[0] == name or now - old[1] > 5:
                    self._pair[(client, ip)] = (name, now)
            self._ip[ip] = self._dirty[ip] = (name, now)
            if len(self._pair) > MAX or len(self._ip) > MAX:
                self._prune(now)

    def get(self, client: str | None, ip: str, now: float | None = None) -> str | None:
        now = time.time() if now is None else now
        with self._lock:
            for v in ((self._pair.get((client, ip)) if client else None), self._ip.get(ip)):
                if v and now - v[1] <= TTL:
                    return v[0]
            v = self._ip.get(ip)
            return v[0] if v else None   # устаревшее имя лучше, чем голый IP

    def _prune(self, now: float) -> None:
        self._pair = {k: v for k, v in self._pair.items() if now - v[1] <= TTL}
        self._ip = {k: v for k, v in self._ip.items() if now - v[1] <= TTL * 24}

    # ---- сохранение между перезапусками ----

    def load(self, conn: sqlite3.Connection) -> None:
        with self._lock:
            for ip, name, ts in conn.execute("SELECT ip, name, ts FROM ipnames"):
                self._ip.setdefault(ip, (name, ts))

    def flush(self, conn: sqlite3.Connection) -> int:
        with self._lock:
            dirty, self._dirty = self._dirty, {}
        if dirty:
            conn.executemany("INSERT INTO ipnames (ip, name, ts) VALUES (?, ?, ?) "
                             "ON CONFLICT(ip) DO UPDATE SET name = excluded.name, ts = excluded.ts",
                             [(ip, n, int(t)) for ip, (n, t) in dirty.items()])
        return len(dirty)
