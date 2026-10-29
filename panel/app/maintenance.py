"""Обслуживание БД: агрегация сайтов по дням, удаление старых данных, бэкап, оптимизация."""
from __future__ import annotations

import datetime
import logging
import sqlite3
import threading
import time
from zoneinfo import ZoneInfo

from . import db, fmt
from .config import Settings

log = logging.getLogger("maintenance")

KEEP_DB_BACKUPS = 14


def aggregate_hosts(conn: sqlite3.Connection, tz: ZoneInfo, upto: int) -> int:
    """dns + flows → hosts_day по завершённым дням (до upto), чтобы после очистки сырых данных остались итоги."""
    done = int(db.get_state(conn, "hosts_day_upto", "0") or 0)
    first = conn.execute("SELECT MIN(ts) FROM dns").fetchone()[0]
    if first is None and done == 0:
        return 0
    start = max(done, fmt.day_start(first or upto))
    n = 0
    day = start
    while day + 86400 <= upto:
        nxt = int((datetime.datetime.fromtimestamp(day, tz) + datetime.timedelta(days=1)).replace(hour=0, minute=0).timestamp())
        agg: dict[tuple[int, str], list[int]] = {}
        for r in conn.execute("SELECT peer_id, name, SUM(count) n FROM dns WHERE ts >= ? AND ts < ? GROUP BY peer_id, name", (day, nxt)):
            agg.setdefault((r["peer_id"], fmt.base_domain(r["name"])), [0, 0, 0, 0])[0] += r["n"]
        for r in conn.execute("SELECT peer_id, host, SUM(conns) c, SUM(bytes_up) u, SUM(bytes_down) d FROM flows "
                              "WHERE ts >= ? AND ts < ? AND host IS NOT NULL GROUP BY peer_id, host", (day, nxt)):
            a = agg.setdefault((r["peer_id"], fmt.base_domain(r["host"])), [0, 0, 0, 0])
            a[1] += r["c"]; a[2] += r["u"]; a[3] += r["d"]
        conn.execute("BEGIN")
        conn.execute("DELETE FROM hosts_day WHERE day = ?", (day,))
        conn.executemany("INSERT INTO hosts_day (day, peer_id, host, requests, conns, bytes_up, bytes_down) VALUES (?, ?, ?, ?, ?, ?, ?)",
                         [(day, pid, host, *v) for (pid, host), v in agg.items()])
        db.set_state(conn, "hosts_day_upto", str(nxt))
        conn.execute("COMMIT")
        n += len(agg)
        day = nxt
    return n


def cleanup(conn: sqlite3.Connection, s: Settings, now: int) -> dict[str, int]:
    """Удаляет данные старше сроков хранения; traffic_hour, sessions, endpoints, архив — бессрочно."""
    plan = {
        "traffic_min": ("ts", s.retention_min_days),
        "online_min": ("ts", s.retention_raw_days),
        "flows": ("ts", s.retention_raw_days),
        "dns": ("ts", s.retention_raw_days),
        "events": ("ts", s.retention_events_days),
        "hosts_day": ("day", 365),
    }
    out = {}
    for table, (col, days) in plan.items():
        if table in ("flows", "dns"):
            # сырые данные удаляются только после того, как попали в hosts_day
            limit = min(now - days * 86400, int(db.get_state(conn, "hosts_day_upto", "0") or 0))
        else:
            limit = now - days * 86400
        out[table] = conn.execute(f"DELETE FROM {table} WHERE {col} < ?", (limit,)).rowcount
    conn.execute("DELETE FROM ipnames WHERE ts < ?", (now - 30 * 86400,))
    return out


def backup_db(conn: sqlite3.Connection, s: Settings, now: int) -> str:
    d = s.data_dir / "backups" / "db"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = d / f"panel-{time.strftime('%Y%m%d-%H%M', time.localtime(now))}.db"
    dst = sqlite3.connect(path)
    try:
        conn.backup(dst)
    finally:
        dst.close()
    path.chmod(0o600)
    for old in sorted(d.glob("panel-*.db"))[:-KEEP_DB_BACKUPS]:
        old.unlink(missing_ok=True)
    return path.name


def tick(conn: sqlite3.Connection, s: Settings, now: int | None = None) -> None:
    now = int(time.time()) if now is None else now
    aggregate_hosts(conn, fmt.TZ, fmt.day_start(now))
    removed = cleanup(conn, s, now)
    if any(removed.values()):
        log.info("очистка: %s", removed)
    local = datetime.datetime.fromtimestamp(now, fmt.TZ)
    day = local.strftime("%Y-%m-%d")
    if local.hour >= 4 and db.get_state(conn, "daily_done") != day:   # ночью, раз в сутки
        name = backup_db(conn, s, now)
        conn.execute("PRAGMA optimize")
        if local.weekday() == 6:
            conn.execute("VACUUM")
        db.set_state(conn, "daily_done", day)
        log.info("бэкап БД %s", name)


def run(conn: sqlite3.Connection, s: Settings, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            tick(conn, s)
        except Exception:  # noqa: BLE001 — поток не должен умирать
            log.exception("maintenance")
        stop.wait(3600)
