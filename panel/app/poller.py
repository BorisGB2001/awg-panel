"""Опрос AmneziaWG раз в POLL_INTERVAL: список клиентов, трафик, сессии, endpoint'ы."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass

from . import awgconf, db
from .alerts import new_country
from .awgctl import AWG, AwgUnavailable, PeerStat
from .config import Settings
from .geo import Geo

log = logging.getLogger("poller")


def parse_qt_date(s: str | None) -> int | None:
    try:
        return int(time.mktime(time.strptime(s or "", "%a %b %d %H:%M:%S %Y")))
    except ValueError:
        return None


@dataclass
class Status:
    """Последний опрос — для страницы сервера и /healthz."""
    last_ok: float = 0.0
    last_error: str | None = None
    online: int = 0
    peers: int = 0


class Poller:
    def __init__(self, settings: Settings, awg: AWG, conn: sqlite3.Connection, geo: Geo | None):
        self.s, self.awg, self.conn, self.geo = settings, awg, conn, geo
        self.status = Status()
        self.counters: dict[str, tuple[int, int]] = json.loads(db.get_state(conn, "counters", "{}"))
        self._was_up = True

    # ---- синхронизация состава клиентов ----

    def sync_peers(self, now: int) -> dict[str, int]:
        """Приводит таблицу peers к awg0.conf + clientsTable; возвращает pubkey → peer_id для клиентов из конфига."""
        conf = self.awg.read_conf()
        names = awgconf.clients_by_key(self.awg.read_clients())
        ips = conf.peer_ips()
        rows = {r["pubkey"]: r for r in self.conn.execute("SELECT id, pubkey, name, ip, deleted_at, disabled FROM peers")}
        first_import = not rows
        ids: dict[str, int] = {}
        self.conn.execute("BEGIN")
        try:
            for key, ip in ips.items():
                ud = names.get(key, {})
                name = ud.get("clientName") or f"peer-{ip}"
                row = rows.get(key)
                if row is None:
                    cur = self.conn.execute(
                        "INSERT INTO peers (pubkey, name, ip, source, created_at) VALUES (?, ?, ?, 'amnezia_app', ?)",
                        (key, name, ip, parse_qt_date(ud.get("creationDate")) or now))
                    ids[key] = cur.lastrowid
                    if not first_import:
                        db.event(self.conn, "peer_discovered", ids[key], {"name": name, "ip": ip}, ts=now)
                    continue
                ids[key] = row["id"]
                if row["deleted_at"] or row["disabled"]:
                    self.conn.execute("UPDATE peers SET deleted_at = NULL, disabled = 0 WHERE id = ?", (row["id"],))
                    db.event(self.conn, "peer_discovered", row["id"], {"name": name, "ip": ip, "returned": True}, ts=now)
                if ud.get("clientName") and name != row["name"]:
                    self.conn.execute("UPDATE peers SET name = ? WHERE id = ?", (name, row["id"]))
                    db.event(self.conn, "peer_renamed", row["id"], {"from": row["name"], "to": name, "source": "amnezia_app"}, ts=now)
                if ip != row["ip"]:
                    self.conn.execute("UPDATE peers SET ip = ? WHERE id = ?", (ip, row["id"]))
            for key, row in rows.items():
                if key not in ips and not row["deleted_at"] and not row["disabled"]:
                    self.conn.execute("UPDATE peers SET deleted_at = ? WHERE id = ?", (now, row["id"]))
                    db.event(self.conn, "peer_removed_external", row["id"], {"name": row["name"], "ip": row["ip"]}, ts=now)
            if first_import and ips:
                db.event(self.conn, "peers_imported", detail={"count": len(ips)}, ts=now)
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        return ids

    # ---- опрос ----

    def tick(self, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        self.check_restart(now)
        with self.awg.locked():  # не пересекаться с операциями управления (manage.py)
            ids = self.sync_peers(now)
        stats = {p.pubkey: p for p in self.awg.dump()}
        minute, hour = now - now % 60, now - now % 3600
        open_sessions = {r["peer_id"]: r for r in self.conn.execute(
            "SELECT id, peer_id, start, endpoint_ip, rx, tx, last_active FROM sessions WHERE end IS NULL")}
        peers = {r["id"]: r for r in self.conn.execute("SELECT id, name, last_endpoint, first_handshake FROM peers")}
        online = 0
        self.conn.execute("BEGIN")
        try:
            for key, pid in ids.items():
                p = stats.get(key)
                if p is None:
                    continue
                drx, dtx = self.delta(key, p)
                if drx or dtx:
                    for table, ts in (("traffic_min", minute), ("traffic_hour", hour)):
                        self.conn.execute(
                            f"INSERT INTO {table} (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?) "
                            "ON CONFLICT(ts, peer_id) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx",
                            (ts, pid, drx, dtx))
                    self.conn.execute("UPDATE peers SET rx_total = rx_total + ?, tx_total = tx_total + ? WHERE id = ?",
                                      (drx, dtx, pid))
                fresh = p.latest_handshake > 0 and now - p.latest_handshake <= self.s.online_window
                is_online = fresh or bool(drx or dtx)
                online += is_online
                if p.latest_handshake:
                    self.conn.execute(
                        "UPDATE peers SET last_handshake = ?, first_handshake = COALESCE(first_handshake, ?) WHERE id = ?",
                        (p.latest_handshake, p.latest_handshake, pid))
                self.track_endpoint(pid, peers[pid], p, now, is_online)
                self.track_session(pid, p, now, is_online, drx, dtx, fresh, open_sessions.get(pid))
            # сессии клиентов, которых больше нет в конфиге
            for pid, sess in open_sessions.items():
                if pid not in ids.values():
                    self.close_session(sess, now)
            self.conn.execute(
                "INSERT INTO online_min (ts, online) VALUES (?, ?) ON CONFLICT(ts) DO UPDATE SET online = MAX(online, excluded.online)",
                (minute, online))
            db.set_state(self.conn, "counters", json.dumps(self.counters))
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.status.online, self.status.peers = online, len(ids)
        self.backfill_geo()

    def backfill_geo(self) -> None:
        """Гео для IP, записанных до загрузки баз DB-IP."""
        if not self.geo or not self.geo.built():
            return
        for r in self.conn.execute("SELECT peer_id, ip FROM endpoints WHERE country IS NULL AND asn IS NULL LIMIT 200").fetchall():
            g = self.geo.lookup(r["ip"])
            if g["country"] or g["asn"]:
                self.conn.execute("UPDATE endpoints SET country = ?, city = ?, asn = ?, org = ? WHERE peer_id = ? AND ip = ?",
                                  (g["country"], g["city"], g["asn"], g["org"], r["peer_id"], r["ip"]))

    def delta(self, key: str, p: PeerStat) -> tuple[int, int]:
        """Прирост счётчиков с прошлого опроса; меньше прошлого — счётчик сброшен (рестарт amnezia-awg2)."""
        prev = self.counters.get(key)
        self.counters[key] = (p.rx, p.tx)
        if prev is None:
            return 0, 0  # первый раз видим клиента: точка отсчёта, без накопленного до нас
        drx = p.rx - prev[0] if p.rx >= prev[0] else p.rx
        dtx = p.tx - prev[1] if p.tx >= prev[1] else p.tx
        return drx, dtx

    def track_endpoint(self, pid: int, peer: sqlite3.Row, p: PeerStat, now: int, is_online: bool) -> None:
        ip = p.endpoint_ip
        if not ip:
            return
        changed = ip != peer["last_endpoint"]
        if not changed and not is_online:
            return
        g = self.geo.lookup(ip) if self.geo else {"country": None, "city": None, "asn": None, "org": None}
        self.conn.execute(
            "INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, count, country, city, asn, org) "
            "VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?) ON CONFLICT(peer_id, ip) DO UPDATE SET last_seen = excluded.last_seen, "
            "count = count + ?, country = COALESCE(excluded.country, country), city = COALESCE(excluded.city, city), "
            "asn = COALESCE(excluded.asn, asn), org = COALESCE(excluded.org, org)",
            (pid, ip, now, now, g["country"], g["city"], g["asn"], g["org"], 1 if changed else 0))
        if changed:
            new_country(self.conn, pid, ip, g["country"], now)
            self.conn.execute("UPDATE peers SET last_endpoint = ? WHERE id = ?", (ip, pid))
            if peer["last_endpoint"]:
                db.event(self.conn, "endpoint_change", pid,
                         {"from": peer["last_endpoint"], "to": ip, "port": p.endpoint.rsplit(":", 1)[1], **g}, ts=now)

    def track_session(self, pid: int, p: PeerStat, now: int, is_online: bool, drx: int, dtx: int, fresh: bool,
                      sess: sqlite3.Row | None) -> None:
        active = max(p.latest_handshake if fresh else 0, now if (drx or dtx) else 0)
        if sess is None:
            if not is_online:
                return
            start = p.latest_handshake if fresh else now
            cur = self.conn.execute(
                "INSERT INTO sessions (peer_id, start, endpoint_ip, rx, tx, last_active) VALUES (?, ?, ?, ?, ?, ?)",
                (pid, start, p.endpoint_ip, drx, dtx, active or start))
            g = self.geo.lookup(p.endpoint_ip) if self.geo and p.endpoint_ip else {}
            db.event(self.conn, "connect", pid, {"session": cur.lastrowid, "endpoint": p.endpoint_ip,
                                                 "country": g.get("country"), "org": g.get("org")}, ts=start)
            return
        if is_online:
            self.conn.execute(
                "UPDATE sessions SET rx = rx + ?, tx = tx + ?, last_active = MAX(COALESCE(last_active, start), ?), "
                "endpoint_ip = COALESCE(?, endpoint_ip) WHERE id = ?",
                (drx, dtx, active, p.endpoint_ip, sess["id"]))
        else:
            self.close_session(sess, now)

    def close_session(self, sess: sqlite3.Row, now: int) -> None:
        row = self.conn.execute("SELECT start, rx, tx, last_active FROM sessions WHERE id = ?", (sess["id"],)).fetchone()
        end = min(now, row["last_active"] or row["start"])
        self.conn.execute("UPDATE sessions SET end = ? WHERE id = ?", (end, sess["id"]))
        db.event(self.conn, "disconnect", sess["peer_id"],
                 {"session": sess["id"], "duration": end - row["start"], "rx": row["rx"], "tx": row["tx"]}, ts=end)

    # ---- рестарт контейнера ----

    def check_restart(self, now: int) -> None:
        try:
            pid = self.awg.pid()
            started = int(self.awg.started_at())
        except AwgUnavailable:
            raise
        prev = db.get_state(self.conn, "awg_pid")
        if prev and int(prev) != pid:
            db.event(self.conn, "alert_server", detail={"reason": "awg_restarted", "pid": pid, "started": started}, ts=now)
        if prev != str(pid):
            db.set_state(self.conn, "awg_pid", str(pid))

    # ---- поток ----

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            t0 = time.time()
            try:
                self.tick()
                if not self._was_up:
                    log.info("AmneziaWG снова доступен")
                self._was_up = True
                self.status.last_ok, self.status.last_error = time.time(), None
            except AwgUnavailable as e:
                self.status.last_error = str(e)
                if self._was_up:
                    log.warning("AmneziaWG недоступен: %s", e)
                    db.event(self.conn, "alert_server", detail={"reason": "awg_unavailable", "error": str(e)})
                self._was_up = False
            except Exception as e:  # noqa: BLE001 — поток не должен умирать
                self.status.last_error = repr(e)
                log.exception("poller")
            stop.wait(max(1.0, self.s.poll_interval - (time.time() - t0)))
