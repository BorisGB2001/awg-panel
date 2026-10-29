"""Куда и сколько: закрытые соединения клиентов из conntrack с байтами в обе стороны.

Долгие соединения попадают в статистику при закрытии — точный трафик по клиенту даёт poller.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict

from .awgctl import AWG, AwgUnavailable
from .config import Settings
from .names import NameCache

log = logging.getLogger("flows")

KV = re.compile(r"(\w+)=(\S+)")
PROTO = re.compile(r"\[DESTROY\]\s+(tcp|udp)\s")
MAX_KEYS = 200_000


def parse_event(line: str) -> tuple[str, str, str, int, int, int] | None:
    """(proto, src, dst, dport, bytes_up, bytes_down) из строки `conntrack -E -e DESTROY`.

    Первые src/dst/sport/dport/packets/bytes — направление клиента, вторые — ответ.
    """
    m = PROTO.search(line)
    if not m:
        return None
    orig: dict[str, str] = {}
    reply: dict[str, str] = {}
    for k, v in KV.findall(line):
        target = reply if k in orig and k in ("src", "dst", "sport", "dport", "packets", "bytes") else orig
        target.setdefault(k, v)
    try:
        return m.group(1), orig["src"], orig["dst"], int(orig.get("dport", 0)), int(orig.get("bytes", 0)), \
            int(reply.get("bytes", 0))
    except (KeyError, ValueError):
        return None


class Flows:
    def __init__(self, settings: Settings, awg: AWG, conn: sqlite3.Connection, names: NameCache):
        self.s, self.awg, self.conn, self.names = settings, awg, conn, names
        self.net = ipaddress.ip_network(settings.vpn_subnet, strict=False)
        self.agg: dict[tuple[int, str, str, int, str], list[int]] = defaultdict(lambda: [0, 0, 0])
        self._lock = threading.Lock()
        self.events = 0
        self.last_error: str | None = None
        self._acct_pid: int | None = None

    def ensure_acct(self) -> None:
        """Учёт байт в conntrack выключен в amnezia-awg2 и сбрасывается при рестарте контейнера — включаем на каждый PID."""
        pid = self.awg.pid()
        if pid != self._acct_pid:
            self.awg.run(["sysctl", "-w", "net.netfilter.nf_conntrack_acct=1"], mount=False)
            self._acct_pid = pid

    def add(self, line: str, now: float | None = None) -> None:
        ev = parse_event(line)
        if not ev:
            return
        proto, src, dst, dport, up, down = ev
        try:
            if ipaddress.ip_address(src) not in self.net:
                return
        except ValueError:
            return
        now = time.time() if now is None else now
        minute = int(now) - int(now) % 60
        with self._lock:
            a = self.agg[(minute, src, dst, dport, proto)]
            a[0] += 1
            a[1] += up
            a[2] += down
            self.events += 1
            big = len(self.agg) > MAX_KEYS
        if big:
            self.flush()

    def flush(self) -> int:
        with self._lock:
            agg, self.agg = self.agg, defaultdict(lambda: [0, 0, 0])
        if not agg:
            return 0
        ip2peer = {r[0]: r[1] for r in self.conn.execute(
            "SELECT ip, id FROM peers WHERE deleted_at IS NULL AND disabled = 0")}
        rows = [(m, ip2peer[src], dst, dport, proto, self.names.get(src, dst), c, up, down)
                for (m, src, dst, dport, proto), (c, up, down) in agg.items() if src in ip2peer]
        self.conn.executemany(
            "INSERT INTO flows (ts, peer_id, dst_ip, dport, proto, host, conns, bytes_up, bytes_down) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ts, peer_id, dst_ip, dport, proto) DO UPDATE SET "
            "conns = conns + excluded.conns, bytes_up = bytes_up + excluded.bytes_up, "
            "bytes_down = bytes_down + excluded.bytes_down, host = COALESCE(excluded.host, host)", rows)
        return len(rows)

    def capture(self, stop: threading.Event) -> None:
        self.ensure_acct()
        argv = self.awg.ns_argv(["conntrack", "-E", "-e", "DESTROY", "-b", "8388608"])
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                self.add(line)
                if stop.is_set():
                    break
            err = proc.stderr.read().strip()
            if err:
                self.last_error = err[:300]
        finally:
            proc.kill()
            proc.wait()

    def run(self, stop: threading.Event) -> None:
        threading.Thread(target=self._flush_loop, args=(stop,), name="flows-flush", daemon=True).start()
        while not stop.is_set():
            try:
                self.capture(stop)
            except AwgUnavailable as e:
                self.last_error = str(e)
            except Exception as e:  # noqa: BLE001 — поток не должен умирать
                self.last_error = repr(e)
                log.exception("flows")
            stop.wait(5)

    def _flush_loop(self, stop: threading.Event) -> None:
        while not stop.wait(60):
            try:
                self.flush()
            except Exception:  # noqa: BLE001
                log.exception("flows flush")
        self.flush()
