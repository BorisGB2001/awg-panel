import json
from contextlib import nullcontext

import pytest

from app import awgconf, db
from app.awgctl import PeerStat
from app.config import Settings
from app.poller import Poller, parse_qt_date

K = lambda c: (c * 43)[:43] + "="  # noqa: E731
T0 = 1_800_000_000


class FakeAWG:
    def __init__(self):
        self.pid_ = 77
        self.peers = {K("a"): ("10.8.1.1", "Анна"), K("b"): ("10.8.1.2", "Борис")}
        self.stats: dict[str, PeerStat] = {}

    def pid(self):
        return self.pid_

    def locked(self):
        return nullcontext()

    def started_at(self):
        return T0 - 1000

    def read_conf(self):
        c = awgconf.AwgConf.parse("[Interface]\nListenPort = 51820\n")
        for k, (ip, _) in self.peers.items():
            c.add_peer(k, K("p"), ip)
        return c

    def read_clients(self):
        return [awgconf.client_entry(k, ip, name, ts=T0 - 86400) for k, (ip, name) in self.peers.items()]

    def dump(self):
        return list(self.stats.values())

    def stat(self, key, hs, rx, tx, ep="95.24.72.224:28113"):
        self.stats[key] = PeerStat(key, ep, self.peers[key][0] + "/32", hs, rx, tx)


class FakeGeo:
    def built(self):
        return "2026-10-01"

    def lookup(self, ip):
        return {"country": "RU", "city": "Москва", "asn": 8402, "org": "Beeline"} if ip.startswith("95.") \
            else {"country": "NL", "city": None, "asn": 1, "org": "X"}


@pytest.fixture
def env(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    awg = FakeAWG()
    p = Poller(Settings(data_dir=tmp_path, online_window=180), awg, conn, FakeGeo())
    return p, awg, conn


def kinds(conn):
    return [r[0] for r in conn.execute("SELECT kind FROM events ORDER BY id")]


def test_qt_date():
    assert parse_qt_date("Wed Oct 28 17:14:55 2026") is not None
    assert parse_qt_date("garbage") is None


def test_first_import_and_baseline(env):
    p, awg, conn = env
    awg.stat(K("a"), T0 - 10, 1000, 5000)
    awg.stat(K("b"), 0, 0, 0, ep=None)
    p.tick(T0)
    rows = {r["name"]: r for r in conn.execute("SELECT * FROM peers")}
    assert set(rows) == {"Анна", "Борис"} and rows["Анна"]["source"] == "amnezia_app"
    assert rows["Анна"]["created_at"] == T0 - 86400
    assert kinds(conn) == ["peers_imported", "connect"]  # один импорт, без события на каждого
    assert conn.execute("SELECT COUNT(*) FROM traffic_min").fetchone()[0] == 0  # первый опрос — точка отсчёта
    assert p.status.online == 1


def test_traffic_deltas_and_counter_reset(env):
    p, awg, conn = env
    awg.stat(K("a"), T0 - 10, 1000, 5000)
    p.tick(T0)
    awg.stat(K("a"), T0 + 20, 1600, 9000)
    p.tick(T0 + 30)
    awg.stat(K("a"), T0 + 50, 100, 200)  # рестарт amnezia-awg2: счётчики с нуля
    p.tick(T0 + 60)
    rx, tx = conn.execute("SELECT SUM(rx), SUM(tx) FROM traffic_hour").fetchone()
    assert (rx, tx) == (600 + 100, 4000 + 200)
    assert conn.execute("SELECT rx_total, tx_total FROM peers WHERE name='Анна'").fetchone()[:] == (700, 4200)
    s = conn.execute("SELECT rx, tx FROM sessions").fetchone()
    assert (s["rx"], s["tx"]) == (700, 4200)
    assert json.loads(db.get_state(conn, "counters"))[K("a")] == [100, 200]


def test_session_open_close(env):
    p, awg, conn = env
    awg.stat(K("a"), T0 - 10, 1000, 5000)
    p.tick(T0)
    awg.stat(K("a"), T0 + 100, 2000, 6000)
    p.tick(T0 + 120)
    p.tick(T0 + 500)  # handshake устарел, трафика нет — сессия закрыта
    s = conn.execute("SELECT start, end, rx, tx FROM sessions").fetchone()
    assert s["start"] == T0 - 10 and s["end"] == T0 + 120 and (s["rx"], s["tx"]) == (1000, 1000)
    assert kinds(conn)[-1] == "disconnect"
    awg.stat(K("a"), T0 + 900, 2100, 6100)
    p.tick(T0 + 910)
    assert conn.execute("SELECT COUNT(*) FROM sessions WHERE end IS NULL").fetchone()[0] == 1
    assert kinds(conn).count("connect") == 2


def test_endpoint_change_with_geo(env):
    p, awg, conn = env
    awg.stat(K("a"), T0 - 10, 0, 0)
    p.tick(T0)
    awg.stat(K("a"), T0 + 20, 0, 0, ep="5.6.7.8:1000")
    p.tick(T0 + 30)
    ev = conn.execute("SELECT detail FROM events WHERE kind='endpoint_change'").fetchone()
    d = json.loads(ev[0])
    assert d["from"] == "95.24.72.224" and d["to"] == "5.6.7.8" and d["country"] == "NL" and d["port"] == "1000"
    eps = {r["ip"]: r for r in conn.execute("SELECT * FROM endpoints")}
    assert eps["95.24.72.224"]["org"] == "Beeline" and eps["5.6.7.8"]["count"] == 1


def test_sync_rename_remove_return(env):
    p, awg, conn = env
    p.tick(T0)
    awg.peers[K("a")] = ("10.8.1.1", "Анна М")
    del awg.peers[K("b")]
    awg.peers[K("c")] = ("10.8.1.3", "Новый")
    p.tick(T0 + 30)
    assert kinds(conn)[1:] == ["peer_renamed", "peer_discovered", "peer_removed_external"] or \
        sorted(kinds(conn)[1:]) == sorted(["peer_renamed", "peer_discovered", "peer_removed_external"])
    assert conn.execute("SELECT deleted_at FROM peers WHERE name='Борис'").fetchone()[0] == T0 + 30
    awg.peers[K("b")] = ("10.8.1.2", "Борис")
    p.tick(T0 + 60)
    assert conn.execute("SELECT deleted_at FROM peers WHERE name='Борис'").fetchone()[0] is None


def test_restart_alert(env):
    p, awg, conn = env
    p.tick(T0)
    awg.pid_ = 88
    p.tick(T0 + 30)
    assert "alert_server" in kinds(conn)
