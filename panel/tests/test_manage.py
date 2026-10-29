import base64
import json
import os
import stat

import pytest
from cryptography.fernet import Fernet

from app import awgconf, db
from app.awgctl import AWG, PeerStat
from app.config import Settings
from app.manage import Manager, ManageError, gen_keypair

K = lambda c: (c * 43)[:43] + "="  # noqa: E731

CONF = ("[Interface]\nPrivateKey = " + K("s") + "\nAddress = 10.8.1.0/24\nListenPort = 51820\n"
        "[Peer]\nPublicKey = " + K("a") + "\nPresharedKey = " + K("p") + "\nAllowedIPs = 10.8.1.1/32\n\n"
        "[Peer]\nPublicKey = " + K("b") + "\nPresharedKey = " + K("p") + "\nAllowedIPs = 10.8.1.5/32\n\n")
CLIENTS = [awgconf.client_entry(K("a"), "10.8.1.1", "Анна", 0), awgconf.client_entry(K("b"), "10.8.1.5", "Борис", 0)]


class LiveAWG(AWG):
    """Настоящая работа с файлами через поддельный /proc, интерфейс — в памяти."""

    def __init__(self, s, proc):
        super().__init__(s, proc)
        self.iface = {K("a"): "10.8.1.1/32", K("b"): "10.8.1.5/32"}
        self.fail_set = False
        self.calls = []

    def dump(self):
        return [PeerStat(k, None, ip, 0, 0, 0) for k, ip in self.iface.items()]

    def set_peer(self, pubkey, ip):
        self.calls.append(("set", pubkey, ip))
        if self.fail_set:
            raise RuntimeError("awg set упал")
        self.iface[pubkey] = f"{ip}/32"

    def remove_peer(self, pubkey):
        self.calls.append(("remove", pubkey))
        self.iface.pop(pubkey, None)


@pytest.fixture
def env(tmp_path):
    proc = tmp_path / "proc"
    (proc / "77").mkdir(parents=True)
    (proc / "77" / "cmdline").write_bytes(b"amneziawg-go\0awg0\0")
    d = proc / "77" / "root" / "opt" / "amnezia" / "awg"
    d.mkdir(parents=True)
    (d / "awg0.conf").write_text(CONF)
    (d / "clientsTable").write_text(awgconf.render_clients(CLIENTS))
    (d / "wireguard_psk.key").write_text(K("p") + "\n")
    os.chmod(d / "awg0.conf", 0o640)
    s = Settings(data_dir=tmp_path / "data")
    conn = db.open_db(s.data_dir / "p.db")
    for k, ip, name in ((K("a"), "10.8.1.1", "Анна"), (K("b"), "10.8.1.5", "Борис")):
        conn.execute("INSERT INTO peers (pubkey, name, ip, source) VALUES (?, ?, ?, 'amnezia_app')", (k, name, ip))
    awg = LiveAWG(s, proc)
    return Manager(s, awg, conn, Fernet(Fernet.generate_key())), awg, d, conn


def pid_of(conn, name):
    return conn.execute("SELECT id FROM peers WHERE name = ?", (name,)).fetchone()[0]


def test_keypair_is_x25519_base64():
    priv, pub = gen_keypair()
    assert len(base64.b64decode(priv)) == 32 and len(base64.b64decode(pub)) == 32 and priv != pub


def test_add_peer_everywhere(env):
    m, awg, d, conn = env
    pid = m.add("Новый клиент", note="тест", actor="admin", actor_ip="1.2.3.4")
    row = conn.execute("SELECT * FROM peers WHERE id = ?", (pid,)).fetchone()
    assert row["ip"] == "10.8.1.6" and row["source"] == "panel"   # max(.1, .5) + 1
    text = (d / "awg0.conf").read_text()
    assert text.startswith(CONF) and f"PublicKey = {row['pubkey']}\nPresharedKey = {K('p')}\nAllowedIPs = 10.8.1.6/32\n\n" in text
    assert stat.S_IMODE((d / "awg0.conf").stat().st_mode) == 0o640
    cl = json.loads((d / "clientsTable").read_text())
    assert cl[-1]["clientId"] == row["pubkey"] and cl[-1]["userData"]["clientName"] == "Новый клиент"
    assert awg.iface[row["pubkey"]] == "10.8.1.6/32"
    priv = m.private_key(pid)
    assert len(base64.b64decode(priv)) == 32
    ev = conn.execute("SELECT kind, actor, actor_ip FROM events").fetchone()
    assert tuple(ev) == ("admin_add", "admin", "1.2.3.4")
    assert len(list((m.s.data_dir / "backups").iterdir())) == 1


def test_add_rejects_duplicate_and_bad_names(env):
    m, *_ = env
    with pytest.raises(ManageError):
        m.add("анна")
    with pytest.raises(ManageError):
        m.add("   ")
    with pytest.raises(ManageError):
        m.add("x" * 65)


def test_add_rollback_on_live_failure(env):
    m, awg, d, conn = env
    awg.fail_set = True
    with pytest.raises(ManageError) as e:
        m.add("Сбой")
    assert "restored" in str(e.value)
    assert (d / "awg0.conf").read_text() == CONF
    assert json.loads((d / "clientsTable").read_text()) == CLIENTS
    assert conn.execute("SELECT COUNT(*) FROM peers").fetchone()[0] == 2
    assert set(awg.iface) == {K("a"), K("b")}


def test_rename(env):
    m, awg, d, conn = env
    m.rename(pid_of(conn, "Борис"), "Борис Г")
    cl = awgconf.clients_by_key(json.loads((d / "clientsTable").read_text()))
    assert cl[K("b")]["clientName"] == "Борис Г"
    assert (d / "awg0.conf").read_text() == CONF and not awg.calls
    with pytest.raises(ManageError):
        m.rename(pid_of(conn, "Анна"), "борис г")


def test_delete_needs_exact_name(env):
    m, awg, d, conn = env
    pid = pid_of(conn, "Анна")
    with pytest.raises(ManageError):
        m.delete(pid, "анна")
    m.delete(pid, "Анна")
    assert K("a") not in (d / "awg0.conf").read_text() and K("a") not in awg.iface
    assert K("a") not in (d / "clientsTable").read_text() and K("b") in awg.iface
    assert conn.execute("SELECT deleted_at FROM peers WHERE id = ?", (pid,)).fetchone()[0]
    with pytest.raises(ManageError):
        m.delete(pid, "Анна")


def test_disable_keeps_ip_reserved_then_enable(env):
    m, awg, d, conn = env
    pid = pid_of(conn, "Борис")   # .5 — максимальный
    m.disable(pid)
    assert K("b") not in awg.iface and K("b") not in (d / "awg0.conf").read_text()
    assert conn.execute("SELECT disabled, ip FROM peers WHERE id = ?", (pid,)).fetchone()[:] == (1, "10.8.1.5")
    new = m.add("После отключения")
    assert conn.execute("SELECT ip FROM peers WHERE id = ?", (new,)).fetchone()[0] == "10.8.1.6"
    m.enable(pid)
    assert awg.iface[K("b")] == "10.8.1.5/32"
    assert "AllowedIPs = 10.8.1.5/32" in (d / "awg0.conf").read_text()
    assert awgconf.clients_by_key(json.loads((d / "clientsTable").read_text()))[K("b")]["clientName"] == "Борис"


def test_enable_refuses_taken_ip(env):
    m, awg, d, conn = env
    pid = pid_of(conn, "Борис")
    m.disable(pid)
    conf = awgconf.AwgConf.parse((d / "awg0.conf").read_text())
    conf.add_peer(K("z"), K("p"), "10.8.1.5")   # приложение AmneziaVPN заняло этот IP
    (d / "awg0.conf").write_text(conf.render())
    with pytest.raises(ManageError):
        m.enable(pid)


def test_backups_are_private_and_rotated(env, monkeypatch):
    m, *_ = env
    monkeypatch.setattr("app.manage.KEEP_BACKUPS", 3)
    for i in range(5):
        m.backup("t", {"f": str(i)})
    root = m.s.data_dir / "backups"
    dirs = sorted(root.iterdir())
    assert len(dirs) == 3 and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE((dirs[-1] / "f").stat().st_mode) == 0o600
