import json
import os
import stat

import pytest

from app import awgconf, awgctl
from app.config import Settings

K = lambda c: (c * 43)[:43] + "="  # noqa: E731 — тестовый ключ base64 нужной длины

CONF = (
    "[Interface]\n"
    f"PrivateKey = {K('s')}\n"
    "Address = 10.8.1.0/24\n"
    "ListenPort = 51820\n"
    "Jc = 4\n"
    "H4 = 4\n"
    f"HeaderProtectionKey = {K('h')}\n"
    "DisableCookies = on\n"
    "[Peer]\n"
    f"PublicKey = {K('a')}\n"
    f"PresharedKey = {K('p')}\n"
    "AllowedIPs = 10.8.1.1/32\n"
    "\n"
    "[Peer]\n"
    f"PublicKey = {K('b')}\n"
    f"PresharedKey = {K('p')}\n"
    "AllowedIPs = 10.8.1.3/32\n"
    "\n"
)

CLIENTS = [
    {"clientId": K("a"), "userData": {"allowed_ips": "10.8.1.1/32", "clientName": "Admin [macOS]",
                                      "creationDate": "Sat Sep 19 14:51:50 2026"}},
    {"clientId": K("b"), "userData": {"allowed_ips": "10.8.1.3/32", "clientName": "Тимур",
                                      "creationDate": "Sat Sep 19 15:02:48 2026", "dataReceived": "30.75 GiB"}},
]

DUMP = "\t".join([K("s"), K("S"), "51820", "4", "10", "50"] + ["x"] * 23) + "\n" + \
    f"{K('a')}\t{K('p')}\t95.24.72.224:28113\t10.8.1.1/32\t1793218812\t218625\t620472\toff\n" + \
    f"{K('b')}\t{K('p')}\t(none)\t10.8.1.3/32\t0\t0\t0\toff\n"


def test_conf_roundtrip_is_byte_exact():
    assert awgconf.AwgConf.parse(CONF).render() == CONF


def test_conf_values():
    c = awgconf.AwgConf.parse(CONF)
    assert c.interface["ListenPort"] == "51820" and c.interface["DisableCookies"] == "on"
    assert c.peer_ips() == {K("a"): "10.8.1.1", K("b"): "10.8.1.3"}


def test_conf_add_and_remove_peer():
    c = awgconf.AwgConf.parse(CONF)
    c.add_peer(K("c"), K("p"), "10.8.1.4")
    assert c.render() == CONF + f"[Peer]\nPublicKey = {K('c')}\nPresharedKey = {K('p')}\nAllowedIPs = 10.8.1.4/32\n\n"
    with pytest.raises(ValueError):
        c.add_peer(K("c"), K("p"), "10.8.1.5")
    assert c.remove_peer(K("c")) and c.render() == CONF
    assert c.remove_peer(K("a"))
    assert "10.8.1.1/32" not in c.render() and c.render().startswith("[Interface]")
    assert not c.remove_peer(K("z"))


def test_conf_add_after_file_without_trailing_blank():
    c = awgconf.AwgConf.parse(CONF.rstrip("\n"))
    c.add_peer(K("c"), K("p"), "10.8.1.4")
    assert "AllowedIPs = 10.8.1.3/32\n\n[Peer]\n" in c.render()


def test_clients_roundtrip_and_entry():
    text = awgconf.render_clients(CLIENTS)
    assert awgconf.parse_clients(text) == CLIENTS and text.endswith("]\n") and "Тимур" in text
    e = awgconf.client_entry(K("c"), "10.8.1.4", "Новый", ts=0)
    assert e["userData"]["allowed_ips"] == "10.8.1.4/32" and list(e) == ["clientId", "userData"]


def test_qt_date_has_unpadded_day():
    import time
    ts = time.mktime((2026, 10, 8, 17, 14, 55, 0, 0, -1))
    assert awgconf.qt_date(ts) == "Thu Oct 8 17:14:55 2026"


def test_parse_dump():
    peers = awgctl.parse_dump(DUMP)
    assert len(peers) == 2
    a, b = peers
    assert a.endpoint_ip == "95.24.72.224" and a.latest_handshake == 1793218812 and (a.rx, a.tx) == (218625, 620472)
    assert b.endpoint is None and b.endpoint_ip is None and b.latest_handshake == 0


@pytest.fixture
def fake(tmp_path):
    proc = tmp_path / "proc"
    (proc / "1").mkdir(parents=True)
    (proc / "1" / "cmdline").write_bytes(b"/sbin/init\0")
    (proc / "77").mkdir()
    (proc / "77" / "cmdline").write_bytes(b"amneziawg-go\0awg0\0")
    d = proc / "77" / "root" / "opt" / "amnezia" / "awg"
    d.mkdir(parents=True)
    (d / "awg0.conf").write_text(CONF)
    os.chmod(d / "awg0.conf", 0o001)  # как на сервере: ---------x
    (d / "clientsTable").write_text(awgconf.render_clients(CLIENTS))
    (d / "wireguard_psk.key").write_text(K("p") + "\n")
    s = Settings(data_dir=tmp_path / "data")
    return awgctl.AWG(s, proc=proc), d


def test_find_pid_and_files(fake):
    awg, d = fake
    assert awg.pid() == 77
    os.chmod(d / "awg0.conf", 0o600)  # чтобы прочитать в тесте без root
    conf = awg.read_conf()
    assert conf.render() == CONF
    assert awgconf.clients_by_key(awg.read_clients())[K("b")]["clientName"] == "Тимур"
    assert awg.psk() == K("p")


def test_write_keeps_mode(fake):
    awg, d = fake
    os.chmod(d / "awg0.conf", 0o640)
    conf = awgconf.AwgConf.parse(CONF)
    conf.add_peer(K("c"), K("p"), "10.8.1.4")
    awg.write_conf(conf)
    assert stat.S_IMODE((d / "awg0.conf").stat().st_mode) == 0o640
    assert "10.8.1.4/32" in (d / "awg0.conf").read_text()
    assert not list(d.glob(".*panel-tmp"))
    awg.write_clients(CLIENTS + [awgconf.client_entry(K("c"), "10.8.1.4", "c")])
    assert len(json.loads((d / "clientsTable").read_text())) == 3


def test_pid_rediscovered_after_restart(fake):
    awg, d = fake
    assert awg.pid() == 77
    proc = d.parents[4]
    (proc / "77" / "cmdline").write_bytes(b"sleep\0")
    (proc / "88").mkdir()
    (proc / "88" / "cmdline").write_bytes(b"amneziawg-go\0awg0\0")
    assert awg.pid() == 88
    (proc / "88" / "cmdline").write_bytes(b"x\0")
    with pytest.raises(awgctl.AwgUnavailable):
        awg.pid()


def test_locked_is_exclusive(fake):
    awg, _ = fake
    with awg.locked():
        assert (awg.s.data_dir / "awg.lock").exists()
