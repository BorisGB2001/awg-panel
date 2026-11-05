"""Бэкап по частям: основной без журнала соединений, журнал отдельно, файлы по частям, повторы после сбоя,
алерт о сбое в Telegram (и в тихие часы); настройки алертов на странице «Сервер»."""
import datetime
import io
import sqlite3
import tarfile
import urllib.error

import pytest
from cryptography.fernet import Fernet

from app import admins, alerts, backup, db, fmt, groups, notify
from app.config import Settings
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура
from tests.test_backup import FakeN
from tests.test_tg_admin import FakeTG, bind
from tests.test_tg_admin import setup as tg_setup


def _world(tmp_path):
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(s.db_path)
    conn.execute("INSERT INTO peers (id, pubkey, name, ip) VALUES (1, 'k1', 'Анна', '10.8.1.1')")
    for i in range(500):
        conn.execute("INSERT INTO flows VALUES (?, 1, '192.0.2.1', 443, 'tcp', 'example.com', 1, 10, 20)", (1_800_000_000 + i,))
        conn.execute("INSERT INTO dns VALUES (?, 1, 'example.com', 'A', 1)", (1_800_000_000 + i,))
    return s, conn


def _members(raw: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


def _rows(blob: bytes, tmp_path, sql: str) -> int:
    p = tmp_path / "check.db"
    p.write_bytes(blob)
    c = sqlite3.connect(p)
    try:
        return c.execute(sql).fetchone()[0]
    finally:
        c.close()
        p.unlink()


def test_main_backup_has_no_log_and_log_goes_separately(tmp_path):
    s, conn = _world(tmp_path)
    full = _members(backup.full_archive(s.db_path, str(s.data_dir), None, host_dir=str(tmp_path / "none")))
    dbf = full["awg-full/panel-data/panel.db"]
    assert _rows(dbf, tmp_path, "SELECT COUNT(*) FROM peers") == 1
    assert _rows(dbf, tmp_path, "SELECT COUNT(*) FROM flows") == 0 and _rows(dbf, tmp_path, "SELECT COUNT(*) FROM dns") == 0
    hist = _members(backup.history_archive(s.db_path, str(s.data_dir)))
    assert set(hist) == {"awg-history/history.db", "awg-history/HISTORY.txt"}
    assert _rows(hist["awg-history/history.db"], tmp_path, "SELECT COUNT(*) FROM flows") == 500
    # журнал читается как бэкап и дописывается в базу без дублей
    files = backup.read_archive(backup.encrypt_openssl(backup.history_archive(s.db_path, str(s.data_dir)), "p4ssword"), "p4ssword")
    conn.execute("DELETE FROM flows WHERE ts >= 1800000250")
    conn.execute("DELETE FROM dns")
    assert backup.import_history(s.db_path, s.data_dir, files["history.db"]) == 250 + 500
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 500
    assert backup.import_history(s.db_path, s.data_dir, files["history.db"]) == 0


def test_split_and_join():
    blob = bytes(range(256)) * 10
    parts = backup.split("a.tar.gz.enc", blob, limit=1000)
    assert [n for n, _ in parts] == ["a.tar.gz.enc.001", "a.tar.gz.enc.002", "a.tar.gz.enc.003"]
    assert backup.split("a.enc", b"x" * 10, limit=1000) == [("a.enc", b"x" * 10)]
    assert backup.join(list(reversed(parts))) == [("a.tar.gz.enc", blob)]
    with pytest.raises(backup.BackupError, match="001, 003"):
        backup.join([parts[0], parts[2]])


def test_parts_are_sent_and_failures_retried_then_alerted(tmp_path, monkeypatch):
    s, conn = _world(tmp_path)
    conn.execute("INSERT INTO admins (id, username, pw_hash, role, tg_chat_id) VALUES (1, 'boss', 'x', 'super', 42)")
    f = Fernet(Fernet.generate_key())
    backup.save_job(conn, f, 1, True, True, False, "", "daily", "3", "0", "p4ssword", with_history=True)
    monkeypatch.setattr(backup, "LIMIT", 4096)
    n = FakeN()
    b = backup.Backups(s, conn, n, f, None)
    b.pause = 0
    at3 = int(datetime.datetime(2026, 10, 28, 3, 5, tzinfo=fmt.TZ).timestamp())
    assert b.due(at3) == 1
    names = [x[1] for x in n.docs]
    assert len(names) > 2 and any(x.startswith("awg-history-") for x in names) and all(x[-4] == "." for x in names)
    whole = dict(backup.join([(x[1], x[2]) for x in n.docs]))
    main_ = next(v for k, v in whole.items() if k.startswith("awg-full-"))
    assert "awg-full/install.sh" in _members(backup.decrypt_openssl(main_, "p4ssword"))
    assert backup.job(conn, 1)["last_ok"] == 1

    # Telegram недоступен: попытка, ещё три через 30 минут, алерт — только после последней
    def down(*a, **k):
        raise urllib.error.URLError("Try again")
    n.send_document = down
    conn.execute("UPDATE backup_jobs SET with_history = 0")
    day2 = at3 + 86400
    kinds = lambda: [r[0] for r in conn.execute("SELECT kind FROM events WHERE kind LIKE '%backup%' ORDER BY id")]  # noqa: E731
    assert b.due(day2) == 1 and kinds()[-1] == "backup_retry"
    assert b.due(day2 + 600) == 0                                  # рано повторять
    for i in range(1, backup.RETRIES + 1):
        assert b.due(day2 + i * backup.RETRY_GAP) == 1
    assert kinds()[-backup.RETRIES - 1:] == ["backup_retry"] * backup.RETRIES + ["alert_backup"]
    assert b.due(day2 + 10 * backup.RETRY_GAP) == 0                # попытки кончились


def test_backup_alert_reaches_owner_in_quiet_hours(tmp_path):
    conn, n, olga = tg_setup(tmp_path)
    night = int(datetime.datetime(2026, 10, 15, 3, tzinfo=fmt.TZ).timestamp())
    n.due_admin_events(night)
    bind(conn, n, "boss", 100)
    bind(conn, n, "olga", 200)
    for name in ("boss", "olga"):
        admins.set_notify(conn, admins.by_name(conn, name)["id"], True, True, "23", "7")
    n.tg.sent.clear()
    db.event(conn, "alert_backup", None, {"username": "olga", "status": "Telegram: down"}, ts=night)
    db.event(conn, "alert_traffic_spike", 1, {"bytes": 1, "median": 1}, ts=night)   # тихие часы — не сейчас
    n.due_admin_events(night)
    assert sorted(c for c, _ in n.tg.sent) == [100, 200] and all("down" in t for _, t in n.tg.sent)


def test_admin_alerts_wait_for_the_network(tmp_path):
    conn, n, olga = tg_setup(tmp_path)
    now = int(datetime.datetime(2026, 10, 15, 12, tzinfo=fmt.TZ).timestamp())
    n.due_admin_events(now)
    bind(conn, n, "boss", 100)
    sent = n.tg.sent

    class Down(FakeTG):
        def send(self, chat, text):
            raise urllib.error.URLError("Try again")
    n.tg = Down()
    db.event(conn, "alert_server", None, {"reason": "disk", "used": 91}, ts=now)
    assert n.due_admin_events(now) == 0
    n.tg = FakeTG()
    assert n.due_admin_events(now + 60) == 1 and "91" in n.tg.sent[0][1]   # дошло, когда сеть вернулась
    assert sent is not n.tg.sent


def test_alert_settings(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    a = alerts.Alerts(Settings(data_dir=tmp_path), conn)
    now = 1_800_000_000
    conn.execute("INSERT INTO peers (id, pubkey, name, ip) VALUES (1, 'a', 'Анна', '10.8.1.1')")
    for i in range(6):
        db.event(conn, "endpoint_change", 1, {"to": f"1.1.1.{i % 2}", "asn": 100 + i % 2}, ts=now - 60 * i)
    hour = now - now % 3600 - 3600
    for h in range(1, 30):
        conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 10000000, 100000000)", (hour - h * 3600,))
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 0, ?)", (hour, 3 << 30))
    alerts.save_config(conn, {"spike_on": "1", "spike_min_gib": "5", "spike_factor": "5",
                              "shared_changes": "6", "shared_window_min": "30"})        # «несколько устройств» выключено
    a.load()
    assert a.check_shared(now) == 0 and a.check_spike(now) == 0                       # 3 ГиБ меньше порога 5 ГиБ
    alerts.save_config(conn, {"spike_on": "1", "spike_min_gib": "2,5", "spike_factor": "5", "shared_on": "1",
                              "shared_changes": "6", "shared_window_min": "30"})
    a.load()
    assert a.check_shared(now) == 1 and a.check_spike(now) == 1
    with pytest.raises(ValueError):
        alerts.save_config(conn, {"spike_min_gib": "abc", "spike_factor": "5", "shared_changes": "6", "shared_window_min": "30"})


def test_server_alerts_form_and_restore_in_parts(client, monkeypatch):  # noqa: F811
    from app import main
    _login(client)
    page = client.get("/server").text
    assert 'action="/server/alerts"' in page
    client.post("/server/alerts", data={"csrf": _csrf(page), "spike_on": "1", "spike_min_gib": "3", "spike_factor": "4",
                                        "shared_changes": "8", "shared_window_min": "20"})
    cfg = alerts.config(main.app.state.db)
    assert cfg["spike_min_gib"] == 3 and cfg["spike_factor"] == 4 and cfg["shared_on"] is False
    # журнал соединений по частям — через форму восстановления, без перезапуска
    conn = main.app.state.db
    conn.execute("INSERT INTO flows VALUES (1800000000, 1, '192.0.2.1', 443, 'tcp', 'example.com', 1, 10, 20)")
    blob = backup.encrypt_openssl(backup.history_archive(main.settings.db_path, str(main.settings.data_dir)), "p4ssword")
    conn.execute("DELETE FROM flows")
    parts = backup.split("awg-history-1.tar.gz.enc", blob, limit=len(blob) // 2 + 1)
    tok = _csrf(client.get("/backups").text)
    restarted = []
    main.app.state.restart = lambda: restarted.append(1)
    r = client.post("/backups/restore", data={"csrf": tok, "password": "p4ssword", "confirm": "RESTORE"},
                    files=[("file", (n, d)) for n, d in parts])
    assert "1 records added" in r.text and not restarted
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1
    r = client.post("/backups/restore", data={"csrf": tok, "password": "p4ssword", "confirm": "RESTORE"},
                    files=[("file", parts[1])])
    assert "Not all parts" in r.text
