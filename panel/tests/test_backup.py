"""Бэкапы: шифрование, полный бэкап портала → восстановление, бэкап группы, расписание и отправка, восстановление со страницы."""
import datetime
import io
import os
import re
import tarfile
import zipfile

import pyotp
import pytest
from cryptography.fernet import Fernet

from app import backup, db, fmt, groups
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура
from tests.test_manage import CONF, env  # noqa: F401 — фикстура: LiveAWG на поддельном /proc


def test_encrypt_roundtrip_and_wrong_password():
    blob = backup.encrypt(b"secret data" * 1000, "correct horse")
    assert blob.startswith(backup.MAGIC) and b"secret data" not in blob
    assert backup.decrypt(blob, "correct horse") == b"secret data" * 1000
    with pytest.raises(backup.BackupError):
        backup.decrypt(blob, "wrong")
    with pytest.raises(backup.BackupError):
        backup.decrypt(b"garbage", "x")


def test_full_backup_restores_db_awg_and_env(env, tmp_path, monkeypatch):  # noqa: F811
    m, awg, d, conn = env
    s = m.s
    (s.data_dir / "data.key").write_bytes(b"KEY")
    envf = tmp_path / "host.env"
    envf.write_text("PANEL_HOST=203.0.113.10\nPUBLIC_HOST=203.0.113.10\nTELEGRAM_BOT_TOKEN=t\n")
    monkeypatch.setattr(backup, "ENV_FILE", str(envf))
    conn = db.open_db(s.db_path)              # база панели (у фикстуры своя p.db — для Manager)
    conn.execute("INSERT INTO groups (name) VALUES ('Офис')")
    raw = backup.portal_archive(s.db_path, str(s.data_dir), awg)
    names = tarfile.open(fileobj=io.BytesIO(raw)).getnames()
    assert {"panel.db", "data.key", "panel.env", "amnezia-awg/awg0.conf", "amnezia-awg/clientsTable",
            "amnezia-awg/wireguard_psk.key", "RESTORE.txt"} <= set(names)
    blob = backup.encrypt(raw, "p4ssword")
    # «сломали» сервер: другой конфиг, пустая база, другой .env
    (d / "awg0.conf").write_text("[Interface]\nListenPort = 1\n")
    conn.execute("DELETE FROM groups")
    envf.write_text("")
    ran = []
    monkeypatch.setattr(awg, "run", lambda args, **kw: ran.append(args) or "")
    files = backup.read_archive(blob, "p4ssword")
    conn.close()
    done = backup.restore(files, s, awg, {"db", "awg", "env"}, live=False, env_path=str(envf), host="198.51.100.7")
    assert len(done) == 3
    assert (d / "awg0.conf").read_text() == CONF and "syncconf" in ran[0][-1]
    assert db.open_db(s.db_path).execute("SELECT name FROM groups").fetchone()[0] == "Офис"
    assert "PANEL_HOST=198.51.100.7" in envf.read_text() and "TELEGRAM_BOT_TOKEN=t" in envf.read_text()
    assert any(p.name.endswith("pre-restore") for p in (s.data_dir / "backups").iterdir())   # прежнее состояние сохранено


def test_live_restore_stages_db_until_restart(env, tmp_path, monkeypatch):  # noqa: F811
    m, awg, d, _ = env
    s = m.s
    conn = db.open_db(s.db_path)
    conn.execute("INSERT INTO groups (name) VALUES ('Старая')")
    files = backup.read_archive(backup.encrypt(backup.portal_archive(s.db_path, str(s.data_dir), None), "p4ssword"), "p4ssword")
    conn.execute("UPDATE groups SET name = 'Новая'")
    backup.restore(files, s, awg, {"db"}, live=True)
    assert conn.execute("SELECT name FROM groups").fetchone()[0] == "Новая"          # до перезапуска — как было
    conn.close()
    assert backup.apply_staged(s.data_dir) and not backup.apply_staged(s.data_dir)
    assert db.open_db(s.db_path).execute("SELECT name FROM groups").fetchone()[0] == "Старая"


def test_group_backup_is_not_restorable_and_has_configs(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    for pid, name in ((1, "Анна"), (2, "Вера")):
        conn.execute("INSERT INTO peers (id, pubkey, name, ip) VALUES (?, ?, ?, ?)", (pid, f"k{pid}", name, f"10.8.1.{pid}"))
    g = groups.create(conn, "A")
    groups.set_peer_group(conn, 1, g)
    raw = backup.group_archive(conn, {g}, lambda pid: {"name": "Анна", "ip": "10.8.1.1", "conf": "[Interface]\n"} if pid == 1 else None)
    z = zipfile.ZipFile(io.BytesIO(raw))
    assert "configs/awg-10.8.1.1.conf" in z.namelist()
    csv = z.read("clients.csv").decode()
    assert "Анна" in csv and "Вера" not in csv
    with pytest.raises(backup.BackupError):
        backup.read_archive(backup.encrypt(raw, "p4ssword"), "p4ssword")


class FakeN:
    def __init__(self):
        self.docs, self.mails = [], []
        self.tg = self
        self.email_on = True
        self.config_for = None

    def send_document(self, chat, name, data, caption="", ctype=""):
        self.docs.append((chat, name, data))


def test_job_settings_schedule_and_delivery(tmp_path, monkeypatch):
    from app.config import Settings
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(s.db_path)
    conn.execute("INSERT INTO admins (id, username, pw_hash, role, tg_chat_id) VALUES (1, 'boss', 'x', 'super', 42)")
    f = Fernet(Fernet.generate_key())
    with pytest.raises(backup.BackupError):        # без пароля не включается
        backup.save_job(conn, f, 1, True, True, False, "", "daily", "3", "0", "")
    with pytest.raises(backup.BackupError):
        backup.save_job(conn, f, 1, True, True, False, "", "daily", "3", "0", "short")
    backup.save_job(conn, f, 1, True, True, True, "boss@example.com", "weekly", "3", "2", "p4ssword")
    n = FakeN()
    mails = []
    monkeypatch.setattr("app.notify.send_email", lambda s, to, subj, text, png=None, files=None: mails.append((to, files)))
    b = backup.Backups(s, conn, n, f, None)
    wed3 = int(datetime.datetime(2026, 10, 28, 3, 10, tzinfo=fmt.TZ).timestamp())    # среда, 03:10
    assert b.due(wed3 - 86400) == 0                       # вторник — не тот день
    assert b.due(wed3) == 1 and b.due(wed3 + 600) == 0    # один раз в день
    assert n.docs[0][0] == 42 and n.docs[0][1].endswith(".tar.gz.enc") and mails[0][0] == "boss@example.com"
    data = backup.decrypt_openssl(n.docs[0][2], "p4ssword")                       # супер-админ — полный бэкап
    assert "awg-full/panel-data/panel.db" in tarfile.open(fileobj=io.BytesIO(data)).getnames()
    j = backup.job(conn, 1)
    assert j["last_ok"] == 1 and "Telegram" in j["last_status"]


def test_backups_page_and_restore_route(client, monkeypatch):  # noqa: F811
    from app import main
    _login(client)
    page = client.get("/backups").text
    assert "the full server" in page and "install.sh" in page and 'action="/backups/restore"' in page
    tok = _csrf(page)
    client.post("/backups/save", data={"csrf": tok, "enabled": "1", "to_telegram": "1", "period": "daily", "hour": "3",
                                       "weekday": "0", "password": "p4ssword"})
    conn = main.app.state.db
    assert backup.job(conn, conn.execute("SELECT id FROM admins WHERE env = 1").fetchone()[0])["enabled"] == 1
    r = client.post("/backups/download", data={"csrf": tok})                    # скачать из браузера
    assert r.headers["content-type"] == "application/octet-stream" and r.content.startswith(b"Salted__")
    assert "awg-full/install.sh" in tarfile.open(fileobj=io.BytesIO(backup.decrypt_openssl(r.content, "p4ssword"))).getnames()
    conn.execute("INSERT INTO groups (name) VALUES ('Из бэкапа')")
    blob = backup.encrypt(backup.portal_archive(main.settings.db_path, str(main.settings.data_dir), None), "p4ssword")
    restarted = []
    main.app.state.restart = lambda: restarted.append(1)
    r = client.post("/backups/restore", data={"csrf": tok, "password": "wrong", "part_db": "1", "confirm": "RESTORE"},
                    files={"file": ("b.awgbak", blob)})
    assert "Wrong password" in r.text and not restarted
    r = client.post("/backups/restore", data={"csrf": tok, "password": "p4ssword", "part_db": "1", "confirm": "RESTORE"},
                    files={"file": ("b.awgbak", blob)})
    assert restarted and "restarts" in r.text
    assert os.path.exists(main.settings.data_dir / "restore" / "panel.db")


def test_group_admin_has_no_restore(client, world):  # noqa: F811
    page = client.get("/backups").text
    assert "your groups (A)" in page and 'action="/backups/restore"' not in page
    assert client.post("/backups/restore", data={"csrf": _csrf(page)}).status_code == 403


from tests.test_groups import world  # noqa: E402,F401 — фикстура


def test_full_backup_openssl_compatible_and_complete(env, tmp_path, monkeypatch):  # noqa: F811
    """Полный бэкап: системный openssl расшифровывает командой из RESTORE.txt, tar распаковывает, суммы сходятся,
    внутри — всё для install.sh; и та же панель восстанавливает из него базу и файлы AmneziaWG."""
    import json
    import shutil
    import subprocess
    m, awg, d, _ = env
    s = m.s
    host = tmp_path / "host"
    (host / "panel" / "app").mkdir(parents=True)
    (host / "docker-compose.yml").write_text("services: {}\n")
    (host / "deploy.sh").write_text("#!/bin/sh\n")
    (host / "panel" / "app" / "main.py").write_text("# code\n")
    (host / "data").mkdir()
    (host / "data" / "panel.db").write_text("must not be copied as source")
    (host / ".env").write_text("PANEL_HOST=203.0.113.10\nPANEL_PORT=14443\n")
    monkeypatch.setattr(backup, "ENV_FILE", str(host / ".env"))
    root = tmp_path / "hostroot" / "opt" / "amnezia" / "amnezia-awg2"
    root.mkdir(parents=True)
    (root / "Dockerfile").write_text("FROM amneziavpn/amneziawg-go:latest\n")
    monkeypatch.setattr(backup, "HOST_ROOT", str(tmp_path / "hostroot"))
    (d.parent / "start.sh").write_text("#!/bin/bash\nawg-quick up /opt/amnezia/awg/awg0.conf\n")
    conn = db.open_db(s.db_path)
    conn.execute("INSERT INTO groups (name) VALUES ('Полный')")
    raw = backup.full_archive(s.db_path, str(s.data_dir), awg, host_dir=str(host))
    blob = backup.encrypt_openssl(raw, "p4ss word")
    assert blob.startswith(b"Salted__")
    enc = tmp_path / "awg-full.tar.gz.enc"
    enc.write_bytes(blob)
    out = tmp_path / "out"
    out.mkdir()
    if shutil.which("openssl"):
        r = subprocess.run(f"openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -pass pass:'p4ss word' -in {enc} | tar xz -C {out}",
                           shell=True, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        full = out / "awg-full"
        names = {str(p.relative_to(full)) for p in full.rglob("*") if p.is_file()}
        assert {"install.sh", "RESTORE.txt", "meta.json", "SHA256SUMS", "panel/docker-compose.yml", "panel/deploy.sh",
                "panel/panel/app/main.py", "panel-data/panel.db", "panel-data/panel.env", "amnezia/Dockerfile",
                "amnezia/start.sh", "amnezia/awg/awg0.conf", "amnezia/awg/clientsTable"} <= names
        assert not any(n.startswith("panel/data/") for n in names) and "panel/.env" not in names
        assert os.access(full / "install.sh", os.X_OK)
        meta = json.loads((full / "meta.json").read_text())
        assert meta["panel_host"] == "203.0.113.10" and meta["awg"]["port"] == "51820" and meta["awg"]["container"] == "amnezia-awg2"
        check = "sha256sum -c --quiet SHA256SUMS" if shutil.which("sha256sum") else "shasum -a 256 -c --quiet SHA256SUMS"
        assert subprocess.run(check, shell=True, cwd=full).returncode == 0
        assert subprocess.run(["bash", "-n", str(full / "install.sh")]).returncode == 0
    with pytest.raises(backup.BackupError):
        backup.decrypt_openssl(blob, "wrong")
    files = backup.read_archive(blob, "p4ss word")             # панель понимает новый формат
    assert files["panel.db"].startswith(backup.SQLITE_HEADER) and "amnezia-awg/awg0.conf" in files and "panel.env" in files
