"""Бэкапы в Telegram и на e-mail.

Супер-администратор получает бэкап всего портала: снимок БД панели, data.key (ключ шифрования приватных ключей
клиентов) и файлы AmneziaWG (awg0.conf, clientsTable, ключи сервера, PSK) — из него восстанавливаются и панель,
и VPN. Администратор группы — бэкап своих групп: список клиентов (CSV) и их конфиги .conf.

Полный бэкап портала содержит ещё и .env панели (пароль и TOTP администратора, ключи, токен бота, почта): по нему
поднимается новый сервер — см. restore.sh и README, раздел «Восстановление из бэкапа».

Архив всегда зашифрован паролем, который задаёт администратор (AES-256-GCM, ключ из пароля через scrypt): в нём
приватные ключи, а Telegram и почта — чужие серверы. Расшифровать:

    docker compose exec panel python -m app.backup decrypt /data/<файл>.awgbak     # спросит пароль
    python3 -m app.backup decrypt awg-backup.awgbak -o awg-backup.tar.gz           # то же на любом компьютере с пакетами панели
    python -m app.backup restore <файл> [--env /srv/host.env] [--host <новый IP>]  # восстановление (панель остановлена)
"""
from __future__ import annotations

import csv
import datetime
import getpass
import glob
import hashlib
import io
import logging
import os
import re
import sqlite3
import sys
import tarfile
import tempfile
import threading
import time
import zipfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db, fmt, groups
from .i18n import t

log = logging.getLogger("backup")

MAGIC = b"AWGBAK1\n"
HOST_DIR = os.environ.get("PANEL_HOST_DIR", "/srv/host")       # каталог установки панели, смонтирован только для чтения
ENV_FILE = os.environ.get("PANEL_ENV_FILE", os.path.join(HOST_DIR, ".env"))
HOST_ROOT = os.environ.get("PANEL_HOST_ROOT", "/proc/1/root")   # корень хоста (pid: host) — Dockerfile AmneziaWG
KIT = os.path.join(os.path.dirname(__file__), "restore_kit")    # install.sh и инструкция для полного бэкапа
OPENSSL_ITER = 600000
SQLITE_HEADER = b"SQLite format 3\x00"
MIN_PASSWORD = 8
PERIODS = ("daily", "weekly")
LIMIT = 45 << 20            # Telegram принимает документы до 50 МБ


class BackupError(ValueError):
    pass


# ---- шифрование ----

def _key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=2**15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)


def encrypt(data: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise BackupError(t("This is not an AWG panel backup."))
    salt, nonce, body = blob[len(MAGIC):len(MAGIC) + 16], blob[len(MAGIC) + 16:len(MAGIC) + 28], blob[len(MAGIC) + 28:]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, body, MAGIC)
    except Exception as e:  # cryptography.exceptions.InvalidTag
        raise BackupError(t("Wrong password or the file is damaged.")) from e


# ---- формат openssl enc: полный бэкап расшифровывается на голом сервере одной командой ----
#   openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -md sha256 -in <файл> | tar xz

def encrypt_openssl(data: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    salt = os.urandom(8)
    kiv = PBKDF2HMAC(hashes.SHA256(), 48, salt, OPENSSL_ITER).derive(passphrase.encode())
    pad = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(kiv[:32]), modes.CBC(kiv[32:])).encryptor()
    return b"Salted__" + salt + enc.update(pad.update(data) + pad.finalize()) + enc.finalize()


def decrypt_openssl(blob: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    salt = blob[8:16]
    kiv = PBKDF2HMAC(hashes.SHA256(), 48, salt, OPENSSL_ITER).derive(passphrase.encode())
    dec = Cipher(algorithms.AES(kiv[:32]), modes.CBC(kiv[32:])).decryptor()
    try:
        unpad = padding.PKCS7(128).unpadder()
        data = unpad.update(dec.update(blob[16:]) + dec.finalize()) + unpad.finalize()
    except ValueError as e:
        raise BackupError(t("Wrong password or the file is damaged.")) from e
    if data[:2] != b"\x1f\x8b":
        raise BackupError(t("Wrong password or the file is damaged."))
    return data


# ---- архивы ----

RESTORE_TXT = """AWG panel backup — {when}
Restore: README, section "Restore from a backup" (restore.sh on a new server, Backups page on the same one).

panel.env         /opt/awg-panel/.env (admin password and TOTP, keys, bot token, mail)
panel.db          panel database (stop the panel, put it into /opt/awg-panel/data/, delete panel.db-wal/-shm)
data.key          key that encrypts client private keys in panel.db (put next to panel.db; DATA_KEY in .env instead, if set)
amnezia-awg/      AmneziaWG files from /opt/amnezia/awg in the amnezia-awg2 container
                  (copy back, then: awg syncconf awg0 <(awg-quick strip /opt/amnezia/awg/awg0.conf))
"""


HISTORY_TABLES = ("flows", "dns")    # журнал соединений и DNS: 90 % базы, восстанавливается отдельно и по желанию


def snapshot(db_path, data_dir, history: bool = False) -> bytes:
    """Снимок БД без остановки панели (sqlite backup). Без history — без журнала соединений и DNS, сжатый VACUUM:
    в нём всё, что нужно для работы (клиенты, ключи, группы, статистика по часам и дням), и он в разы меньше."""
    with tempfile.TemporaryDirectory(dir=data_dir) as tmp:
        snap = os.path.join(tmp, "panel.db")
        src, dst = sqlite3.connect(db_path), sqlite3.connect(snap)
        try:
            src.backup(dst)
            if not history:
                for tbl in HISTORY_TABLES:
                    dst.execute(f"DELETE FROM {tbl}")
                dst.commit()
                dst.execute("VACUUM")
        finally:
            dst.close()
            src.close()
        with open(snap, "rb") as f:
            return f.read()


def history_archive(db_path, data_dir) -> bytes:
    """tar.gz: history.db — только таблицы журнала соединений и DNS (без индексов) и HISTORY.txt."""
    now = int(time.time())
    with tempfile.TemporaryDirectory(dir=data_dir) as tmp:
        path = os.path.join(tmp, "history.db")
        src = sqlite3.connect(db_path, isolation_level=None)
        try:
            src.execute("ATTACH DATABASE ? AS h", (path,))
            src.execute("BEGIN")           # один снимок на обе таблицы
            for tbl in HISTORY_TABLES:   # без ключей и индексов: файл вдвое меньше, дубли отсекает база при загрузке
                if src.execute("SELECT 1 FROM main.sqlite_master WHERE type = 'table' AND name = ?", (tbl,)).fetchone():
                    src.execute(f"CREATE TABLE h.{tbl} AS SELECT * FROM main.{tbl}")
            src.execute("COMMIT")
            src.execute("DETACH DATABASE h")
        finally:
            src.close()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
            def add(name: str, data: bytes) -> None:
                info = tarfile.TarInfo(f"awg-history/{name}")
                info.size, info.mtime, info.mode = len(data), now, 0o600
                tar.addfile(info, io.BytesIO(data))
            with open(path, "rb") as f:
                add("history.db", f.read())
            add("HISTORY.txt", HISTORY_TXT.format(when=fmt.dt(now, "%Y-%m-%d %H:%M")).encode())
        return buf.getvalue()


HISTORY_TXT = """AWG panel connection log — {when}
Sites and DNS queries of the clients for the last days (tables flows and dns). The panel works without it:
restore the full backup first, then load this file on the Backups page ("Restore from a backup").
"""


def split(name: str, blob: bytes, limit: int | None = None) -> list[tuple[str, bytes]]:
    """Файл больше лимита Telegram — на части name.001, name.002, …; склеиваются обратно: cat name.0* > name."""
    limit = limit or LIMIT
    if len(blob) <= limit:
        return [(name, blob)]
    return [(f"{name}.{i // limit + 1:03d}", blob[i:i + limit]) for i in range(0, len(blob), limit)]


def join(files: list[tuple[str, bytes]]) -> list[tuple[str, bytes]]:
    """Обратно к split: части одного файла (name.001, name.002, …) склеиваются по порядку, остальные — как есть."""
    whole: dict[str, list[tuple[int, bytes]]] = {}
    out: list[tuple[str, bytes]] = []
    for name, data in files:
        m = re.fullmatch(r"(.+)\.(\d{3})", name or "")
        if m:
            whole.setdefault(m.group(1), []).append((int(m.group(2)), data))
        else:
            out.append((name, data))
    for base, parts in whole.items():
        nums = sorted(n for n, _ in parts)
        if nums != list(range(1, len(nums) + 1)):
            raise BackupError(t("Not all parts of {name} were chosen: got {got}.", name=base, got=", ".join(f"{n:03d}" for n in nums)))
        out.append((base, b"".join(d for _, d in sorted(parts))))
    return out


def portal_archive(db_path, data_dir, awg) -> bytes:
    """tar.gz: снимок БД (sqlite backup — без остановки панели), data.key и файлы AmneziaWG."""
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        def add(name: str, data: bytes) -> None:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), now, 0o600
            tar.addfile(info, io.BytesIO(data))

        add("panel.db", snapshot(db_path, data_dir))
        if os.path.exists(ENV_FILE):
            with open(ENV_FILE, "rb") as f:
                add("panel.env", f.read())
        key = os.path.join(data_dir, "data.key")
        if os.path.exists(key):
            with open(key, "rb") as f:
                add("data.key", f.read())
        if awg is not None:
            folder = awg.path("awg0.conf").parent
            for p in sorted(folder.iterdir()):
                if p.is_file() and not p.name.startswith("."):
                    add(f"amnezia-awg/{p.name}", p.read_bytes())
        add("RESTORE.txt", RESTORE_TXT.format(when=fmt.dt(now, "%Y-%m-%d %H:%M")).encode())
    return buf.getvalue()


SOURCE_SKIP = ("data/", "caddy/", ".git/", ".venv/", "samples/", "docs/", "tools/", "secrets/")


def full_archive(db_path, data_dir, awg, host_dir: str = HOST_DIR) -> bytes:
    """Полный бэкап: всё, чтобы install.sh поднял сервер с нуля — исходники и скрипты панели, база, data.key, .env,
    файлы AmneziaWG, Dockerfile и start.sh контейнера, его параметры, контрольные суммы. Корень архива — awg-full/."""
    import hashlib as _h
    import json as _json
    now = int(time.time())
    files: dict[str, tuple[bytes, int]] = {}

    def put(name: str, data: bytes, mode: int = 0o600) -> None:
        files[name] = (data, mode)

    # исходники и скрипты панели — из каталога установки (без данных и сертификатов)
    if os.path.isdir(host_dir):
        for root, dirs, names in os.walk(host_dir):
            rel = os.path.relpath(root, host_dir)
            rel = "" if rel == "." else rel + "/"
            dirs[:] = [d for d in dirs if not (rel + d + "/").startswith(SOURCE_SKIP) and d not in ("__pycache__", ".pytest_cache")]
            for n in names:
                if (rel + n).startswith(SOURCE_SKIP) or n == ".env" or n.endswith((".pyc", ".awgbak", ".enc")):
                    continue
                path = os.path.join(root, n)
                with open(path, "rb") as f:
                    put(f"panel/{rel}{n}", f.read(), 0o755 if os.access(path, os.X_OK) else 0o644)
    # данные панели (без журнала соединений — он идёт отдельным архивом)
    put("panel-data/panel.db", snapshot(db_path, data_dir))
    for name, src_path in (("data.key", os.path.join(data_dir, "data.key")), ("panel.env", ENV_FILE)):
        if os.path.exists(src_path):
            with open(src_path, "rb") as f:
                put(f"panel-data/{name}", f.read())
    # AmneziaWG: файлы, start.sh из контейнера, Dockerfile с хоста, параметры запуска
    meta = {"created": now, "created_text": fmt.dt(now, "%Y-%m-%d %H:%M"), "awg": None}
    try:
        from . import __version__
        meta["panel_version"] = __version__
    except ImportError:
        pass
    env_vals = {}
    if "panel-data/panel.env" in files:
        for line in files["panel-data/panel.env"][0].decode(errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env_vals[k.strip()] = v.strip()
    meta["panel_host"] = env_vals.get("PANEL_HOST", "")
    meta["panel_port"] = env_vals.get("PANEL_PORT", "14443") or "14443"
    try:
        folder = awg.path("awg0.conf").parent if awg is not None else None
    except Exception as e:  # noqa: BLE001 — AmneziaWG недоступен: бэкап панели всё равно ценен, install.sh пропустит шаг
        folder, meta["awg_error"] = None, str(e)[:200]
    if folder is not None:
        for p in sorted(folder.iterdir()):
            if p.is_file() and not p.name.startswith("."):
                put(f"amnezia/awg/{p.name}", p.read_bytes())
        start = folder.parent / "start.sh"
        if start.exists():
            put("amnezia/start.sh", start.read_bytes(), 0o755)
        port, subnet = "", ""
        for line in (folder / "awg0.conf").read_text().splitlines():
            if line.split("=")[0].strip() == "ListenPort":
                port = line.split("=", 1)[1].strip()
        try:   # сеть контейнера (amnezia-dns-net): адрес eth0 внутри контейнера
            out = awg.run(["ip", "-4", "-o", "addr", "show", "eth0"], mount=False)
            import ipaddress as _ip
            subnet = str(_ip.ip_interface(out.split()[3]).network)
        except Exception:  # noqa: BLE001 — без подсети install.sh возьмёт её по умолчанию
            subnet = ""
        name = "amnezia-awg2"
        for df in sorted(glob.glob(os.path.join(HOST_ROOT, "opt/amnezia/*/Dockerfile"))):
            name = os.path.basename(os.path.dirname(df))
            with open(df, "rb") as f:
                put("amnezia/Dockerfile", f.read(), 0o644)
            break
        meta["awg"] = {"container": name, "port": port, "network": "amnezia-dns-net", "subnet": subnet}
    put("meta.json", _json.dumps(meta, ensure_ascii=False, indent=2).encode(), 0o644)
    for kit in ("install.sh", "RESTORE.txt"):
        with open(os.path.join(KIT, kit), "rb") as f:
            put(kit, f.read(), 0o755 if kit.endswith(".sh") else 0o644)
    put("SHA256SUMS", "".join(f"{_h.sha256(d).hexdigest()}  {n}\n" for n, (d, _) in sorted(files.items())).encode(), 0o644)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=6) as tar:
        for n, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(f"awg-full/{n}")
            info.size, info.mtime, info.mode = len(data), now, mode
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def group_archive(conn: sqlite3.Connection, group_ids: set[int], config_for) -> bytes:
    """zip: clients.csv и конфиги клиентов групп (у кого ключ есть у панели)."""
    peers = conn.execute(
        "SELECT p.*, g.name AS group_name, c.email, c.tg_chat_id FROM peers p JOIN groups g ON g.id = p.group_id "
        f"LEFT JOIN contacts c ON c.peer_id = p.id WHERE p.deleted_at IS NULL{db.peer_filter(group_ids, 'p.group_id')[0]} "
        "ORDER BY g.name, p.name", db.peer_filter(group_ids, "p.group_id")[1]).fetchall()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        out = io.StringIO()
        w = csv.writer(out, delimiter=";")
        w.writerow(["group", "name", "ip", "disabled", "quota_bytes", "quota_period", "email", "telegram_id", "note", "config"])
        names: set[str] = set()
        for p in peers:
            cfg = config_for(p["id"]) if config_for else None
            fname = ""
            if cfg:
                from .clientconf import file_name
                fname = file_name(cfg["name"], cfg["ip"])
                if fname in names:
                    fname = fname.removesuffix(".conf") + f"-{p['ip']}.conf"
                names.add(fname)
                z.writestr(f"configs/{fname}", cfg["conf"])
            w.writerow([p["group_name"], p["name"], p["ip"], p["disabled"], p["quota_bytes"] or "", p["quota_period"],
                        p["email"] or "", p["tg_chat_id"] or "", p["note"] or "", fname])
        z.writestr("clients.csv", "﻿" + out.getvalue())
    return buf.getvalue()


# ---- восстановление ----

PARTS = ("db", "awg", "env")


FULL_MAP = {"awg-full/panel-data/panel.db": "panel.db", "awg-full/panel-data/data.key": "data.key",
            "awg-full/panel-data/panel.env": "panel.env"}


def read_archive(blob: bytes, passphrase: str) -> dict[str, bytes]:
    """Расшифровать бэкап портала (полный или прежний) и вернуть его файлы под единые имена: panel.db, data.key,
    panel.env, amnezia-awg/*. Бэкап группы (zip) восстанавливать нечем — это конфиги."""
    data = decrypt_openssl(blob, passphrase) if blob.startswith(b"Salted__") else decrypt(blob, passphrase)
    if data[:2] != b"\x1f\x8b":
        raise BackupError(t("This is a group backup: it holds client configs, there is nothing to restore on the server."))
    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile() and ".." not in m.name and not m.name.startswith("/"):
                name = m.name
                if name == "awg-history/history.db":
                    name = "history.db"
                elif name.startswith("awg-full/"):
                    name = FULL_MAP.get(name) or ("amnezia-awg/" + name[len("awg-full/amnezia/awg/"):]
                                                  if name.startswith("awg-full/amnezia/awg/") else name)
                out[name] = tar.extractfile(m).read()
    if "history.db" in out and out["history.db"].startswith(SQLITE_HEADER):
        return out
    if "panel.db" not in out or not out["panel.db"].startswith(SQLITE_HEADER):
        raise BackupError(t("The backup has no panel database."))
    return out


def import_history(db_path, data_dir, blob: bytes) -> int:
    """Журнал соединений из архива awg-history — в текущую базу; уже имеющиеся строки не дублируются.
    Возвращает число добавленных строк."""
    added = 0
    with tempfile.TemporaryDirectory(dir=str(data_dir)) as tmp:
        path = os.path.join(tmp, "history.db")
        with open(path, "wb") as f:
            f.write(blob)
        conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("ATTACH DATABASE ? AS h", (path,))
            conn.execute("BEGIN IMMEDIATE")
            for tbl in HISTORY_TABLES:
                if not conn.execute("SELECT 1 FROM h.sqlite_master WHERE type = 'table' AND name = ?", (tbl,)).fetchone():
                    continue
                mine = [r[1] for r in conn.execute(f"PRAGMA main.table_info({tbl})")]
                theirs = {r[1] for r in conn.execute(f"PRAGMA h.table_info({tbl})")}
                cols = ", ".join(c for c in mine if c in theirs)
                added += conn.execute(f"INSERT OR IGNORE INTO main.{tbl} ({cols}) SELECT {cols} FROM h.{tbl}").rowcount
            conn.execute("COMMIT")
            conn.execute("DETACH DATABASE h")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
    return added


def set_host(env: bytes, host: str) -> bytes:
    """Новый публичный IP/домен сервера в .env (PANEL_HOST и PUBLIC_HOST)."""
    lines, seen = env.decode().splitlines(), set()
    for i, line in enumerate(lines):
        k = line.split("=", 1)[0].strip()
        if k in ("PANEL_HOST", "PUBLIC_HOST"):
            lines[i] = f"{k}={host}"
            seen.add(k)
    lines += [f"{k}={host}" for k in ("PANEL_HOST", "PUBLIC_HOST") if k not in seen]
    return ("\n".join(lines) + "\n").encode()


def _write(path, data: bytes, mode: int = 0o600) -> None:
    tmp = f"{path}.restore-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def restore(files: dict[str, bytes], settings, awg, parts: set[str], live: bool, env_path: str | None = None,
            host: str | None = None) -> list[str]:
    """Вернуть из бэкапа выбранное: db — база и data.key, awg — файлы AmneziaWG (применяются без перезапуска),
    env — .env панели. live=True: панель работает — база кладётся в data/restore и подставляется при старте.
    Текущее состояние перед этим сохраняется в data/backups. Возвращает список сделанного."""
    done: list[str] = []
    data_dir = str(settings.data_dir)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    keep = os.path.join(data_dir, "backups", f"{stamp}-pre-restore")
    os.makedirs(keep, mode=0o700, exist_ok=True)
    if "awg" in parts:
        names = [n.split("/", 1)[1] for n in files if n.startswith("amnezia-awg/")]
        if "awg0.conf" not in names and f"{settings.awg_iface}.conf" not in names:
            raise BackupError(t("The backup has no AmneziaWG files."))
        folder = awg.path(f"{settings.awg_iface}.conf").parent
        with awg.locked():
            for p in folder.iterdir():
                if p.is_file() and not p.name.startswith("."):
                    _write(os.path.join(keep, "awg-" + p.name), p.read_bytes())
            from .awgctl import atomic_write
            for name in names:
                atomic_write(folder / name, files[f"amnezia-awg/{name}"].decode())
            awg.run(["bash", "-c", f"awg syncconf {settings.awg_iface} <(awg-quick strip {settings.awg_dir}/{settings.awg_iface}.conf)"])
        done.append(t("AmneziaWG files restored and applied"))
    if "db" in parts:
        if os.path.exists(settings.db_path):
            src, dst = sqlite3.connect(settings.db_path), sqlite3.connect(os.path.join(keep, "panel.db"))
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
        target = os.path.join(data_dir, "restore") if live else data_dir
        os.makedirs(target, mode=0o700, exist_ok=True)
        _write(os.path.join(target, "panel.db"), files["panel.db"])
        if "data.key" in files:
            _write(os.path.join(target, "data.key"), files["data.key"])
        if not live:
            for ext in ("-wal", "-shm"):
                try:
                    os.remove(os.path.join(data_dir, "panel.db" + ext))
                except FileNotFoundError:
                    pass
        done.append(t("panel database restored") if not live else t("panel database will be restored when the panel restarts"))
    if "env" in parts and "panel.env" in files:
        if not env_path:
            done.append(t(".env was not changed (restore it with restore.sh)"))
        else:
            env = set_host(files["panel.env"], host) if host else files["panel.env"]
            with open(env_path, "wb") as f:          # bind-mount: перезапись на месте, без rename
                f.write(env)
            done.append(t(".env restored") + (f" (PANEL_HOST/PUBLIC_HOST = {host})" if host else ""))
    return done


def apply_staged(data_dir) -> bool:
    """При старте панели: база из data/restore заменяет текущую (её копия уже в data/backups/…-pre-restore)."""
    staged = os.path.join(str(data_dir), "restore", "panel.db")
    if not os.path.exists(staged):
        return False
    for ext in ("-wal", "-shm"):
        try:
            os.remove(os.path.join(str(data_dir), "panel.db" + ext))
        except FileNotFoundError:
            pass
    os.replace(staged, os.path.join(str(data_dir), "panel.db"))
    key = os.path.join(str(data_dir), "restore", "data.key")
    if os.path.exists(key):
        os.replace(key, os.path.join(str(data_dir), "data.key"))
    log.warning("panel database restored from a backup")
    return True


# ---- задания ----

def job(conn: sqlite3.Connection, admin_id: int) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO backup_jobs (admin_id) VALUES (?)", (admin_id,))
    return conn.execute("SELECT * FROM backup_jobs WHERE admin_id = ?", (admin_id,)).fetchone()


def save_job(conn: sqlite3.Connection, fernet, admin_id: int, enabled: bool, to_telegram: bool, to_email: bool, email: str,
             period: str, hour: str, weekday: str, password: str, with_history: bool = True) -> None:
    from .portal import EMAIL_RE
    cur = job(conn, admin_id)
    email = (email or "").strip()[:200]
    if to_email and not EMAIL_RE.fullmatch(email):
        raise BackupError(t("Enter a valid e-mail address."))
    if period not in PERIODS:
        raise BackupError(t("Unknown period or action."))
    if password and len(password) < MIN_PASSWORD:
        raise BackupError(t("The archive password must be at least {n} characters.", n=MIN_PASSWORD))
    pass_enc = fernet.encrypt(password.encode()).decode() if password else cur["pass_enc"]
    if enabled and not pass_enc:
        raise BackupError(t("Set an archive password: backups are always encrypted."))
    if enabled and not (to_telegram or to_email):
        raise BackupError(t("Choose where to send the backup: Telegram, e-mail or both."))
    conn.execute("UPDATE backup_jobs SET enabled = ?, to_telegram = ?, to_email = ?, email = ?, period = ?, hour = ?, "
                 "weekday = ?, pass_enc = ?, with_history = ? WHERE admin_id = ?",
                 (int(enabled), int(to_telegram), int(to_email), email or None, period,
                  int(hour) % 24 if hour.isdigit() else 3, int(weekday) % 7 if weekday.isdigit() else 0, pass_enc,
                  int(with_history), admin_id))


RETRIES, RETRY_GAP = 3, 30 * 60      # сбой по расписанию (часто — сеть): ещё 3 попытки через 30 минут


class Backups:
    """Расписание и отправка. notifier — каналы (Telegram, e-mail) и сборка конфигов; awg — файлы AmneziaWG."""

    def __init__(self, settings, conn: sqlite3.Connection, notifier, fernet, awg=None):
        self.s, self.conn, self.n, self.fernet, self.awg = settings, conn, notifier, fernet, awg
        self._lock = threading.Lock()
        self.running: set[int] = set()     # admin_id, чей бэкап собирается прямо сейчас (кнопка «сейчас»)
        self.pause = 20                    # секунд между повторами отправки одного файла

    def build(self, admin: sqlite3.Row, now: int, history: bool = False) -> list[tuple[str, bytes]]:
        """Незашифрованные архивы: супер-администратору — полный бэкап и (по желанию) журнал соединений отдельно."""
        stamp = fmt.dt(now, "%Y%m%d-%H%M")
        if admin["role"] == "super":
            out = [(f"awg-full-{stamp}.tar.gz.enc", full_archive(self.s.db_path, str(self.s.data_dir), self.awg))]
            if history:
                out.append((f"awg-history-{stamp}.tar.gz.enc", history_archive(self.s.db_path, str(self.s.data_dir))))
            return out
        gids = groups.admin_group_ids(self.conn, admin["id"])
        if not gids:
            raise BackupError(t("No groups: sees nothing"))
        return [(f"awg-groups-{admin['username']}-{stamp}.awgbak", group_archive(self.conn, gids, self.n.config_for))]

    @staticmethod
    def seal(name: str, raw: bytes, password: str) -> bytes:
        return encrypt_openssl(raw, password) if name.endswith(".enc") else encrypt(raw, password)

    def _send(self, fn, *args) -> None:
        """Отправка одного файла: сеть сервера бывает с перерывами — ещё две попытки с паузой."""
        for attempt in range(3):
            try:
                return fn(*args)
            except BackupError:
                raise
            except Exception:  # noqa: BLE001
                if attempt == 2:
                    raise
                time.sleep(self.pause)

    def run(self, admin_id: int, now: int | None = None, alert: bool = True) -> str:
        """Собрать, зашифровать и отправить бэкап администратора; итог пишется в задание и в журнал.
        alert=False — это не последняя попытка: сбой записывается без алерта, повтор будет позже."""
        now = int(time.time()) if now is None else now
        with self._lock:
            admin = self.conn.execute("SELECT * FROM admins WHERE id = ?", (admin_id,)).fetchone()
            j = job(self.conn, admin_id)
            sent, errors, size = [], [], 0
            try:
                if not j["pass_enc"]:
                    raise BackupError(t("Set an archive password: backups are always encrypted."))
                password = self.fernet.decrypt(j["pass_enc"].encode()).decode()
                files: list[tuple[str, bytes]] = []
                for name, raw in self.build(admin, now, bool(j["with_history"])):
                    files += split(name, self.seal(name, raw, password))
                size = sum(len(b) for _, b in files)
                total = len(files)
                if j["to_telegram"]:
                    try:
                        if not (self.n.tg and admin["tg_chat_id"]):
                            raise BackupError(t("Telegram is not connected on the My account page."))
                        for i, (name, blob) in enumerate(files, 1):
                            caption = t("AWG panel backup {name}, {size}. Encrypted with your backup password.",
                                        name=name, size=fmt.size(len(blob)))
                            if total > 1:
                                caption += " " + t("File {i} of {n}.", i=i, n=total)
                            self._send(self.n.tg.send_document, admin["tg_chat_id"], name, blob, caption, "application/octet-stream")
                        sent.append("Telegram" + (f" ({total})" if total > 1 else ""))
                    except Exception as e:  # noqa: BLE001 — второй канал всё равно пробуем
                        errors.append(f"Telegram: {e}")
                if j["to_email"]:
                    try:
                        if not self.n.email_on:
                            raise BackupError(t("E-mail is not configured: add SMTP_* to .env on the server."))
                        from .notify import send_email
                        for i, (name, blob) in enumerate(files, 1):   # по письму на файл: у почты свой лимит вложений
                            caption = t("AWG panel backup {name}, {size}. Encrypted with your backup password.",
                                        name=name, size=fmt.size(len(blob)))
                            self._send(send_email, self.s, j["email"], t("AWG panel backup {name}", name=name)
                                       + (f" ({i}/{total})" if total > 1 else ""), caption,
                                       None, [(name, blob, "application", "octet-stream")])
                        sent.append(j["email"])
                    except Exception as e:  # noqa: BLE001
                        errors.append(f"e-mail: {e}")
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
            ok = bool(sent) and not errors
            status = (t("sent: {to}", to=", ".join(sent)) if sent else "") + ("; " if sent and errors else "") + "; ".join(errors)
            self.conn.execute("UPDATE backup_jobs SET last_ts = ?, last_ok = ?, last_status = ?, last_size = ? WHERE admin_id = ?",
                              (now, int(ok), status[:500], size, admin_id))
            kind = "backup_sent" if ok else ("alert_backup" if alert else "backup_retry")
            db.event(self.conn, kind, None, {"username": admin["username"], "status": status[:300]},
                     admin["username"] if ok else None, ts=now)
            return status

    def start(self, admin_id: int) -> bool:
        """Кнопка «Сделать бэкап сейчас»: сборка и отправка идут в фоне (минута и больше), страница не ждёт."""
        if admin_id in self.running:
            return False
        self.running.add(admin_id)

        def work() -> None:
            try:
                self.run(admin_id)
            except Exception:  # noqa: BLE001
                log.exception("backup")
            finally:
                self.running.discard(admin_id)
        threading.Thread(target=work, name="backup-now", daemon=True).start()
        return True

    def due(self, now: int) -> int:
        local = datetime.datetime.fromtimestamp(now, fmt.TZ)
        day = local.strftime("%Y-%m-%d")
        n = 0
        for j in self.conn.execute("SELECT j.* FROM backup_jobs j JOIN admins a ON a.id = j.admin_id "
                                   "WHERE j.enabled = 1 AND a.disabled = 0").fetchall():
            if j["last_day"] != day and j["hour"] == local.hour:
                if j["period"] == "weekly" and local.weekday() != j["weekday"]:
                    continue
                self.conn.execute("UPDATE backup_jobs SET last_day = ?, retries = 0 WHERE admin_id = ?", (day, j["admin_id"]))
                self.run(j["admin_id"], now, alert=False)
            elif (j["last_day"] == day and not j["last_ok"] and j["retries"] < RETRIES
                  and now - (j["last_ts"] or 0) >= RETRY_GAP):
                self.conn.execute("UPDATE backup_jobs SET retries = retries + 1 WHERE admin_id = ?", (j["admin_id"],))
                self.run(j["admin_id"], now, alert=j["retries"] + 1 >= RETRIES)
            else:
                continue
            n += 1
        return n

    def loop(self, stop: threading.Event) -> None:
        while not stop.wait(60):
            try:
                self.due(int(time.time()))
            except Exception:  # noqa: BLE001
                log.exception("backup")


def _cli() -> None:
    if len(sys.argv) < 3 or sys.argv[1] not in ("decrypt", "restore"):
        sys.exit(__doc__)
    src = sys.argv[2]
    if sys.argv[1] == "restore":
        from .awgctl import AWG
        from .config import settings
        arg = lambda k: sys.argv[sys.argv.index(k) + 1] if k in sys.argv else None  # noqa: E731
        with open(src, "rb") as f:
            files = read_archive(f.read(), getpass.getpass("Backup password: "))
        parts = set((arg("--parts") or "db,awg,env").split(","))
        for line in restore(files, settings, AWG(settings), parts, live=False, env_path=arg("--env"), host=arg("--host")):
            print("✓", line)
        return
    out = sys.argv[sys.argv.index("-o") + 1] if "-o" in sys.argv else None
    with open(src, "rb") as f:
        blob = f.read()
    data = decrypt(blob, getpass.getpass("Backup password: "))
    if not out:
        base = src.removesuffix(".awgbak")
        out = base + (".tar.gz" if data[:2] == b"\x1f\x8b" else ".zip")
    with open(out, "wb") as f:
        f.write(data)
    print(f"Decrypted: {out}")


if __name__ == "__main__":
    _cli()
