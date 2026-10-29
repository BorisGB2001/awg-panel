"""Управление клиентами: добавить, удалить, переименовать, отключить, включить.

Каждая операция: блокировка → свежее чтение обоих файлов → бэкап → запись → применение на живом интерфейсе
(awg set, без перезапуска) → сверка с `awg show dump`. Ошибка на любом шаге после бэкапа — файлы и интерфейс
возвращаются в исходное состояние.
"""
from __future__ import annotations

import base64
import os
import shutil
import sqlite3
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from . import awgconf, db
from .awgctl import AWG, atomic_write
from .config import Settings
from .i18n import t
from .ipalloc import next_ip

KEEP_BACKUPS = 200


class ManageError(RuntimeError):
    """Понятная администратору причина отказа или сбоя."""


def gen_keypair() -> tuple[str, str]:
    """(private, public) в base64, как `awg genkey | awg pubkey`."""
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def clean_name(name: str) -> str:
    name = "".join(ch for ch in unicodedata.normalize("NFC", name or "") if unicodedata.category(ch)[0] != "C").strip()
    if not 1 <= len(name) <= 64:
        raise ManageError(t("Client name must be 1 to 64 characters."))
    return name


def load_fernet(settings: Settings) -> Fernet:
    """Ключ шифрования приватных ключей клиентов: DATA_KEY из .env, иначе файл /data/data.key (создаётся сам)."""
    if settings.data_key:
        return Fernet(settings.data_key.encode())
    path = settings.data_dir / "data.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(Fernet.generate_key())
    return Fernet(path.read_bytes().strip())


@dataclass
class Change:
    """Что операция делает с файлами и интерфейсом."""
    conf: awgconf.AwgConf
    clients: list[dict]
    live: list[tuple[str, str, str]] = field(default_factory=list)   # ("set", pub, ip) | ("remove", pub, "")


class Manager:
    def __init__(self, settings: Settings, awg: AWG, conn: sqlite3.Connection, fernet: Fernet | None = None):
        self.s, self.awg, self.conn = settings, awg, conn
        self.fernet = fernet or load_fernet(settings)

    # ---- общий каркас операции ----

    def _apply(self, op: str, build) -> None:
        """build(conf, clients) -> Change. Всё под блокировкой, с бэкапом и откатом."""
        conf_name = f"{self.s.awg_iface}.conf"
        raw_conf, raw_clients = self.awg.read_text(conf_name), self._read_clients_raw()
        backup = self.backup(op, {conf_name: raw_conf, "clientsTable": raw_clients})
        before = {p.pubkey: p.allowed_ips for p in self.awg.dump()}
        ch = build(awgconf.AwgConf.parse(raw_conf), awgconf.parse_clients(raw_clients or "[]"))
        done: list[tuple[str, str, str]] = []
        try:
            self.awg.write_conf(ch.conf)
            self.awg.write_clients(ch.clients)
            for act in ch.live:
                if act[0] == "set":
                    self.awg.set_peer(act[1], act[2])
                else:
                    self.awg.remove_peer(act[1])
                done.append(act)
            self._verify(ch.live)
        except Exception as e:
            problems = self._rollback(conf_name, raw_conf, raw_clients, done, before)
            msg = t("The operation failed ({error}); files and interface are restored to the state before it, backup: {backup}.",
                    error=e, backup=backup.name)
            if problems:
                msg += " " + t("Warning, the rollback was incomplete: {items}", items="; ".join(problems))
            raise ManageError(msg) from e

    def _read_clients_raw(self) -> str:
        try:
            return self.awg.read_text("clientsTable")
        except FileNotFoundError:
            return ""

    def _verify(self, live: list[tuple[str, str, str]]) -> None:
        now = {p.pubkey: p.allowed_ips for p in self.awg.dump()}
        for act, pub, ip in live:
            if act == "set" and now.get(pub) != f"{ip}/32":
                raise ManageError(t("after awg set the client did not appear on the interface with {ip}/32", ip=ip))
            if act == "remove" and pub in now:
                raise ManageError(t("after awg set … remove the client is still on the interface"))

    def _rollback(self, conf_name: str, raw_conf: str, raw_clients: str, done, before: dict[str, str]) -> list[str]:
        problems = []
        for path, text in ((self.awg.path(conf_name), raw_conf), (self.awg.path("clientsTable"), raw_clients)):
            try:
                if text or path.exists():
                    atomic_write(path, text)
            except Exception as e:  # noqa: BLE001
                problems.append(f"{path.name}: {e}")
        for act, pub, _ in reversed(done):
            try:
                if pub in before:
                    self.awg.set_peer(pub, before[pub].split("/")[0])
                else:
                    self.awg.remove_peer(pub)
            except Exception as e:  # noqa: BLE001
                problems.append(f"interface {act} {pub[:8]}…: {e}")
        return problems

    def backup(self, op: str, files: dict[str, str]) -> Path:
        root = self.s.data_dir / "backups"
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        d = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{op}"
        n = 1
        while d.exists():
            n += 1
            d = root / f"{time.strftime('%Y%m%d-%H%M%S')}-{op}-{n}"
        d.mkdir(mode=0o700)
        for name, text in files.items():
            fd = os.open(d / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
        for old in sorted(p for p in root.iterdir() if p.is_dir() and p.name[:8].isdigit())[:-KEEP_BACKUPS]:
            shutil.rmtree(old, ignore_errors=True)
        return d

    # ---- проверки ----

    def _peer(self, peer_id: int) -> sqlite3.Row:
        row = self.conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
        if row is None or row["deleted_at"]:
            raise ManageError(t("Client not found."))
        return row

    def _check_unique(self, name: str, skip_id: int | None = None) -> None:
        # lower() в SQLite не знает кириллицу — сравниваем в Python
        rows = self.conn.execute("SELECT id, name FROM peers WHERE deleted_at IS NULL AND id IS NOT ?", (skip_id,))
        if any((r["name"] or "").casefold() == name.casefold() for r in rows):
            raise ManageError(t("A client named “{name}” already exists.", name=name))

    def _used_ips(self, conf: awgconf.AwgConf, clients: list[dict]) -> set[str]:
        used = set(conf.peer_ips().values())
        used |= {awgconf.first_ip(c.get("userData", {}).get("allowed_ips", "")) for c in clients}
        used |= {r[0] for r in self.conn.execute("SELECT ip FROM peers WHERE disabled = 1 AND deleted_at IS NULL")}
        return used

    # ---- операции ----

    def add(self, name: str, note: str = "", actor: str | None = None, actor_ip: str | None = None) -> int:
        name = clean_name(name)
        with self.awg.locked():
            self._check_unique(name)
            priv, pub = gen_keypair()
            psk = self.awg.psk()
            got: dict[str, str] = {}

            def build(conf, clients):
                ip = got["ip"] = next_ip(self.s.vpn_subnet, self._used_ips(conf, clients))
                conf.add_peer(pub, psk, ip)
                return Change(conf, clients + [awgconf.client_entry(pub, ip, name)], [("set", pub, ip)])

            self._apply("add", build)
            now = int(time.time())
            cur = self.conn.execute(
                "INSERT INTO peers (pubkey, name, ip, note, source, private_key_enc, created_at) VALUES (?, ?, ?, ?, 'panel', ?, ?)",
                (pub, name, got["ip"], (note or "").strip()[:500] or None, self.fernet.encrypt(priv.encode()), now))
            db.event(self.conn, "admin_add", cur.lastrowid, {"name": name, "ip": got["ip"]}, actor, actor_ip, now)
            return cur.lastrowid

    def rename(self, peer_id: int, name: str, actor: str | None = None, actor_ip: str | None = None) -> None:
        name = clean_name(name)
        with self.awg.locked():
            row = self._peer(peer_id)
            if name == row["name"]:
                return
            self._check_unique(name, peer_id)
            if not row["disabled"]:
                def build(conf, clients):
                    for c in clients:
                        if c.get("clientId") == row["pubkey"]:
                            c.setdefault("userData", {})["clientName"] = name
                            break
                    else:
                        raise ManageError(t("the client is not in clientsTable"))
                    return Change(conf, clients)

                self._apply("rename", build)
            self.conn.execute("UPDATE peers SET name = ? WHERE id = ?", (name, peer_id))
            db.event(self.conn, "admin_rename", peer_id, {"from": row["name"], "to": name}, actor, actor_ip)

    def _remove_build(self, row: sqlite3.Row):
        def build(conf, clients):
            in_conf = conf.remove_peer(row["pubkey"])
            rest = [c for c in clients if c.get("clientId") != row["pubkey"]]
            if not in_conf and len(rest) == len(clients):
                raise ManageError(t("the client is neither in awg0.conf nor in clientsTable"))
            return Change(conf, rest, [("remove", row["pubkey"], "")])
        return build

    def delete(self, peer_id: int, confirm: str, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.awg.locked():
            row = self._peer(peer_id)
            if confirm.strip() != row["name"]:
                raise ManageError(t("To delete, type the client name exactly."))
            if not row["disabled"]:
                self._apply("delete", self._remove_build(row))
            now = int(time.time())
            self.conn.execute("UPDATE peers SET deleted_at = ?, disabled = 0, private_key_enc = NULL WHERE id = ?", (now, peer_id))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_delete", peer_id, {"name": row["name"], "ip": row["ip"]}, actor, actor_ip, now)

    def rekey(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        """Новые ключи клиента с тем же IP: старый конфиг перестаёт работать, новый выдаёт панель.

        Так же получают конфиг клиенты, созданные в приложении AmneziaVPN (их приватный ключ есть только на устройстве).
        Отключённому клиенту меняется только ключ в БД — на интерфейс он вернётся при включении уже с новым.
        """
        with self.awg.locked():
            row = self._peer(peer_id)
            priv, pub = gen_keypair()
            if not row["disabled"]:
                psk = self.awg.psk()

                def build(conf, clients):
                    if not conf.remove_peer(row["pubkey"]):
                        raise ManageError(t("the client is not in awg0.conf"))
                    conf.add_peer(pub, psk, row["ip"])
                    for c in clients:
                        if c.get("clientId") == row["pubkey"]:
                            c["clientId"] = pub          # имя и дата создания в приложении AmneziaVPN остаются
                            break
                    else:
                        clients.append(awgconf.client_entry(pub, row["ip"], row["name"]))
                    return Change(conf, clients, [("remove", row["pubkey"], ""), ("set", pub, row["ip"])])

                self._apply("rekey", build)
            self.conn.execute("UPDATE peers SET pubkey = ?, private_key_enc = ? WHERE id = ?",
                              (pub, self.fernet.encrypt(priv.encode()), peer_id))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_rekey", peer_id, {"name": row["name"], "ip": row["ip"]}, actor, actor_ip)

    def disable(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.awg.locked():
            row = self._peer(peer_id)
            if row["disabled"]:
                return
            self._apply("disable", self._remove_build(row))
            self.conn.execute("UPDATE peers SET disabled = 1 WHERE id = ?", (peer_id,))
            self.conn.execute("UPDATE sessions SET end = COALESCE(last_active, start) WHERE peer_id = ? AND end IS NULL", (peer_id,))
            db.event(self.conn, "admin_disable", peer_id, {"name": row["name"], "ip": row["ip"]}, actor, actor_ip)

    def enable(self, peer_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self.awg.locked():
            row = self._peer(peer_id)
            if not row["disabled"]:
                return
            psk = self.awg.psk()

            def build(conf, clients):
                owner = {ip: k for k, ip in conf.peer_ips().items()}.get(row["ip"])
                if owner and owner != row["pubkey"]:
                    raise ManageError(t("IP {ip} is already taken by another client (added outside the panel).", ip=row["ip"]))
                if not conf.peer(row["pubkey"]):
                    conf.add_peer(row["pubkey"], psk, row["ip"])
                if not any(c.get("clientId") == row["pubkey"] for c in clients):
                    clients = clients + [awgconf.client_entry(row["pubkey"], row["ip"], row["name"], row["created_at"])]
                return Change(conf, clients, [("set", row["pubkey"], row["ip"])])

            self._apply("enable", build)
            self.conn.execute("UPDATE peers SET disabled = 0 WHERE id = ?", (peer_id,))
            db.event(self.conn, "admin_enable", peer_id, {"name": row["name"], "ip": row["ip"]}, actor, actor_ip)

    def private_key(self, peer_id: int) -> str | None:
        row = self.conn.execute("SELECT private_key_enc FROM peers WHERE id = ?", (peer_id,)).fetchone()
        return self.fernet.decrypt(row[0]).decode() if row and row[0] else None
