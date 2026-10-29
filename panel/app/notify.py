"""Уведомления клиентам: Telegram-бот, e-mail, ежедневная сводка картинкой, события.

Каналы включаются сами, когда в .env есть TELEGRAM_BOT_TOKEN / SMTP_HOST; без них всё остальное работает.
"""
from __future__ import annotations

import datetime
import json
import logging
import smtplib
import sqlite3
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid
from email.message import EmailMessage

from . import db, fmt, i18n, portal, report
from .i18n import t
from .config import Settings

log = logging.getLogger("notify")

# какие события клиента ему пересылаются
CLIENT_EVENTS = {"alert_new_country", "alert_shared_config", "admin_disable", "admin_enable", "block_add", "block_delete",
                 "alert_traffic_spike"}


# ---- Telegram ----

class Telegram:
    def __init__(self, token: str):
        self.token = token
        self.username: str | None = None

    def call(self, method: str, params: dict | None = None, files: dict[str, tuple[str, bytes, str]] | None = None,
             timeout: float = 30) -> dict:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        if files:
            boundary = uuid.uuid4().hex
            body = b""
            for k, v in (params or {}).items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
            for k, (name, data, ctype) in files.items():
                body += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; filename=\"{name}\"\r\n"
                         f"Content-Type: {ctype}\r\n\r\n").encode() + data + b"\r\n"
            body += f"--{boundary}--\r\n".encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        else:
            req = urllib.request.Request(url, data=urllib.parse.urlencode(params or {}).encode())
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out = json.loads(r.read())
        except urllib.error.HTTPError as e:
            out = json.loads(e.read() or b"{}") or {"ok": False, "description": str(e)}
        if not out.get("ok"):
            raise RuntimeError(f"Telegram {method}: {out.get('description')}")
        return out["result"]

    def me(self) -> str:
        if not self.username:
            self.username = self.call("getMe")["username"]
        return self.username

    def send(self, chat_id: int, text: str) -> None:
        self.call("sendMessage", {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"})

    def send_photo(self, chat_id: int, png: bytes, caption: str) -> None:
        self.call("sendPhoto", {"chat_id": chat_id, "caption": caption[:1000]}, {"photo": ("stats.png", png, "image/png")})


# ---- e-mail ----

def send_email(s: Settings, to: str, subject: str, text: str, png: bytes | None = None) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from or s.smtp_user, to, subject
    msg.set_content(text)
    if png:
        msg.add_attachment(png, maintype="image", subtype="png", filename="stats.png")
    ctx = ssl.create_default_context()
    if s.smtp_ssl or s.smtp_port == 465:
        with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, context=ctx, timeout=30) as m:
            if s.smtp_user:
                m.login(s.smtp_user, s.smtp_password)
            m.send_message(msg)
    else:
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30) as m:
            m.starttls(context=ctx)
            if s.smtp_user:
                m.login(s.smtp_user, s.smtp_password)
            m.send_message(msg)


# ---- рассылка ----

class Notifier:
    def __init__(self, settings: Settings, conn: sqlite3.Connection):
        self.s, self.conn = settings, conn
        self.tg = Telegram(settings.telegram_token) if settings.telegram_token else None
        self.last_error: str | None = None
        self._lock = threading.Lock()

    @property
    def email_on(self) -> bool:
        return bool(self.s.smtp_host)

    def log(self, peer_id: int, channel: str, kind: str, err: str | None) -> None:
        self.conn.execute("INSERT INTO notify_log (ts, peer_id, channel, kind, ok, error) VALUES (?, ?, ?, ?, ?, ?)",
                          (int(time.time()), peer_id, channel, kind, int(err is None), err))

    def lang(self, peer_id: int) -> str | None:
        row = self.conn.execute("SELECT lang FROM contacts WHERE peer_id = ?", (peer_id,)).fetchone()
        return row[0] if row else None

    def deliver(self, peer_id: int, kind: str, text: str, png: bytes | None = None, subject: str | None = None) -> int:
        """В Telegram и/или на подтверждённый e-mail клиента; возвращает число успешных отправок."""
        c = portal.contact(self.conn, peer_id)
        sent = 0
        if self.tg and c["tg_chat_id"]:
            try:
                self.tg.send_photo(c["tg_chat_id"], png, text) if png else self.tg.send(c["tg_chat_id"], text)
                self.log(peer_id, "telegram", kind, None)
                sent += 1
            except Exception as e:  # noqa: BLE001 — сбой канала не должен мешать другому
                self.log(peer_id, "telegram", kind, str(e)[:300])
        if self.email_on and c["email"] and c["email_verified"]:
            try:
                send_email(self.s, c["email"], subject or t("VPN: notification"), text, png)
                self.log(peer_id, "email", kind, None)
                sent += 1
            except Exception as e:  # noqa: BLE001
                self.log(peer_id, "email", kind, str(e)[:300])
        return sent

    def daily(self, peer_id: int, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        with i18n.use(self.lang(peer_id)):
            png, caption = report.daily_png(self.conn, peer_id, now)
            name = self.conn.execute("SELECT name FROM peers WHERE id = ?", (peer_id,)).fetchone()[0]
            return self.deliver(peer_id, "daily", caption, png,
                                subject=t("VPN: statistics for {date} — {name}", date=fmt.dt(now, "%d.%m"), name=name))

    def due_daily(self, now: int) -> None:
        local = datetime.datetime.fromtimestamp(now, fmt.TZ)
        day = local.strftime("%Y-%m-%d")
        for r in self.conn.execute(
                "SELECT c.peer_id FROM contacts c JOIN peers p ON p.id = c.peer_id WHERE p.deleted_at IS NULL AND c.daily = 1 "
                "AND c.daily_hour = ? AND COALESCE(c.last_daily, '') != ? AND (c.tg_chat_id IS NOT NULL OR c.email_verified = 1)",
                (local.hour, day)).fetchall():
            self.conn.execute("UPDATE contacts SET last_daily = ? WHERE peer_id = ?", (day, r[0]))
            self.daily(r[0], now)

    def due_events(self) -> None:
        last = int(db.get_state(self.conn, "notify_event_id", "0") or 0)
        if not last:   # первый запуск — не рассылаем историю
            last = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        rows = self.conn.execute(
            "SELECT e.id, e.kind, e.detail, e.peer_id FROM events e JOIN contacts c ON c.peer_id = e.peer_id "
            "WHERE e.id > ? AND c.events = 1 ORDER BY e.id LIMIT 200", (last,)).fetchall()
        top = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        for r in rows:
            if r["kind"] in CLIENT_EVENTS:
                with i18n.use(self.lang(r["peer_id"])):
                    self.deliver(r["peer_id"], r["kind"], "VPN: " + fmt.event_text(r["kind"], r["detail"]))
        db.set_state(self.conn, "notify_event_id", str(max(top, last)))

    # ---- бот: привязка и команды ----

    def handle_update(self, u: dict) -> None:
        m = u.get("message") or {}
        chat = (m.get("chat") or {}).get("id")
        text = (m.get("text") or "").strip()
        if not chat or not text:
            return
        who = (m.get("from") or {})
        name = "@" + who["username"] if who.get("username") else who.get("first_name", "")
        if text.startswith("/start"):
            code = text.split(maxsplit=1)[1] if " " in text else ""
            row = portal.bind_telegram(self.conn, code, chat, name) if code else None
            if row:
                with i18n.use(self.lang(row["peer_id"])):
                    self.tg.send(chat, t("Done: VPN notifications for “{name}” will come here.", name=row["name"]) + "\n"
                                 + t("/stats — today's statistics, /stop — disconnect."))
            else:
                self.tg.send(chat, t("Open your VPN portal and press “Connect Telegram” — the link is valid for an hour."))
        elif text.startswith("/stop"):
            n = portal.unbind_telegram(self.conn, chat)
            self.tg.send(chat, t("Notifications disabled.") if n else t("This chat was not connected."))
        elif text.startswith("/stats"):
            row = self.conn.execute("SELECT peer_id FROM contacts WHERE tg_chat_id = ?", (chat,)).fetchone()
            if row:
                with i18n.use(self.lang(row[0])):
                    png, caption = report.daily_png(self.conn, row[0], int(time.time()))
                self.tg.send_photo(chat, png, caption)
            else:
                self.tg.send(chat, t("This chat is not connected to a VPN portal."))

    def bot_loop(self, stop: threading.Event) -> None:
        offset = 0
        while not stop.is_set():
            try:
                for u in self.tg.call("getUpdates", {"offset": offset, "timeout": 50}, timeout=60):
                    offset = u["update_id"] + 1
                    with self._lock:
                        self.handle_update(u)
                self.last_error = None
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:300]
                stop.wait(15)

    def run(self, stop: threading.Event) -> None:
        if self.tg:
            threading.Thread(target=self.bot_loop, args=(stop,), name="telegram", daemon=True).start()
        while not stop.wait(60):
            try:
                with self._lock:
                    now = int(time.time())
                    self.due_events()
                    self.due_daily(now)
            except Exception as e:  # noqa: BLE001
                self.last_error = repr(e)
                log.exception("notify")
