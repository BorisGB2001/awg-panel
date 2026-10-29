"""Блокировка доменов и IP для клиентов VPN.

Правила живут в ядре: цепочка AWGPANEL_BLOCK в filter-таблице net-namespace контейнера amnezia-awg2, переход в неё —
первым правилом FORWARD для -i awg0. Панель только пишет правила: если она остановлена, блокировка продолжает работать.
После рестарта контейнера (новый PID) правила ставятся заново.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import sqlite3
import threading
import time

from . import db
from .awgctl import AWG, AwgUnavailable
from .config import Settings
from .i18n import t

log = logging.getLogger("blocker")

CHAIN = "AWGPANEL_BLOCK"

# Публичные DNS-резолверы с DoH/DoT: для клиентов с доменными правилами закрываем им 443/853, чтобы браузер
# и Android («Частный DNS») откатились на обычный DNS, который блокировка видит.
DOH_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
                 "208.67.220.220", "94.140.14.14", "94.140.15.15", "77.88.8.8", "77.88.8.1", "185.228.168.9",
                 "76.76.2.0", "45.90.28.0", "45.90.30.0"]

PRESETS: dict[str, list[str]] = {
    "YouTube": ["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com",
                "youtubei.googleapis.com", "yt3.ggpht.com", "youtube.googleapis.com"],
    "TikTok": ["tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "byteoversea.com", "ibytedtos.com",
               "musical.ly"],
    "Instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
    "Facebook": ["facebook.com", "fbcdn.net", "facebook.net", "fb.com", "fb.me", "messenger.com"],
    "X (Twitter)": ["x.com", "twitter.com", "twimg.com", "t.co"],
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


class BlockError(ValueError):
    pass


def parse_value(raw: str, vpn_subnet: str) -> tuple[str, str]:
    """('ip', '1.2.3.0/24') | ('domain', 'youtube.com'); всё, что нельзя безопасно заблокировать, — BlockError."""
    v = raw.strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/", 1)[0] if not re.match(r"^[\d.]+/\d+$", v) else v
    v = v.split(":", 1)[0] if v.count(":") == 1 else v
    v = v.removeprefix("*.").rstrip(".")
    if not v:
        raise BlockError(t("empty value"))
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError:
        net = None
    if net is not None:
        if net.version != 4:
            raise BlockError(t("{value}: IPv6 is not supported — VPN clients have IPv4 only", value=raw))
        if net.prefixlen < 8:
            raise BlockError(t("{value}: the subnet is too wide (less than /8) — it would block almost everything", value=raw))
        if net.overlaps(ipaddress.ip_network(vpn_subnet, strict=False)) or net.is_private:
            raise BlockError(t("{value}: the VPN network or a private network — nothing to block", value=raw))
        return "ip", str(net) if net.prefixlen < 32 else str(net.network_address)
    if v.startswith("www."):
        v = v[4:]
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as e:
        raise BlockError(t("{value}: invalid domain", value=raw)) from e
    if not DOMAIN_RE.match(v):
        raise BlockError(t("{value}: does not look like a domain or IP", value=raw))
    return "domain", v


def dns_hex(domain: str) -> str:
    """Имя в формате DNS для xt_string: youtube.com → |07|youtube|03|com|00|."""
    out = ""
    for label in domain.split("."):
        out += f"|{len(label):02x}|{label}"
    return out + "|00|"


def sni_exact_hex(domain: str) -> str:
    """server_name в ClientHello: 2 байта длины + имя — точное совпадение без захвата notyoutube.com."""
    n = len(domain)
    return f"|{n >> 8:02x} {n & 0xFF:02x}|{domain}"


def build_rules(rules: list[sqlite3.Row | dict], peer_ips: dict[int, str]) -> list[str]:
    """Строки `-A AWGPANEL_BLOCK …` для iptables-restore.

    rules — включённые правила (id, kind, value, peer_id); peer_ips — IP активных клиентов. Правило клиента, которого
    нет среди активных, пропускается.
    """
    lines: list[str] = []
    domain_sources: list[str | None] = []
    for r in rules:
        src = None
        if r["peer_id"] is not None:
            src = peer_ips.get(r["peer_id"])
            if not src:
                continue
        s = f"-s {src}/32 " if src else ""
        tag = f'-m comment --comment "r{r["id"]}"'
        if r["kind"] == "ip":
            lines.append(f"-A {CHAIN} {s}-d {r['value']} {tag} -j REJECT")
            continue
        d = r["value"]
        for proto in ("udp", "tcp"):
            lines.append(f'-A {CHAIN} {s}-p {proto} --dport 53 -m string --algo bm --icase --hex-string "{dns_hex(d)}" '
                         f"{tag} -j DROP")
        lines.append(f'-A {CHAIN} {s}-p tcp --dport 443 -m string --algo bm --icase --hex-string "{sni_exact_hex(d)}" '
                     f"{tag} -j REJECT --reject-with tcp-reset")
        lines.append(f'-A {CHAIN} {s}-p tcp --dport 443 -m string --algo bm --icase --string ".{d}" '
                     f"{tag} -j REJECT --reject-with tcp-reset")
        if src not in domain_sources:
            domain_sources.append(src)
    # против обходов — только для тех, кого касаются доменные правила; если есть общее правило — для всех
    if None in domain_sources:
        domain_sources = [None]
    bypass: list[str] = []
    for src in domain_sources:
        s = f"-s {src}/32 " if src else ""
        bypass.append(f'-A {CHAIN} {s}-p udp --dport 443 -m comment --comment "quic" -j REJECT')
        bypass.append(f'-A {CHAIN} {s}-p tcp --dport 853 -m comment --comment "dot" -j REJECT --reject-with tcp-reset')
        bypass.append(f'-A {CHAIN} {s}-p udp --dport 853 -m comment --comment "dot" -j REJECT')
        bypass.append(f'-A {CHAIN} {s}-p tcp --dport 443 -d {",".join(DOH_RESOLVERS)} -m comment --comment "doh" '
                      f"-j REJECT --reject-with tcp-reset")
    return bypass + lines + [f"-A {CHAIN} -j RETURN"]


def restore_text(lines: list[str]) -> str:
    return "*filter\n" + f":{CHAIN} - [0:0]\n" + "\n".join(lines) + "\nCOMMIT\n"


COUNTER_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s.*/\*\s*(\S+)\s*\*/")


def parse_counters(text: str) -> dict[str, int]:
    """`iptables -L CHAIN -v -x -n` → {comment: пакетов}."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        m = COUNTER_RE.match(line)
        if m:
            out[m.group(3)] = out.get(m.group(3), 0) + int(m.group(1))
    return out


class Blocker:
    def __init__(self, settings: Settings, awg: AWG, conn: sqlite3.Connection):
        self.s, self.awg, self.conn = settings, awg, conn
        self._lock = threading.RLock()   # один экземпляр на процесс: фоновый поток и веб-запросы
        self._applied_pid: int | None = None
        self._last_counts: dict[str, int] = {}
        self.last_error: str | None = None
        self.applied_rules = 0

    # ---- правила в БД ----

    def active_rules(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT b.* FROM block_rules b LEFT JOIN peers p ON p.id = b.peer_id WHERE b.enabled = 1 "
            "AND (b.peer_id IS NULL OR (p.deleted_at IS NULL AND p.disabled = 0)) ORDER BY b.id").fetchall()

    def add(self, values: list[str], peer_id: int | None, note: str = "", preset: str | None = None,
            actor: str | None = None, actor_ip: str | None = None) -> tuple[int, list[str]]:
        """Добавляет правила; возвращает (сколько добавлено, ошибки по отдельным значениям)."""
        with self._lock:
            added, errors = 0, []
            now = int(time.time())
            for raw in values:
                if not raw.strip():
                    continue
                try:
                    kind, value = parse_value(raw, self.s.vpn_subnet)
                except BlockError as e:
                    errors.append(str(e))
                    continue
                cur = self.conn.execute(
                    "INSERT OR IGNORE INTO block_rules (kind, value, peer_id, note, preset, created_at, actor) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)", (kind, value, peer_id, (note or "").strip()[:200] or None, preset, now, actor))
                if cur.rowcount:
                    added += 1
                    db.event(self.conn, "block_add", peer_id, {"kind": kind, "value": value, "preset": preset}, actor, actor_ip, now)
            if added:
                self.apply()
            return added, errors

    def set_enabled(self, rule_id: int, enabled: bool, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM block_rules WHERE id = ?", (rule_id,)).fetchone()
            if not r:
                raise BlockError(t("rule not found"))
            self.conn.execute("UPDATE block_rules SET enabled = ? WHERE id = ?", (int(enabled), rule_id))
            db.event(self.conn, "block_on" if enabled else "block_off", r["peer_id"], {"kind": r["kind"], "value": r["value"]},
                     actor, actor_ip)
            self.apply()

    def delete(self, rule_id: int, actor: str | None = None, actor_ip: str | None = None) -> None:
        with self._lock:
            r = self.conn.execute("SELECT * FROM block_rules WHERE id = ?", (rule_id,)).fetchone()
            if not r:
                raise BlockError(t("rule not found"))
            self.conn.execute("DELETE FROM block_rules WHERE id = ?", (rule_id,))
            db.event(self.conn, "block_delete", r["peer_id"], {"kind": r["kind"], "value": r["value"]}, actor, actor_ip)
            self.apply()

        # ---- ядро ----

    def apply(self) -> None:
        """Атомарно заменяет содержимое цепочки и ставит переход в неё первым правилом FORWARD."""
        with self._lock:
            peer_ips = {r[0]: r[1] for r in self.conn.execute(
                "SELECT id, ip FROM peers WHERE deleted_at IS NULL AND disabled = 0")}
            lines = build_rules(self.active_rules(), peer_ips)
            self.awg.run(["iptables-restore", "--noflush"], input=restore_text(lines))
            jump = ["FORWARD", "-i", self.s.awg_iface, "-j", CHAIN]
            try:
                self.awg.run(["iptables", "-C", *jump])
            except AwgUnavailable:
                self.awg.run(["iptables", "-I", *jump[:1], "1", *jump[1:]])
            self._applied_pid = self.awg.pid()
            self._last_counts = {}
            self.applied_rules = len(lines) - 1
            self.last_error = None

    def collect_hits(self) -> None:
        """Счётчики срабатываний по правилам (пакеты) → block_rules.hits, время последнего срабатывания."""
        with self._lock:
            counts = parse_counters(self.awg.run(["iptables", "-L", CHAIN, "-v", "-x", "-n"]))
            now = int(time.time())
            for tag, n in counts.items():
                prev = self._last_counts.get(tag, 0)
                delta = n - prev if n >= prev else n
                self._last_counts[tag] = n
                if delta > 0 and tag.startswith("r") and tag[1:].isdigit():
                    self.conn.execute("UPDATE block_rules SET hits = hits + ?, hits_ts = ? WHERE id = ?", (delta, now, int(tag[1:])))
                elif delta > 0:
                    db.set_state(self.conn, f"block_hits_{tag}", str(int(db.get_state(self.conn, f"block_hits_{tag}", "0")) + delta))

    def run(self, stop: threading.Event) -> None:
        """Ставит правила при старте и после рестарта контейнера, раз в минуту — проверка перехода и счётчики."""
        while not stop.is_set():
            try:
                pid = self.awg.pid()
                if pid != self._applied_pid:
                    self.apply()
                    log.info("правила блокировки применены (PID %s): %s", pid, self.applied_rules)
                else:
                    try:
                        self.awg.run(["iptables", "-C", "FORWARD", "-i", self.s.awg_iface, "-j", CHAIN])
                    except AwgUnavailable:
                        self.apply()
                self.collect_hits()
            except AwgUnavailable as e:
                self.last_error = str(e)
            except Exception as e:  # noqa: BLE001 — поток не должен умирать
                self.last_error = repr(e)
                log.exception("blocker")
            stop.wait(60)


def rule_matches(rule_kind: str, rule_value: str, name: str) -> bool:
    """Для пометки «заблокировано» в списке сайтов: домен и его поддомены."""
    return rule_kind == "domain" and (name == rule_value or name.endswith("." + rule_value))
