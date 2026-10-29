"""Файлы сервера AmneziaWG: awg0.conf и clientsTable.

Правки делаются так, чтобы всё, чего они не касаются, осталось байт в байт: файл делится на секции по строкам «[...]»,
каждая секция хранит свой исходный текст. Новый [Peer] пишется в формате, который создаёт приложение AmneziaVPN.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str                 # "Interface" | "Peer" | "" (текст до первой секции)
    raw: str                  # исходный текст секции вместе с завершающими пустыми строками
    values: dict[str, str] = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: str) -> Section:
        name, values = "", {}
        for line in raw.splitlines():
            s = line.strip()
            if not s or s.startswith(("#", ";")):
                continue
            if s.startswith("[") and s.endswith("]"):
                name = s[1:-1].strip()
            elif "=" in s:
                k, v = s.split("=", 1)
                values[k.strip()] = v.strip()
        return cls(name, raw, values)


@dataclass
class AwgConf:
    sections: list[Section]

    @classmethod
    def parse(cls, text: str) -> AwgConf:
        chunks, cur = [], []
        for line in text.splitlines(keepends=True):
            if line.lstrip().startswith("[") and cur:
                chunks.append("".join(cur))
                cur = []
            cur.append(line)
        if cur:
            chunks.append("".join(cur))
        return cls([Section.parse(c) for c in chunks])

    def render(self) -> str:
        return "".join(s.raw for s in self.sections)

    @property
    def interface(self) -> dict[str, str]:
        for s in self.sections:
            if s.name == "Interface":
                return s.values
        raise ValueError("the config has no [Interface] section")

    @property
    def peers(self) -> list[dict[str, str]]:
        return [s.values for s in self.sections if s.name == "Peer"]

    def peer(self, pubkey: str) -> dict[str, str] | None:
        return next((p for p in self.peers if p.get("PublicKey") == pubkey), None)

    def peer_ips(self) -> dict[str, str]:
        """pubkey → IP клиента (первый адрес из AllowedIPs, без маски)."""
        return {p["PublicKey"]: first_ip(p.get("AllowedIPs", "")) for p in self.peers if "PublicKey" in p}

    def add_peer(self, pubkey: str, psk: str, ip: str) -> None:
        if self.peer(pubkey):
            raise ValueError("a client with this key is already in the config")
        if self.sections and not self.sections[-1].raw.endswith("\n\n"):
            last = self.sections[-1]
            last.raw = last.raw if last.raw.endswith("\n") else last.raw + "\n"
            last.raw += "\n"
        raw = f"[Peer]\nPublicKey = {pubkey}\nPresharedKey = {psk}\nAllowedIPs = {ip}/32\n\n"
        self.sections.append(Section.parse(raw))

    def remove_peer(self, pubkey: str) -> bool:
        n = len(self.sections)
        self.sections = [s for s in self.sections if not (s.name == "Peer" and s.values.get("PublicKey") == pubkey)]
        return len(self.sections) != n


def first_ip(allowed_ips: str) -> str:
    return allowed_ips.split(",")[0].strip().split("/")[0] if allowed_ips.strip() else ""


# ---- clientsTable ----

def parse_clients(text: str) -> list[dict]:
    data = json.loads(text) if text.strip() else []
    if not isinstance(data, list):
        raise ValueError("clientsTable: a JSON array was expected")
    return data


def render_clients(clients: list[dict]) -> str:
    return json.dumps(clients, indent=4, ensure_ascii=False) + "\n"


def qt_date(ts: float | None = None) -> str:
    """Дата в формате Qt::TextDate, как её пишет приложение AmneziaVPN: «Wed Oct 8 17:14:55 2026»."""
    t = time.localtime(ts)
    return time.strftime("%a %b ", t) + str(t.tm_mday) + time.strftime(" %H:%M:%S %Y", t)


def client_entry(pubkey: str, ip: str, name: str, ts: float | None = None) -> dict:
    return {"clientId": pubkey,
            "userData": {"allowed_ips": f"{ip}/32", "clientName": name, "creationDate": qt_date(ts)}}


def clients_by_key(clients: list[dict]) -> dict[str, dict]:
    return {c.get("clientId", ""): c.get("userData", {}) for c in clients}
