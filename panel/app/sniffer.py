"""Домены, к которым обращаются клиенты: DNS-ответы и SNI из TLS ClientHello на awg0.

tcpdump запускается в net-namespace amnezia-awg2 и отдаёт pcap в stdout; фильтр BPF пропускает только DNS-ответы
и первые сегменты TLS ClientHello — остальной трафик (десятки ГБ в день) в Python не попадает.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import sqlite3
import struct
import subprocess
import threading
import time
from collections import defaultdict
from typing import BinaryIO, Iterator

from .awgctl import AWG, AwgUnavailable
from .config import Settings
from .names import NameCache

log = logging.getLogger("sniffer")

BPF = "udp src port 53 or (tcp dst port 443 and tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)"
LINK_OFFSET = {101: 0, 12: 0, 228: 0, 229: 0, 113: 16, 276: 20, 0: 4, 1: 14}


# ---- pcap ----

def pcap_packets(stream: BinaryIO) -> Iterator[tuple[float, bytes]]:
    """(время, IP-пакет) из потока pcap."""
    hdr = stream.read(24)
    if len(hdr) < 24:
        return
    magic = hdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap stream")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(endian + "I", hdr[20:24])[0]
    off = LINK_OFFSET.get(link, 0)
    while True:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, _ = struct.unpack(endian + "IIII", rec)
        data = stream.read(incl)
        if len(data) < incl:
            return
        yield sec + frac / (1e9 if nano else 1e6), data[off:]


def parse_ip(pkt: bytes) -> tuple[str, str, int, int, int, bytes] | None:
    """(src, dst, proto, sport, dport, payload) для TCP/UDP поверх IPv4/IPv6."""
    if not pkt:
        return None
    ver = pkt[0] >> 4
    if ver == 4 and len(pkt) >= 20:
        ihl = (pkt[0] & 0x0F) * 4
        proto = pkt[9]
        src, dst = socket.inet_ntop(socket.AF_INET, pkt[12:16]), socket.inet_ntop(socket.AF_INET, pkt[16:20])
        l4 = pkt[ihl:]
    elif ver == 6 and len(pkt) >= 40:
        proto = pkt[6]
        src, dst = socket.inet_ntop(socket.AF_INET6, pkt[8:24]), socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        l4 = pkt[40:]
    else:
        return None
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return src, dst, proto, sport, dport, l4[8:]
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        return src, dst, proto, sport, dport, l4[(l4[12] >> 4) * 4:]
    return None


# ---- DNS ----

def _name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels, end = [], None
    while pos < len(msg):
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if depth > 10 or pos + 1 >= len(msg):
                raise ValueError("dns: compression loop")
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            end = pos + 2 if end is None else end
            rest, _ = _name(msg, ptr, depth + 1)
            if rest:
                labels.append(rest)
            pos = end
            return ".".join(labels).lower(), pos
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels).lower(), (end if end is not None else pos)


def parse_dns_response(msg: bytes) -> tuple[str, int, list[str]] | None:
    """(имя запроса, тип запроса, IP из ответов A/AAAA). None — не ответ или ошибка разбора."""
    try:
        if len(msg) < 12:
            return None
        flags, qd, an = struct.unpack("!HHH", msg[2:8])
        if not flags & 0x8000 or qd != 1:
            return None
        qname, pos = _name(msg, 12)
        qtype = struct.unpack("!H", msg[pos:pos + 2])[0]
        pos += 4
        ips = []
        for _ in range(an):
            _, pos = _name(msg, pos)
            rtype, _, _, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
            pos += 10
            rdata = msg[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif rtype == 28 and rdlen == 16:
                ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
        return qname.rstrip("."), qtype, ips
    except (ValueError, struct.error, IndexError):
        return None


# ---- TLS SNI ----

def parse_sni(data: bytes) -> str | None:
    """server_name из TLS ClientHello (если он целиком в первом сегменте)."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        p = 9 + 2 + 32                      # record(5) + handshake hdr(4) + version + random
        p += 1 + data[p]                    # session id
        p += 2 + struct.unpack("!H", data[p:p + 2])[0]   # cipher suites
        p += 1 + data[p]                    # compression
        end = p + 2 + struct.unpack("!H", data[p:p + 2])[0]
        p += 2
        while p + 4 <= min(end, len(data)):
            etype, elen = struct.unpack("!HH", data[p:p + 4])
            p += 4
            if etype == 0:
                n = struct.unpack("!H", data[p + 3:p + 5])[0]
                return data[p + 5:p + 5 + n].decode("ascii").lower() or None
            p += elen
    except (struct.error, IndexError, UnicodeDecodeError):
        return None
    return None


# ---- сборщик ----

class Sniffer:
    def __init__(self, settings: Settings, awg: AWG, conn: sqlite3.Connection, names: NameCache):
        self.s, self.awg, self.conn, self.names = settings, awg, conn, names
        self.net = ipaddress.ip_network(settings.vpn_subnet, strict=False)
        self.counts: dict[tuple[int, str, str, str], int] = defaultdict(int)
        self._lock = threading.Lock()
        self.packets = 0
        self.last_error: str | None = None

    def is_client(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in self.net
        except ValueError:
            return False

    def handle(self, ts: float, pkt: bytes) -> None:
        p = parse_ip(pkt)
        if not p:
            return
        src, dst, proto, sport, dport, payload = p
        self.packets += 1
        minute = int(ts) - int(ts) % 60
        if sport == 53 and self.is_client(dst):
            if proto == 6:
                payload = payload[2:]       # DNS over TCP: 2 байта длины
            r = parse_dns_response(payload)
            if not r:
                return
            qname, qtype, ips = r
            for ip in ips:
                self.names.put(dst, ip, qname, now=ts)
            if qtype == 1 and qname:        # A — по одному на обращение (AAAA/HTTPS не дублируем)
                with self._lock:
                    self.counts[(minute, dst, qname, "dns")] += 1
        elif dport == 443 and proto == 6 and self.is_client(src):
            sni = parse_sni(payload)
            if sni:
                self.names.put(src, dst, sni, strong=True, now=ts)
                with self._lock:
                    self.counts[(minute, src, sni, "sni")] += 1

    def flush(self) -> int:
        with self._lock:
            counts, self.counts = self.counts, defaultdict(int)
        ip2peer = {r[0]: r[1] for r in self.conn.execute(
            "SELECT ip, id FROM peers WHERE deleted_at IS NULL AND disabled = 0")}
        rows = [(m, ip2peer[ip], name, kind, n) for (m, ip, name, kind), n in counts.items() if ip in ip2peer]
        if rows:
            self.conn.executemany(
                "INSERT INTO dns (ts, peer_id, name, kind, count) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(ts, peer_id, name, kind) DO UPDATE SET count = count + excluded.count", rows)
        self.names.flush(self.conn)
        return len(rows)

    def capture(self, stop: threading.Event) -> None:
        argv = self.awg.ns_argv(["tcpdump", "-i", self.s.awg_iface, "-n", "-U", "-s", "2048", "-w", "-", BPF])
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            for ts, pkt in pcap_packets(proc.stdout):
                self.handle(ts, pkt)
                if stop.is_set():
                    break
        finally:
            proc.kill()
            proc.wait()

    def run(self, stop: threading.Event) -> None:
        flusher = threading.Thread(target=self._flush_loop, args=(stop,), name="sniffer-flush", daemon=True)
        flusher.start()
        while not stop.is_set():
            try:
                self.capture(stop)
                self.last_error = "tcpdump exited"
            except AwgUnavailable as e:
                self.last_error = str(e)
            except Exception as e:  # noqa: BLE001 — поток не должен умирать
                self.last_error = repr(e)
                log.exception("sniffer")
            stop.wait(5)

    def _flush_loop(self, stop: threading.Event) -> None:
        while not stop.wait(60):
            try:
                self.flush()
            except Exception:  # noqa: BLE001
                log.exception("sniffer flush")
        self.flush()

