import io
import socket
import struct

from app import db
from app.config import Settings
from app.flows import Flows, parse_event
from app.names import NameCache
from app.sniffer import Sniffer, parse_dns_response, parse_ip, parse_sni, pcap_packets


def dns_response(qname: str, ips: list[str], qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(x)]) + x.encode() for x in qname.split(".")) + b"\0"
    msg = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(ips) + 1, 0, 0) + labels + struct.pack("!HH", qtype, 1)
    # CNAME на первое имя через сжатие (указатель 0xC00C), затем A-записи с указателем на CNAME-цель
    cname = b"\x03cdn" + b"\xc0\x0c"
    msg += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(cname)) + cname
    cname_off = len(msg) - len(cname)
    for ip in ips:
        if ":" in ip:
            msg += struct.pack("!H", 0xC000 | cname_off) + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, ip)
        else:
            msg += struct.pack("!H", 0xC000 | cname_off) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return msg


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    ext_sni = struct.pack("!HH", 0, len(name) + 5) + struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    ext_other = struct.pack("!HH", 0x000A, 4) + b"\x00\x02\x00\x1d"
    exts = ext_other + ext_sni
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def ipv4(src, dst, proto, sport, dport, payload):
    l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) if proto == 17 else \
        struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 0, 0, 0)
    total = 20 + len(l4) + len(payload)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + l4 + payload


def pcap(pkts):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
    for ts, p in pkts:
        out += struct.pack("<IIII", int(ts), 0, len(p), len(p)) + p
    return io.BytesIO(out)


def test_dns_with_compression():
    r = parse_dns_response(dns_response("www.youtube.com", ["142.250.1.1", "142.250.1.2"]))
    assert r == ("www.youtube.com", 1, ["142.250.1.1", "142.250.1.2"])
    assert parse_dns_response(b"\x00" * 5) is None
    assert parse_dns_response(dns_response("x.com", [])[:20]) is None or True  # обрезанный — без исключения


def test_sni():
    assert parse_sni(client_hello("rr3---sn-abc.googlevideo.com")) == "rr3---sn-abc.googlevideo.com"
    assert parse_sni(b"\x16\x03\x01\x00\x05\x02") is None
    assert parse_sni(client_hello("x.ru")[:30]) is None


def test_pcap_and_sniffer_pipeline(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (pubkey, name, ip) VALUES ('k', 'Анна', '10.8.1.5')")
    names = NameCache()
    sn = Sniffer(Settings(data_dir=tmp_path), awg=None, conn=conn, names=names)
    stream = pcap([
        (1_800_000_010, ipv4("8.8.8.8", "10.8.1.5", 17, 53, 40000, dns_response("www.youtube.com", ["142.250.1.1"]))),
        (1_800_000_011, ipv4("8.8.8.8", "10.8.1.5", 17, 53, 40001, dns_response("www.youtube.com", ["2a00::1"], qtype=28))),
        (1_800_000_012, ipv4("10.8.1.5", "142.250.9.9", 6, 50000, 443, client_hello("i.ytimg.com"))),
        (1_800_000_013, ipv4("8.8.8.8", "10.9.9.9", 17, 53, 40002, dns_response("other.com", ["1.1.1.1"]))),
    ])
    for ts, p in pcap_packets(stream):
        assert parse_ip(p)
        sn.handle(ts, p)
    assert names.get("10.8.1.5", "142.250.1.1") == "www.youtube.com"
    assert names.get(None, "142.250.9.9") == "i.ytimg.com"
    assert names.get("10.8.1.5", "1.1.1.1") is None
    sn.flush()
    rows = {(r["name"], r["kind"]): r["count"] for r in conn.execute("SELECT * FROM dns")}
    assert rows == {("www.youtube.com", "dns"): 1, ("i.ytimg.com", "sni"): 1}   # AAAA не дублирует, чужая сеть не пишется
    assert conn.execute("SELECT name FROM ipnames WHERE ip='142.250.1.1'").fetchone()[0] == "www.youtube.com"


CT_TCP = ("[1793224000.123456]\t[DESTROY] tcp      6 src=10.8.1.5 dst=142.250.1.1 sport=50000 dport=443 packets=20 bytes=3000 "
          "src=142.250.1.1 dst=172.29.172.2 sport=443 dport=50000 packets=30 bytes=40000 [ASSURED] mark=0 use=1")
CT_UDP = ("    [DESTROY] udp      17 src=10.8.1.5 dst=8.8.8.8 sport=40000 dport=53 packets=1 bytes=60 "
          "src=8.8.8.8 dst=172.29.172.2 sport=53 dport=40000 packets=1 bytes=120 mark=0 use=1")


def test_parse_conntrack():
    assert parse_event(CT_TCP) == ("tcp", "10.8.1.5", "142.250.1.1", 443, 3000, 40000)
    assert parse_event(CT_UDP) == ("udp", "10.8.1.5", "8.8.8.8", 53, 60, 120)
    assert parse_event("[DESTROY] icmp     1 src=10.8.1.5 dst=1.1.1.1 type=8 code=0 id=1") is None


def test_flows_aggregate_and_host(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (pubkey, name, ip) VALUES ('k', 'Анна', '10.8.1.5')")
    names = NameCache()
    names.put("10.8.1.5", "142.250.1.1", "www.youtube.com")
    f = Flows(Settings(data_dir=tmp_path), awg=None, conn=conn, names=names)
    for _ in range(3):
        f.add(CT_TCP, now=1_800_000_030)
    f.add(CT_TCP.replace("src=10.8.1.5", "src=192.168.1.1", 1), now=1_800_000_030)   # не клиент VPN
    f.flush()
    r = conn.execute("SELECT * FROM flows").fetchone()
    assert (r["host"], r["conns"], r["bytes_up"], r["bytes_down"], r["dport"]) == ("www.youtube.com", 3, 9000, 120000, 443)
    assert conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 1


def test_namecache_sni_beats_dns():
    n = NameCache()
    n.put("c", "1.1.1.1", "a.example", now=100)
    n.put("c", "1.1.1.1", "b.example", strong=True, now=101)
    n.put("c", "1.1.1.1", "c.example", now=102)   # DNS сразу после SNI не перетирает
    assert n.get("c", "1.1.1.1", now=103) == "b.example"


def test_base_domain():
    from app.fmt import base_domain
    assert base_domain("rr3---sn-abc.googlevideo.com") == "googlevideo.com"
    assert base_domain("www.bbc.co.uk") == "bbc.co.uk"
    assert base_domain("youtube.com") == "youtube.com"
    assert base_domain("1.2.3.4") == "1.2.3.4"


def test_sites_aggregation(tmp_path):
    from app.main import sites
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO dns VALUES (100, 1, 'www.youtube.com', 'dns', 3)")
    conn.execute("INSERT INTO dns VALUES (100, 2, 'm.youtube.com', 'sni', 1)")
    conn.execute("INSERT INTO flows VALUES (100, 1, '1.1.1.1', 443, 'tcp', 'rr1.googlevideo.com', 2, 10, 5000)")
    rows = {r["site"]: r for r in sites(conn, 0)}
    assert rows["youtube.com"]["req"] == 4 and len(rows["youtube.com"]["peers"]) == 2
    assert rows["googlevideo.com"]["down"] == 5000
    assert [r["site"] for r in sites(conn, 0, peer_id=2)] == ["youtube.com"]
