import pytest

from app import db
from app.blocker import (CHAIN, Blocker, BlockError, build_rules, dns_hex, parse_counters, parse_value, restore_text,
                         rule_matches, sni_exact_hex)
from app.config import Settings

NET = "10.8.1.0/24"


@pytest.mark.parametrize("raw, want", [
    ("youtube.com", ("domain", "youtube.com")),
    ("https://www.YouTube.com/watch?v=1", ("domain", "youtube.com")),
    ("*.googlevideo.com", ("domain", "googlevideo.com")),
    ("ютуб.рф", ("domain", "ютуб.рф".encode("idna").decode())),
    ("142.250.1.1", ("ip", "142.250.1.1")),
    ("142.250.0.0/15", ("ip", "142.250.0.0/15")),
    ("142.250.1.1:443", ("ip", "142.250.1.1")),
])
def test_parse_value(raw, want):
    assert parse_value(raw, NET) == want


@pytest.mark.parametrize("raw", ["", "0.0.0.0/0", "10.0.0.0/7", "10.8.1.5", "192.168.0.0/16", "2a00::1", "не домен", "localhost"])
def test_parse_value_rejects(raw):
    with pytest.raises(BlockError):
        parse_value(raw, NET)


def test_encodings():
    assert dns_hex("youtube.com") == "|07|youtube|03|com|00|"
    assert sni_exact_hex("youtube.com") == "|00 0b|youtube.com"


def test_build_rules_global_and_peer():
    rules = [{"id": 1, "kind": "domain", "value": "youtube.com", "peer_id": None},
             {"id": 2, "kind": "ip", "value": "1.2.3.0/24", "peer_id": 7},
             {"id": 3, "kind": "ip", "value": "5.5.5.5", "peer_id": 99}]   # клиента нет среди активных
    lines = build_rules(rules, {7: "10.8.1.7"})
    text = "\n".join(lines)
    assert '-p udp --dport 53 -m string --algo bm --icase --hex-string "|07|youtube|03|com|00|"' in text
    assert '--hex-string "|00 0b|youtube.com"' in text and '--string ".youtube.com"' in text
    assert f"-A {CHAIN} -s 10.8.1.7/32 -d 1.2.3.0/24" in text
    assert "5.5.5.5" not in text
    assert sum("quic" in x for x in lines) == 1 and "-s" not in [x for x in lines if "quic" in x][0]  # общее правило — для всех
    assert lines[-1] == f"-A {CHAIN} -j RETURN"


def test_bypass_only_for_affected_peer():
    lines = build_rules([{"id": 1, "kind": "domain", "value": "tiktok.com", "peer_id": 7}], {7: "10.8.1.7", 8: "10.8.1.8"})
    quic = [x for x in lines if "quic" in x]
    assert quic == [f'-A {CHAIN} -s 10.8.1.7/32 -p udp --dport 443 -m comment --comment "quic" -j REJECT']
    assert not any("10.8.1.8" in x for x in lines)


def test_no_rules_is_just_return():
    assert build_rules([], {}) == [f"-A {CHAIN} -j RETURN"]
    assert restore_text(["-A X"]).startswith(f"*filter\n:{CHAIN} - [0:0]\n")


def test_parse_counters():
    text = ("Chain AWGPANEL_BLOCK (1 references)\n    pkts      bytes target     prot opt in     out     source               destination\n"
            "      12     720 DROP       17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:53 STRING match  /* r1 */\n"
            "       3     180 DROP       6    --  *      *       0.0.0.0/0            0.0.0.0/0            tcp dpt:53 /* r1 */\n"
            "       5     300 REJECT     17   --  *      *       0.0.0.0/0            0.0.0.0/0            udp dpt:443 /* quic */\n"
            "       0       0 RETURN     0    --  *      *       0.0.0.0/0            0.0.0.0/0\n")
    assert parse_counters(text) == {"r1": 15, "quic": 5}


def test_rule_matches():
    assert rule_matches("domain", "youtube.com", "m.youtube.com")
    assert not rule_matches("domain", "youtube.com", "notyoutube.com")


class FakeAWG:
    def __init__(self):
        self.calls, self.jump = [], False
        self.counters = ""

    def pid(self):
        return 77

    def run(self, args, mount=True, input=None, timeout=15):
        from app.awgctl import AwgUnavailable
        self.calls.append((args, input))
        if args[:2] == ["iptables", "-C"]:
            if not self.jump:
                raise AwgUnavailable("нет")
        if args[:2] == ["iptables", "-I"]:
            self.jump = True
        if args[:2] == ["iptables", "-L"]:
            return self.counters
        return ""


def test_blocker_add_apply_and_hits(tmp_path):
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, pubkey, name, ip) VALUES (7, 'k', 'Анна', '10.8.1.7')")
    awg = FakeAWG()
    b = Blocker(Settings(data_dir=tmp_path), awg, conn)
    added, errors = b.add(["youtube.com", "youtube.com", "0.0.0.0/0", "1.2.3.4"], None, preset="YouTube", actor="admin")
    assert added == 2 and len(errors) == 1
    restore = [c for c in awg.calls if c[0][0] == "iptables-restore"][-1]
    assert "youtube.com" in restore[1] and "1.2.3.4" in restore[1] and awg.jump
    rid = conn.execute("SELECT id FROM block_rules WHERE value='youtube.com'").fetchone()[0]
    awg.counters = f"      4     240 DROP       17   --  *      *       0.0.0.0/0            0.0.0.0/0     /* r{rid} */\n"
    b.collect_hits()
    b.collect_hits()   # повторное чтение тех же счётчиков не удваивает
    assert conn.execute("SELECT hits FROM block_rules WHERE id=?", (rid,)).fetchone()[0] == 4
    b.set_enabled(rid, False)
    assert "youtube.com" not in [c for c in awg.calls if c[0][0] == "iptables-restore"][-1][1]
    b.delete(rid)
    assert conn.execute("SELECT COUNT(*) FROM block_rules").fetchone()[0] == 1
    kinds = [r[0] for r in conn.execute("SELECT kind FROM events ORDER BY id")]
    assert kinds == ["block_add", "block_add", "block_off", "block_delete"]
