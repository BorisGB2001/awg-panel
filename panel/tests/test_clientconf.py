import json
import re
from pathlib import Path

from app import clientconf
from app.awgconf import AwgConf

K = lambda c: (c * 43)[:43] + "="  # noqa: E731

# [Interface] сервера в том виде, в каком его пишет AmneziaVPN (ключи и параметры — тестовые)
SERVER = ("[Interface]\nPrivateKey = " + K("s") + "\nAddress = 10.8.1.0/24\nListenPort = 51820\n"
          "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 72\nS2 = 56\nS3 = 32\nS4 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
          "HeaderProtectionKey = " + K("h") + "\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\n"
          "RekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n"
          "RandomTrailers = on\nDisableCookies = on\n")

# эталон, экспортированный приложением AmneziaVPN (samples/amnezia_for_awg.conf), ключи заменены
REFERENCE = ("[Interface]\nAddress = 10.8.1.46/32\nDNS = 8.8.8.8, 8.8.4.4\nPrivateKey = " + K("c") + "\n"
             "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 72\nS2 = 56\nS3 = 32\nS4 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n"
             "HeaderProtectionKey = " + K("h") + "\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\n"
             "RekeyTimeout = 3-7\nRejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\n"
             "RandomTrailers = on\nDisableCookies = on\n\n[Peer]\nPublicKey = " + K("S") + "\nPresharedKey = " + K("p") + "\n"
             "AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.10:51820\nPersistentKeepalive = 25-35\n\n")

ARGS = dict(ip="10.8.1.46", private_key=K("c"), server_public_key=K("S"), psk=K("p"), host="203.0.113.10",
            dns=("8.8.8.8", "8.8.4.4"), keepalive="25-35")


def test_conf_matches_amnezia_export_byte_for_byte():
    assert clientconf.render_conf(AwgConf.parse(SERVER), **ARGS) == REFERENCE


def test_conf_matches_real_sample_when_available():
    """Сверка со настоящим экспортом (файл с ключами есть только у разработчика, в образ не попадает)."""
    sample = Path(__file__).parents[2] / "samples" / "amnezia_for_awg.conf"
    if not sample.exists():
        return
    # значения (ключи, адрес, параметры сервера) у образца свои — сверяем порядок и формат строк
    mask = lambda t: re.sub(r"(?m)^(\w+) = .*$", r"\1 = <v>", t)  # noqa: E731
    assert mask(clientconf.render_conf(AwgConf.parse(SERVER), **ARGS)) == mask(sample.read_text())


def test_empty_special_junk_not_written():
    conf = AwgConf.parse(SERVER.replace("H4 = 4\n", "H4 = 4\nI1 = <b 0x01>\nI2 =\n"))
    text = clientconf.render_conf(conf, **ARGS)
    assert "I1 = <b 0x01>\nHeaderProtectionKey" in text and "I2" not in text


def test_vpn_key_roundtrip_and_structure():
    conf = AwgConf.parse(SERVER)
    native = clientconf.render_conf(conf, **ARGS)
    obj = clientconf.vpn_json(conf, name="Тест", public_key=K("C"), native=native, **{k: v for k, v in ARGS.items()})
    key = clientconf.encode_vpn(obj)
    assert key.startswith("vpn://") and "=" not in key and "+" not in key and "/" not in key[6:]
    back = clientconf.decode_vpn(key)
    assert back == obj
    c = back["containers"][0]
    assert back["defaultContainer"] == c["container"] == "amnezia-awg2" and back["hostName"] == "203.0.113.10"
    last = json.loads(c["awg"]["last_config"])
    assert last["config"] == native and last["client_ip"] == "10.8.1.46" and last["port"] == 51820
    assert last["client_pub_key"] == last["clientId"] == K("C") and last["HeaderProtectionKey"] == K("h")
    assert c["awg"]["port"] == "51820" and c["awg"]["S4"] == "16" and "PrivateKey" not in c["awg"]


def test_qcompress_header():
    data = b"x" * 1000
    packed = clientconf.q_compress(data)
    assert packed[:4] == (1000).to_bytes(4, "big") and clientconf.q_uncompress(packed) == data


def test_qr_svg():
    svg = clientconf.qr_svg("vpn://abc")
    assert svg.startswith(b"<?xml") and b"<svg" in svg


def test_content_disposition_is_latin1():
    from app.main import content_disposition
    h = content_disposition("Тест панели Claude", "10.8.1.47")
    h.encode("latin-1")
    assert 'filename="awg-10.8.1.47.conf"' in h and "filename*=UTF-8''" in h
