"""Конфигурация клиента: .conf, QR и ключ vpn:// для приложения AmneziaVPN.

.conf повторяет эталон, экспортированный приложением (samples/amnezia_for_awg.conf), и шаблон AmneziaVPN
client/server_scripts/awg/template.conf: пустые параметры (I1…I5) не пишутся.
vpn:// — как ExportController::generateConnectionConfig: JSON → qCompress(…, 8) → base64url без «=».
"""
from __future__ import annotations

import base64
import io
import json
import struct
import zlib

import qrcode
import qrcode.image.svg

from .awgconf import AwgConf

# порядок параметров обфускации в клиентском [Interface], как в шаблоне AmneziaVPN
AWG_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
            "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
            "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"]
SERVER_ONLY = {"PrivateKey", "Address", "ListenPort", "PostUp", "PostDown", "SaveConfig", "MTU", "Table"}

CONTAINER = "amnezia-awg2"
MTU = "1280"   # значение AmneziaVPN для мобильных платформ — подходит всем


def awg_params(conf: AwgConf) -> dict[str, str]:
    """Параметры обфускации сервера в порядке шаблона; неизвестные новые — в конце, в порядке файла."""
    iface = conf.interface
    out = {k: iface[k] for k in AWG_KEYS if iface.get(k)}
    out |= {k: v for k, v in iface.items() if k not in out and k not in SERVER_ONLY and v}
    return out


def render_conf(conf: AwgConf, *, ip: str, private_key: str, server_public_key: str, psk: str, host: str,
                dns: tuple[str, str], keepalive: str) -> str:
    iface = conf.interface
    lines = ["[Interface]", f"Address = {ip}/32", f"DNS = {dns[0]}, {dns[1]}", f"PrivateKey = {private_key}"]
    lines += [f"{k} = {v}" for k, v in awg_params(conf).items()]
    lines += ["", "[Peer]", f"PublicKey = {server_public_key}", f"PresharedKey = {psk}", "AllowedIPs = 0.0.0.0/0, ::/0",
              f"Endpoint = {host}:{iface['ListenPort']}", f"PersistentKeepalive = {keepalive}", "", ""]
    return "\n".join(lines)


def vpn_json(conf: AwgConf, *, name: str, ip: str, private_key: str, public_key: str, server_public_key: str,
             psk: str, host: str, dns: tuple[str, str], keepalive: str, native: str) -> dict:
    iface = conf.interface
    params = awg_params(conf)
    net, cidr = (iface.get("Address", "10.8.1.0/24").split("/") + ["24"])[:2]
    client = {"config": native, "hostName": host, "port": int(iface["ListenPort"]), "client_ip": ip,
              "client_priv_key": private_key, "client_pub_key": public_key, "server_pub_key": server_public_key,
              "psk_key": psk, "clientId": public_key, "allowed_ips": ["0.0.0.0/0", "::/0"],
              "persistent_keep_alive": keepalive, "mtu": MTU, **params}
    server = {"port": iface["ListenPort"], "transport_proto": "udp", "protocol_version": "2",
              "subnet_address": net, "subnet_cidr": cidr, **params,
              "last_config": json.dumps(client, ensure_ascii=False, separators=(",", ":"))}
    return {"containers": [{"container": CONTAINER, "awg": server}], "defaultContainer": CONTAINER,
            "description": name, "dns1": dns[0], "dns2": dns[1], "format_version": 1, "hostName": host}


def q_compress(data: bytes, level: int = 8) -> bytes:
    """Qt qCompress: 4 байта big-endian длины исходных данных + zlib-поток."""
    return struct.pack(">I", len(data)) + zlib.compress(data, level)


def q_uncompress(data: bytes) -> bytes:
    n = struct.unpack(">I", data[:4])[0]
    out = zlib.decompress(data[4:])
    if len(out) != n:
        raise ValueError("qUncompress: length mismatch")
    return out


def encode_vpn(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, indent=4).encode()
    return "vpn://" + base64.urlsafe_b64encode(q_compress(raw)).decode().rstrip("=")


def decode_vpn(key: str) -> dict:
    b = key.strip().removeprefix("vpn://")
    return json.loads(q_uncompress(base64.urlsafe_b64decode(b + "=" * (-len(b) % 4))))


def qr_svg(text: str) -> bytes:
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, error_correction=qrcode.constants.ERROR_CORRECT_L,
                      box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue()


def qr_png(text: str) -> bytes:
    """QR картинкой — для Telegram и почты (SVG там не показывается)."""
    img = qrcode.make(text, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=3)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def file_name(name: str, ip: str) -> str:
    """Имя файла .conf: имя клиента латиницей/цифрами, иначе по IP."""
    keep = "".join(ch if ch.isascii() and (ch.isalnum() or ch in "-_") else "_" for ch in name).strip("_")[:40]
    return f"{keep or 'awg-' + ip}.conf"
