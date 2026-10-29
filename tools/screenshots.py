"""Скриншоты разделов панели для README на вымышленных данных.

Поднимает панель локально (без AmneziaWG и сборщиков) на временной БД с демо-данными: клиенты, группы,
трафик за 30 дней, сайты, события, блокировки, архив. Адреса — из диапазонов для документации (RFC 5737),
имена клиентов вымышленные. Входит тестовым администратором и снимает страницы Chrome без окна (DevTools Protocol).

    .venv/bin/python tools/screenshots.py            # → docs/screenshots/{en,ru}/*.png

Нужны Google Chrome (или Edge) и пакеты панели из panel/requirements.txt (+ httpx).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
sys.path.insert(0, str(ROOT / "panel"))

CHROME = next((p for p in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                           "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
                           shutil.which("google-chrome") or "", shutil.which("chromium") or "") if p and Path(p).exists()), None)
WIDTH, MAX_HEIGHT = 1280, 1500
UA = "awg-panel-screenshots"   # сессия панели привязана к User-Agent — одинаковый у входа и у Chrome

# страница → (адрес, подпись для README)
PAGES = [
    ("overview", "/", "Overview"),
    ("client", "/peer/1", "Client card"),
    ("sites", "/hosts?days=7", "Sites"),
    ("events", "/events", "Events"),
    ("archive", "/archive", "Monthly archive"),
    ("alerts", "/alerts", "Alerts"),
    ("blocking", "/blocks", "Blocking"),
    ("groups", "/groups", "Groups"),
    ("server", "/server", "Server"),
    ("admins", "/admins", "Administrators"),
    ("portal", None, "Client portal"),
    ("overview-dark", "/", "Overview, dark theme"),
]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- демо-данные ----

CLIENTS = [  # имя, группа, онлайн, страна, город, провайдер
    ("Alice iPhone", "Family", True, "DE", "Berlin", "Example Mobile GmbH"),
    ("Alice MacBook", "Family", True, "DE", "Berlin", "Example Fiber AG"),
    ("Bob Pixel", "Family", False, "NL", "Amsterdam", "Demo Telecom B.V."),
    ("Kids tablet", "Family", True, "DE", "Berlin", "Example Fiber AG"),
    ("Office laptop 01", "Office", True, "FI", "Helsinki", "Sample Networks Oy"),
    ("Office laptop 02", "Office", True, "FI", "Helsinki", "Sample Networks Oy"),
    ("Office laptop 03", "Office", False, "FI", "Espoo", "Sample Networks Oy"),
    ("Reception PC", "Office", True, "FI", "Helsinki", "Sample Networks Oy"),
    ("Sales phone", "Office", True, "SE", "Stockholm", "Example Mobil AB"),
    ("Accounting", "Office", False, "FI", "Helsinki", "Sample Networks Oy"),
    ("Guest Wi-Fi 1", "Guests", True, "GB", "London", "Demo Broadband Ltd"),
    ("Guest Wi-Fi 2", "Guests", False, "GB", "London", "Demo Broadband Ltd"),
    ("Contractor", "Guests", True, "US", "New York", "Example Cable Inc."),
    ("Home router", None, True, "NL", "Rotterdam", "Demo Telecom B.V."),
    ("Old phone", None, False, "PL", "Warsaw", "Przyklad Sp. z o.o."),
]
SITES = [("youtube.com", ["www.youtube.com", "i.ytimg.com", "rr3---sn.googlevideo.com"], 9.0),
         ("google.com", ["www.google.com", "mail.google.com"], 3.0), ("netflix.com", ["www.netflix.com", "occ-0.nflxvideo.net"], 7.0),
         ("github.com", ["github.com", "api.github.com"], 1.5), ("wikipedia.org", ["en.wikipedia.org"], 0.6),
         ("telegram.org", ["web.telegram.org"], 1.2), ("apple.com", ["www.apple.com", "updates.cdn-apple.com"], 2.5),
         ("microsoft.com", ["login.microsoftonline.com", "outlook.office.com"], 2.0), ("spotify.com", ["open.spotify.com"], 1.8),
         ("zoom.us", ["us05web.zoom.us"], 2.2), ("cloudflare.com", ["www.cloudflare.com"], 0.4),
         ("reddit.com", ["www.reddit.com", "i.redd.it"], 1.1), ("tiktok.com", ["www.tiktok.com"], 2.8),
         ("instagram.com", ["www.instagram.com", "scontent.cdninstagram.com"], 2.1), ("amazon.com", ["www.amazon.com"], 0.9)]


def seed(conn, now: int, admin_pw_hash: str, fernet) -> None:
    from app import db, groups, monthly, fmt, quotas
    rnd = random.Random(7)
    gid = {name: groups.create(conn, name, note) for name, note in
           (("Office", "Helsinki office"), ("Family", "home devices"), ("Guests", "temporary access"))}
    created = now - 60 * 86400
    for i, (name, group, online, cc, city, org) in enumerate(CLIENTS, start=1):
        ip = f"10.8.1.{i + 1}"
        ep = f"{('203.0.113', '198.51.100', '192.0.2')[i % 3]}.{20 + i * 7}"
        lh = now - rnd.randint(5, 90) if online else now - rnd.randint(2, 40) * 3600
        conn.execute("INSERT INTO peers (id, pubkey, name, ip, source, created_at, first_handshake, last_handshake, "
                     "last_endpoint, group_id, disabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (i, base64.b64encode(rnd.randbytes(32)).decode(), name, ip, "panel" if i % 3 else "amnezia_app",
                      created + i * 3600, created + i * 7200, lh, ep, gid.get(group), int(name == "Old phone")))
        conn.execute("INSERT INTO endpoints (peer_id, ip, first_seen, last_seen, count, country, city, asn, org) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (i, ep, created, lh, rnd.randint(3, 40), cc, city, 64500 + i, org))
        weight = rnd.uniform(0.2, 1.6) * (3 if "laptop" in name or "router" in name else 1)
        rx_total = tx_total = 0
        for h in range(30 * 24):
            ts = now - now % 3600 - h * 3600
            hour = (ts // 3600 + 3) % 24
            day_curve = 0.15 + max(0.0, 1 - abs(hour - 20) / 8) + (0.6 if 9 <= hour <= 18 and group == "Office" else 0)
            tx = int(rnd.uniform(40, 260) * day_curve * weight * 1024 * 1024)
            rx = int(tx * rnd.uniform(0.05, 0.2))
            rx_total += rx
            tx_total += tx
            conn.execute("INSERT INTO traffic_hour VALUES (?, ?, ?, ?)", (ts, i, rx, tx))
            if h < 24:
                for m in range(0, 60, 10):
                    conn.execute("INSERT INTO traffic_min VALUES (?, ?, ?, ?)", (ts + m * 60, i, rx // 6, tx // 6))
        conn.execute("UPDATE peers SET rx_total = ?, tx_total = ? WHERE id = ?", (rx_total, tx_total, i))
        for s in range(6):
            start = now - (s + 1) * rnd.randint(6, 30) * 3600
            end = None if (s == 0 and online) else start + rnd.randint(600, 5 * 3600)
            conn.execute("INSERT INTO sessions (peer_id, start, end, endpoint_ip, rx, tx) VALUES (?, ?, ?, ?, ?, ?)",
                         (i, start, end, ep, rnd.randint(1, 80) << 20, rnd.randint(20, 900) << 20))
        for site, names, w in rnd.sample(SITES, 8):
            for d in range(7):
                ts = now - d * 86400 - rnd.randint(0, 80000)
                n = rnd.choice(names)
                conn.execute("INSERT OR IGNORE INTO dns VALUES (?, ?, ?, 'dns', ?)", (ts - ts % 60, i, n, rnd.randint(2, 60)))
                conn.execute("INSERT OR IGNORE INTO flows VALUES (?, ?, ?, 443, 'tcp', ?, ?, ?, ?)",
                             (ts - ts % 60, i, f"198.51.100.{rnd.randint(1, 250)}", n, rnd.randint(1, 30),
                              int(w * rnd.uniform(0.2, 2) * (1 << 20)), int(w * rnd.uniform(5, 60) * (1 << 20))))
        conn.execute("INSERT INTO events (ts, peer_id, kind, detail) VALUES (?, ?, 'connect', ?)",
                     (lh - 3600, i, json.dumps({"endpoint": f"{ep}:{rnd.randint(30000, 60000)}", "country": cc, "org": org})))
        conn.execute("INSERT INTO events (ts, peer_id, kind, detail) VALUES (?, ?, 'disconnect', ?)",
                     (lh - 7200, i, json.dumps({"duration": rnd.randint(600, 9000), "tx": rnd.randint(50, 900) << 20,
                                                "rx": rnd.randint(5, 90) << 20})))
    for m in range(24 * 60 * 30 // 10):
        ts = now - now % 600 - m * 600
        hour = (ts // 3600 + 3) % 24
        conn.execute("INSERT INTO online_min VALUES (?, ?)", (ts, max(1, int(11 * (0.35 + max(0, 1 - abs(hour - 19) / 9))))))
    month = monthly.current_month(now - 31 * 86400, fmt.TZ)
    for i, (name, *_rest) in enumerate(CLIENTS, start=1):
        conn.execute("INSERT INTO monthly_archive (month, peer_id, name, ip, rx, tx, sessions, online_sec, created_at) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (month, i, name, f"10.8.1.{i + 1}", rnd.randint(1, 9) << 30,
                                                           rnd.randint(5, 120) << 30, rnd.randint(20, 200),
                                                           rnd.randint(50, 600) * 3600, now))
    ev = [("endpoint_change", 2, {"from": "203.0.113.27", "to": "198.51.100.41", "country": "DE", "org": "Example Mobile GmbH"}),
          ("alert_new_country", 13, {"country": "US", "ip": "192.0.2.111", "known": ["GB"]}),
          ("alert_shared_config", 11, {"changes": 9, "providers": ["Demo Broadband Ltd", "Example Cable Inc."]}),
          ("alert_traffic_spike", 14, {"bytes": 14 << 30, "median": 300 << 20}),
          ("admin_add", 10, {"name": "Accounting", "ip": "10.8.1.11"}),
          ("block_add", 11, {"value": "tiktok.com", "preset": "TikTok"}),
          ("acct_created", None, {"username": "olga", "role": "group"})]
    for k, (kind, pid, detail) in enumerate(ev):
        conn.execute("INSERT INTO events (ts, peer_id, kind, detail, actor, actor_ip) VALUES (?, ?, ?, ?, ?, ?)",
                     (now - k * 2400 - 600, pid, kind, json.dumps(detail),
                      "admin" if kind.startswith(("admin", "block", "acct")) else None,
                      "192.0.2.10" if kind.startswith(("admin", "block", "acct")) else None))
    for value, pid, preset, hits in (("youtube.com", 11, "YouTube", 412), ("googlevideo.com", 11, "YouTube", 1288),
                                     ("tiktok.com", None, "TikTok", 97), ("tiktokcdn.com", None, "TikTok", 54),
                                     ("casino.example", None, None, 3), ("198.51.100.0/24", 13, None, 21)):
        conn.execute("INSERT INTO block_rules (kind, value, peer_id, preset, created_at, actor, hits, hits_ts) "
                     "VALUES (?, ?, ?, ?, ?, 'admin', ?, ?)", ("ip" if "/" in value else "domain", value, pid, preset,
                                                              now - 9 * 86400, hits, now - 1200))
    quotas.set_group_quota(conn, gid["Office"], "1200", "month", "alert")
    quotas.set_group_quota(conn, gid["Guests"], "20", "day", "disable")
    quotas.set_peer_quota(conn, 1, "150", "month", "alert")
    for user, role, group in (("ivan", "super", None), ("olga", "group", "Office")):
        conn.execute("INSERT INTO admins (username, pw_hash, role, created_at, last_login, last_ip, totp_enc) "
                     "VALUES (?, ?, ?, ?, ?, ?, ?)", (user, admin_pw_hash, role, now - 20 * 86400, now - 7200,
                                                     "192.0.2.10", fernet.encrypt(b"JBSWY3DPEHPK3PXP").decode()))
        if group:
            aid = conn.execute("SELECT id FROM admins WHERE username = ?", (user,)).fetchone()[0]
            groups.set_admin_groups(conn, aid, {gid[group]})
    db.set_state(conn, "observe_start", str(now - 40 * 86400))


class FakeAWG:
    """Для страницы «Сервер»: ответы как у работающего AmneziaWG, параметры — примерные."""
    CONF = ("[Interface]\nPrivateKey = demo\nAddress = 10.8.1.0/24\nListenPort = 51820\nJc = 4\nJmin = 10\nJmax = 50\n"
            "S1 = 72\nS2 = 56\nS3 = 32\nS4 = 16\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nHeaderProtectionKey = demo\n"
            "ContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRandomTrailers = on\nDisableCookies = on\n")

    def __init__(self, *a, **kw):
        pass

    def pid(self):
        return 4242

    def started_at(self):
        return time.time() - 9 * 86400 - 5 * 3600

    def run(self, args, mount=True, input=None, timeout=15):
        return "amneziawg-tools v1.0.20260101 - https://amnezia.org\n" if args[0] == "awg" else "823\n65536\n"

    def read_conf(self):
        from app.awgconf import AwgConf
        return AwgConf.parse(self.CONF)


# ---- Chrome DevTools ----

async def cdp_session(port: int):
    import httpx
    import websockets
    for _ in range(50):
        try:
            tabs = httpx.get(f"http://127.0.0.1:{port}/json/list", timeout=1).json()
            page = next(t for t in tabs if t.get("type") == "page")
            break
        except Exception:  # noqa: BLE001 — Chrome ещё запускается
            await asyncio.sleep(0.2)
    else:
        raise SystemExit("Chrome DevTools did not start")
    ws = await websockets.connect(page["webSocketDebuggerUrl"], max_size=64 << 20)
    counter = iter(range(1, 10 ** 9))

    async def call(method, **params):
        mid = next(counter)
        await ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(await ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})
    return ws, call


async def shoot(base: str, cookie: str, portal_url: str, port: int) -> None:
    ws, call = await cdp_session(port)
    await call("Page.enable")
    await call("Network.enable")
    await call("Network.setUserAgentOverride", userAgent=UA)
    await call("Emulation.setDeviceMetricsOverride", width=WIDTH, height=900, deviceScaleFactor=1, mobile=False)
    host = base.split("//")[1].split(":")[0]
    for lang in ("en", "ru"):
        (OUT / lang).mkdir(parents=True, exist_ok=True)
        for name, path, _title in PAGES:
            theme = "dark" if name.endswith("-dark") else "light"
            await call("Network.clearBrowserCookies")
            for k, v in (("lang", lang), ("theme", theme)) + ((("awgp", cookie),) if path else ()):
                await call("Network.setCookie", name=k, value=v, domain=host, path="/")
            await call("Page.navigate", url=base + (path or portal_url))
            await asyncio.sleep(1.2)
            h = (await call("Runtime.evaluate", expression="document.documentElement.scrollHeight", returnByValue=True))["result"]["value"]
            shot = await call("Page.captureScreenshot", format="png", captureBeyondViewport=True,
                              clip={"x": 0, "y": 0, "width": WIDTH, "height": min(h, MAX_HEIGHT), "scale": 1})
            (OUT / lang / f"{name}.png").write_bytes(base64.b64decode(shot["data"]))
            print(f"{lang}/{name}.png")
    await ws.close()


def main() -> None:
    if not CHROME:
        raise SystemExit("Google Chrome or Microsoft Edge is required")
    import pyotp
    tmp = Path(tempfile.mkdtemp(prefix="awg-shots-"))
    secret = pyotp.random_base32()
    from app import auth
    pw = "demo-password-123"
    os.environ.update(PANEL_DATA=str(tmp), ADMIN_USER="admin", ADMIN_PASSWORD_HASH=auth.hash_password(pw), TOTP_SECRET=secret,
                      SESSION_SECRET="s" * 48, COOKIE_SECURE="false", PANEL_COLLECTORS="0", TZ="Europe/Moscow",
                      PANEL_HOST="203.0.113.10", PUBLIC_HOST="203.0.113.10")
    import httpx
    import uvicorn
    from app import db, main as panel, portal
    from app.manage import load_fernet
    now = int(time.time())
    conn = db.open_db(panel.settings.db_path)
    seed(conn, now, auth.hash_password(pw), load_fernet(panel.settings))
    portal_token = portal.issue_link(conn, 1, "admin", None)
    conn.execute("UPDATE peers SET portal_config = 1 WHERE id = 1")
    conn.close()
    panel.AWG = FakeAWG
    real_info = panel.server_info

    def server_info(request):   # снимки делаются не на Linux: /proc и диск — примерные значения
        info = real_info(request)
        info["errors"] = [e for e in info["errors"] if not e.startswith("/proc")]
        info.update(load=["0.18", "0.26", "0.21"], cpus=2, mem=(896 << 20, 1976 << 20), disk=(5_900 << 20, 19_000 << 20),
                    geo="2026-10-01", backups=["20261029-1412-add", "20261028-0913-disable", "20261027-2210-rename"],
                    backups_total=37)
        return info
    panel.server_info = server_info
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(panel.app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            httpx.get(base + "/login", timeout=1)
            break
        except httpx.HTTPError:
            time.sleep(0.1)
    st = panel.app.state   # сборщики не запущены — для страницы «Сервер» показываем их как работающие
    st.poller = SimpleNamespace(status=SimpleNamespace(last_ok=time.time() - 12, last_error=None, online=10, peers=len(CLIENTS)))
    st.sniffer = SimpleNamespace(last_error=None, packets=184_220)
    st.flows = SimpleNamespace(last_error=None, events=96_410)
    st.blocker = SimpleNamespace(last_error=None, applied_rules=18)
    with httpx.Client(base_url=base, headers={"User-Agent": UA}, follow_redirects=True) as c:
        csrf = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").text).group(1)
        r = c.post("/login", data={"username": "admin", "password": pw, "code": pyotp.TOTP(secret).now(), "csrf": csrf})
        cookie = c.cookies.get("awgp")
        assert cookie and r.status_code == 200, "login failed"
    profile = tempfile.mkdtemp(prefix="awg-chrome-")
    dport = free_port()
    chrome = subprocess.Popen([CHROME, "--headless=new", f"--remote-debugging-port={dport}", f"--user-data-dir={profile}",
                               "--no-first-run", "--hide-scrollbars", "--force-color-profile=srgb", "about:blank"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        asyncio.run(shoot(base, cookie, f"/me/k/{portal_token}", dport))
    finally:
        chrome.terminate()
        server.should_exit = True
        shutil.rmtree(profile, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
