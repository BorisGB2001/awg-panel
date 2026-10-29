"""Веб-приложение панели: вход, страницы, API."""
from __future__ import annotations

import csv
import io
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from starlette.middleware.sessions import SessionMiddleware

from . import __version__, auth, charts, clientconf, db, fmt, i18n, maintenance, monthly, notify, portal, report
from .fmt import N_
from .i18n import t
from .awgctl import AWG, AwgUnavailable
from .alerts import Alerts
from .blocker import PRESETS, Blocker, BlockError, rule_matches
from .config import settings
from .geo import Geo
from .manage import Manager, ManageError
from .flows import Flows
from .names import NameCache
from .poller import Poller
from .sniffer import Sniffer

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=BASE / "templates")
fmt.register(templates.env)
limiter = auth.RateLimiter()
totp = auth.TOTPGuard(settings.totp_secret) if settings.totp_secret else None


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app.state.db = db.open_db(settings.db_path)
    app.state.stop = threading.Event()
    app.state.geo = Geo(settings.data_dir / "geo")
    app.state.poller = app.state.sniffer = app.state.flows = app.state.blocker = app.state.alerts = None
    app.state.notifier = None
    if os.environ.get("PANEL_COLLECTORS", "1") == "1":
        threading.Thread(target=app.state.geo.updater, args=(app.state.stop,), name="geo", daemon=True).start()
        app.state.poller = Poller(settings, AWG(settings), db.open_db(settings.db_path), app.state.geo)
        threading.Thread(target=app.state.poller.run, args=(app.state.stop,), name="poller", daemon=True).start()
        app.state.alerts = Alerts(settings, db.open_db(settings.db_path), AWG(settings))
        threading.Thread(target=app.state.alerts.run, args=(app.state.stop,), name="alerts", daemon=True).start()
        threading.Thread(target=maintenance.run, args=(db.open_db(settings.db_path), settings, app.state.stop),
                         name="maintenance", daemon=True).start()
        threading.Thread(target=monthly.run, args=(db.open_db(settings.db_path), fmt.TZ, app.state.stop),
                         name="monthly", daemon=True).start()
        app.state.notifier = notify.Notifier(settings, db.open_db(settings.db_path))
        threading.Thread(target=app.state.notifier.run, args=(app.state.stop,), name="notify", daemon=True).start()
        app.state.blocker = Blocker(settings, AWG(settings), db.open_db(settings.db_path))
        threading.Thread(target=app.state.blocker.run, args=(app.state.stop,), name="blocker", daemon=True).start()
        if settings.collect_hosts:
            names = NameCache()
            names.load(app.state.db)
            app.state.sniffer = Sniffer(settings, AWG(settings), db.open_db(settings.db_path), names)
            app.state.flows = Flows(settings, AWG(settings), db.open_db(settings.db_path), names)
            threading.Thread(target=app.state.sniffer.run, args=(app.state.stop,), name="sniffer", daemon=True).start()
            threading.Thread(target=app.state.flows.run, args=(app.state.stop,), name="flows", daemon=True).start()
    yield
    app.state.stop.set()
    app.state.db.close()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def current_user(request: Request) -> str | None:
    s = request.session
    user = s.get("user")
    if not user:
        return None
    if s.get("ua") != auth.ua_fingerprint(request.headers.get("user-agent", "")) or \
            time.time() - s.get("at", 0) > settings.session_hours * 3600:
        s.clear()
        return None
    return user


def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = request.session["csrf"] = auth.new_csrf()
    return tok


def check_csrf(request: Request, token: str) -> None:
    """Токен из формы + Origin/Referer того же хоста."""
    if not secrets.compare_digest(token or "", request.session.get("csrf", "")):
        raise HTTPException(403, "CSRF")
    origin = request.headers.get("origin") or ""
    if origin == "null":  # приватные режимы и no-referrer: источник скрыт — остаются токен и SameSite=Strict
        origin = ""
    origin = origin or request.headers.get("referer") or ""
    if origin and urlsplit(origin).netloc != request.headers.get("host", ""):
        raise HTTPException(403, "Origin")


def render(request: Request, name: str, **ctx) -> HTMLResponse:
    ctx.setdefault("user", current_user(request))
    ctx.setdefault("flash", request.session.pop("flash", None))
    ctx.setdefault("lang", i18n.get())
    ctx.setdefault("theme", theme_of(request))
    ctx.setdefault("path", request.url.path)
    return templates.TemplateResponse(request, name, {"csrf": csrf_token(request), **ctx})


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    i18n.set_lang(request.cookies.get("lang"))
    if path.startswith(("/static/", "/me", "/lang/", "/theme/")) or path in ("/login", "/healthz") or current_user(request):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return RedirectResponse("/login", status_code=303)


# добавлен последним — значит внешний: сессия уже разобрана, когда работает require_login
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret or secrets.token_urlsafe(48),
    session_cookie="awgp",
    max_age=settings.session_hours * 3600,
    same_site="strict",
    https_only=settings.cookie_secure,
)


THEMES = ("auto", "light", "dark")


def theme_of(request: Request) -> str:
    t = request.cookies.get("theme", "")
    return t if t in THEMES else "auto"


def back_to(request: Request) -> RedirectResponse:
    """Назад на страницу, с которой пришли (только этот же хост)."""
    ref = urlsplit(request.headers.get("referer") or "")
    back = (ref.path or "/") + (f"?{ref.query}" if ref.query else "")
    if ref.netloc and ref.netloc != request.headers.get("host", ""):
        back = "/"
    return RedirectResponse(back if local_path(back) else "/", status_code=303)


@app.get("/theme/{mode}")
def set_theme(request: Request, mode: str):
    """Тема оформления — в cookie на год: светлая, тёмная или как в системе."""
    resp = back_to(request)
    resp.set_cookie("theme", mode if mode in THEMES else "auto", max_age=365 * 86400, httponly=True,
                    secure=settings.cookie_secure, samesite="lax")
    return resp


@app.get("/lang/{code}")
def set_language(request: Request, code: str):
    """Язык интерфейса — в cookie на год; в кабинете клиента он же язык его уведомлений."""
    code = i18n.normalize(code)
    resp = back_to(request)
    resp.set_cookie("lang", code, max_age=365 * 86400, httponly=True, secure=settings.cookie_secure, samesite="lax")
    peer, _ = me_peer(request)
    if peer:
        portal.contact(request.app.state.db, peer["id"])
        request.app.state.db.execute("UPDATE contacts SET lang = ? WHERE peer_id = ?", (code, peer["id"]))
    return resp


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html", problems=settings.problems(), error=None)


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(""), password: str = Form(""), code: str = Form(""),
                csrf: str = Form("")):
    check_csrf(request, csrf)
    ip = client_ip(request)
    conn = request.app.state.db
    wait = limiter.blocked(ip)
    if wait:
        return render(request, "login.html", problems=[], error=t("Too many attempts. Try again in {n} min.", n=wait // 60 + 1))
    ok = (not settings.problems() and totp is not None
          and secrets.compare_digest(username, settings.admin_user)
          and auth.verify_password(password, settings.admin_password_hash)
          and totp.verify(code))
    if not ok:
        if limiter.fail(ip):
            db.event(conn, "alert_server", detail={"reason": "login_bruteforce"}, actor_ip=ip)
        db.event(conn, "admin_login_failed", detail={"username": username[:64]}, actor_ip=ip)
        return render(request, "login.html", problems=settings.problems(), error=t("Wrong username, password or code."))
    limiter.success(ip)
    request.session.clear()
    request.session.update(user=username, ua=auth.ua_fingerprint(request.headers.get("user-agent", "")),
                           at=int(time.time()), csrf=auth.new_csrf())
    db.event(conn, "admin_login", actor=username, actor_ip=ip)
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


CLIENTS_SQL = """
SELECT p.id, p.name, p.ip, p.disabled, p.created_at, p.last_handshake, p.last_endpoint, p.rx_total, p.tx_total,
       e.country, e.city, e.org,
       COALESCE(t.rx, 0) AS rx_today, COALESCE(t.tx, 0) AS tx_today,
       s.start AS session_start
FROM peers p
LEFT JOIN endpoints e ON e.peer_id = p.id AND e.ip = p.last_endpoint
LEFT JOIN (SELECT peer_id, SUM(rx) rx, SUM(tx) tx FROM traffic_hour WHERE ts >= ? GROUP BY peer_id) t ON t.peer_id = p.id
LEFT JOIN sessions s ON s.peer_id = p.id AND s.end IS NULL
WHERE p.deleted_at IS NULL
ORDER BY (s.start IS NULL), COALESCE(p.last_handshake, 0) DESC, p.name
"""


@app.get("/", response_class=HTMLResponse)
def index(request: Request, days: int = 1):
    conn = request.app.state.db
    now = int(time.time())
    days = days if days in charts.RANGES else 1
    bucket, label = charts.RANGES[days]
    rows = conn.execute(CLIENTS_SQL, (fmt.day_start(now),)).fetchall()
    clients = [dict(r) | {"status": fmt.status(r, now, settings.online_window)} for r in rows]
    online = sum(c["status"] == "online" for c in clients)
    totals = conn.execute("SELECT COALESCE(SUM(rx), 0), COALESCE(SUM(tx), 0) FROM traffic_hour WHERE ts >= ?",
                          (now - 86400 - now % 3600,)).fetchone()
    events = conn.execute(
        "SELECT ev.ts, ev.kind, ev.detail, p.name FROM events ev LEFT JOIN peers p ON p.id = ev.peer_id "
        "ORDER BY ev.id DESC LIMIT 20").fetchall()
    poller = request.app.state.poller
    since = now - days * 86400
    peak = conn.execute("SELECT COALESCE(MAX(online), 0) FROM online_min WHERE ts >= ?", (now - 86400,)).fetchone()[0]
    alerts = conn.execute("SELECT COUNT(*) FROM events WHERE kind LIKE 'alert_%' AND acked = 0").fetchone()[0]
    top_clients = conn.execute(
        "SELECT p.id, p.name, SUM(t.tx) d, SUM(t.rx) u FROM traffic_hour t JOIN peers p ON p.id = t.peer_id "
        "WHERE t.ts >= ? GROUP BY p.id ORDER BY SUM(t.tx + t.rx) DESC LIMIT 10", (now - 86400 - now % 3600,)).fetchall()
    month = monthly.current_month(now, fmt.TZ)
    m_start, _ = monthly.month_bounds(month, fmt.TZ)

    def top10(start: int) -> str:
        rows = conn.execute("SELECT p.id, p.name, SUM(t.tx) d FROM traffic_hour t JOIN peers p ON p.id = t.peer_id "
                            "WHERE t.ts >= ? GROUP BY p.id ORDER BY d DESC LIMIT 10", (start,)).fetchall()
        return charts.hbars([(r["name"], r["d"], f"/peer/{r['id']}") for r in rows if r["d"]])
    return render(request, "index.html", clients=clients, online=online, rx24=totals[0], tx24=totals[1],
                  top_today=top10(fmt.day_start(now)), top_month=top10(m_start), month=month,
                  events=events, poll=poller.status if poller else None, now=now, days=days, peak=peak, alerts=alerts,
                  top_clients=top_clients,
                  traffic_chart=charts.bars(charts.traffic_series(conn, since, now, bucket), fmt.TZ, label),
                  online_chart=charts.bars(charts.online_series(conn, since, now, bucket), fmt.TZ, label,
                                           bytes_axis=False, legend=(t("online"), "")),
                  top_sites=sites(conn, now - 86400, limit=15) if settings.collect_hosts else [])


def manager(request: Request) -> Manager:
    m = getattr(request.app.state, "manager", None)
    if m is None:
        m = request.app.state.manager = Manager(settings, AWG(settings), request.app.state.db)
    return m


def flash(request: Request, text: str, kind: str = "ok") -> None:
    request.session["flash"] = {"text": text, "kind": kind}


def manage_action(request: Request, csrf: str, fn, ok: str, back: str, done=None) -> RedirectResponse:
    """POST-действие управления: CSRF, автор, сообщение об успехе или причине отказа.
    back — куда вернуться при ошибке; done(result) — куда при успехе (по умолчанию тоже back)."""
    check_csrf(request, csrf)
    try:
        res = fn(actor=current_user(request), actor_ip=client_ip(request))
    except (ManageError, AwgUnavailable) as e:
        flash(request, str(e), "error")
        return RedirectResponse(back, status_code=303)
    flash(request, ok)
    return RedirectResponse(done(res) if done else back, status_code=303)


@app.post("/peers/add")
def peer_add(request: Request, name: str = Form(""), note: str = Form(""), csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).add(name, note, **kw),
                         t("Client “{name}” added.", name=name.strip()), "/", lambda pid: f"/peer/{pid}")


def sites(conn, since: int, peer_id: int | None = None, limit: int = 100) -> list[dict]:
    """Сайты по базовому домену: обращения (DNS + SNI), клиенты, соединения и байты (conntrack)."""
    where, args = ("AND peer_id = ?", (since, peer_id)) if peer_id else ("", (since,))
    out: dict[str, dict] = {}

    def row(name: str) -> dict:
        b = fmt.base_domain(name)
        return out.setdefault(b, {"site": b, "names": set(), "req": 0, "peers": set(), "conns": 0, "down": 0, "up": 0})

    for r in conn.execute(f"SELECT name, peer_id, SUM(count) n FROM dns WHERE ts >= ? {where} GROUP BY name, peer_id", args):
        x = row(r["name"])
        x["names"].add(r["name"]); x["req"] += r["n"]; x["peers"].add(r["peer_id"])
    for r in conn.execute(f"SELECT host, peer_id, SUM(conns) c, SUM(bytes_down) d, SUM(bytes_up) u FROM flows "
                          f"WHERE ts >= ? AND host IS NOT NULL {where} GROUP BY host, peer_id", args):
        x = row(r["host"])
        x["names"].add(r["host"]); x["conns"] += r["c"]; x["down"] += r["d"]; x["up"] += r["u"]; x["peers"].add(r["peer_id"])
    rows = sorted(out.values(), key=lambda x: (x["down"] + x["up"], x["req"]), reverse=True)
    return rows[:limit]


@app.get("/peer/{peer_id}", response_class=HTMLResponse)
def peer_page(request: Request, peer_id: int, days: int = 1):
    conn = request.app.state.db
    now = int(time.time())
    row = conn.execute(CLIENTS_SQL.replace("WHERE p.deleted_at IS NULL", "WHERE p.id = ?"),
                       (fmt.day_start(now), peer_id)).fetchone()
    if row is None:
        raise HTTPException(404)
    peer = dict(row) | {"status": fmt.status(row, now, settings.online_window)}
    extra = conn.execute("SELECT pubkey, note, source, deleted_at, private_key_enc IS NOT NULL AS has_key FROM peers WHERE id = ?",
                         (peer_id,)).fetchone()
    sessions = conn.execute("SELECT s.*, e.country, e.org FROM sessions s LEFT JOIN endpoints e "
                            "ON e.peer_id = s.peer_id AND e.ip = s.endpoint_ip WHERE s.peer_id = ? ORDER BY s.start DESC LIMIT 50",
                            (peer_id,)).fetchall()
    endpoints = conn.execute("SELECT * FROM endpoints WHERE peer_id = ? ORDER BY last_seen DESC", (peer_id,)).fetchall()
    events = conn.execute("SELECT ts, kind, detail, actor FROM events WHERE peer_id = ? ORDER BY id DESC LIMIT 50",
                          (peer_id,)).fetchall()
    days = days if days in (1, 7, 30) else 1
    dnslog = conn.execute("SELECT ts, name, kind, count FROM dns WHERE peer_id = ? ORDER BY ts DESC, count DESC LIMIT 300",
                          (peer_id,)).fetchall()
    rules = conn.execute("SELECT * FROM block_rules WHERE peer_id = ? OR peer_id IS NULL ORDER BY peer_id IS NULL, kind, value",
                         (peer_id,)).fetchall()
    active = [r for r in rules if r["enabled"]]
    site_rows = sites(conn, now - days * 86400, peer_id)
    for x in site_rows:
        x["blocked"] = any(rule_matches(r["kind"], r["value"], n) for r in active for n in x["names"] | {x["site"]})
    bucket, label = charts.RANGES[days]
    contact = portal.contact(conn, peer_id)
    return render(request, "peer.html", contact=contact, portal_on=extra_portal(conn, peer_id),
                  portal_config=conn.execute("SELECT portal_config FROM peers WHERE id = ?", (peer_id,)).fetchone()[0],
                  notifier=request.app.state.notifier, peer=peer, extra=extra, sessions=sessions, endpoints=endpoints,
                  events=events, now=now, days=days, sites=site_rows, dnslog=dnslog,
                  collect_hosts=settings.collect_hosts, rules=rules,
                  traffic_chart=charts.bars(charts.traffic_series(conn, now - days * 86400, now, bucket, peer_id), fmt.TZ, label),
                  heat=charts.heatmap(charts.activity_cells(conn, peer_id, now - 30 * 86400, fmt.TZ)))


def client_config(request: Request, peer_id: int) -> dict:
    """.conf и vpn:// клиента; только для созданных в панели (приватный ключ есть только у нас)."""
    m = manager(request)
    row = request.app.state.db.execute("SELECT name, ip, pubkey, deleted_at, disabled FROM peers WHERE id = ?",
                                       (peer_id,)).fetchone()
    priv = m.private_key(peer_id) if row and not row["deleted_at"] else None
    if not priv:
        raise HTTPException(404, t("This client's private key exists only on its device."))
    awg = m.awg
    conf = awg.read_conf()
    args = dict(ip=row["ip"], private_key=priv, server_public_key=awg.server_public_key(), psk=awg.psk(),
                host=settings.public_host or settings.panel_host, dns=settings.client_dns,
                keepalive=settings.client_keepalive)
    native = clientconf.render_conf(conf, **args)
    vpn = clientconf.encode_vpn(clientconf.vpn_json(conf, name=row["name"], public_key=row["pubkey"], native=native, **args))
    return {"name": row["name"], "ip": row["ip"], "conf": native, "vpn": vpn, "disabled": row["disabled"]}


def content_disposition(name: str, ip: str) -> str:
    """Заголовки HTTP — только latin-1: ASCII-имя awg-<ip>.conf плюс имя клиента в filename* (RFC 5987)."""
    keep = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name).strip("_")[:40] or "client"
    return f"attachment; filename=\"awg-{ip}.conf\"; filename*=UTF-8''{quote(keep)}.conf"


@app.get("/peer/{peer_id}/config", response_class=HTMLResponse)
def peer_config(request: Request, peer_id: int):
    cfg = client_config(request, peer_id)
    db.event(request.app.state.db, "admin_config_view", peer_id, None, current_user(request), client_ip(request))
    return render(request, "config.html", peer_id=peer_id, cfg=cfg)


@app.get("/peer/{peer_id}/config.conf")
def peer_config_file(request: Request, peer_id: int):
    cfg = client_config(request, peer_id)
    return Response(cfg["conf"], media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": content_disposition(cfg["name"], cfg["ip"]), "Cache-Control": "no-store"})


@app.get("/peer/{peer_id}/qr/{kind}.svg")
def peer_qr(request: Request, peer_id: int, kind: str):
    if kind not in ("conf", "vpn"):
        raise HTTPException(404)
    cfg = client_config(request, peer_id)
    try:
        svg = clientconf.qr_svg(cfg[kind])
    except Exception:  # qrcode.exceptions.DataOverflowError — не помещается в один QR
        raise HTTPException(422, t("Too long for a single QR code"))
    return Response(svg, media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.post("/peer/{peer_id}/rename")
def peer_rename(request: Request, peer_id: int, name: str = Form(""), csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).rename(peer_id, name, **kw), t("Name changed."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/disable")
def peer_disable(request: Request, peer_id: int, csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).disable(peer_id, **kw), t("Client disabled, its IP stays reserved."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/enable")
def peer_enable(request: Request, peer_id: int, csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).enable(peer_id, **kw), t("Client enabled again."), f"/peer/{peer_id}")


@app.post("/peer/{peer_id}/delete")
def peer_delete(request: Request, peer_id: int, confirm: str = Form(""), csrf: str = Form("")):
    return manage_action(request, csrf, lambda **kw: manager(request).delete(peer_id, confirm, **kw),
                         t("Client deleted. History is kept."), f"/peer/{peer_id}", lambda _: "/")


def blocker(request: Request) -> Blocker:
    b = request.app.state.blocker
    if b is None:
        b = request.app.state.blocker = Blocker(settings, AWG(settings), request.app.state.db)
    return b


def local_path(path: str) -> bool:
    """Путь на этом же сайте: «/\\evil.com» и «//evil.com» браузер понимает как другой хост."""
    return path.startswith("/") and not path.startswith(("//", "/\\")) and not any(c in path for c in "\\\r\n")


def back_url(back: str) -> str:
    return back if local_path(back) else "/blocks"


@app.get("/blocks", response_class=HTMLResponse)
def blocks_page(request: Request):
    conn = request.app.state.db
    rules = conn.execute("SELECT b.*, p.name AS peer_name FROM block_rules b LEFT JOIN peers p ON p.id = b.peer_id "
                         "ORDER BY b.peer_id IS NOT NULL, p.name, b.preset, b.kind, b.value").fetchall()
    peers = conn.execute("SELECT id, name, ip FROM peers WHERE deleted_at IS NULL ORDER BY name").fetchall()
    bypass = {k: int(db.get_state(conn, f"block_hits_{k}", "0")) for k in ("quic", "dot", "doh")}
    b = request.app.state.blocker
    return render(request, "blocks.html", rules=rules, peers=peers, presets=PRESETS, bypass=bypass,
                  blocker_error=b.last_error if b else None)


def block_action(request: Request, csrf: str, back: str, fn, ok: str) -> RedirectResponse:
    check_csrf(request, csrf)
    try:
        msg = fn(actor=current_user(request), actor_ip=client_ip(request)) or ok
        flash(request, msg)
    except (BlockError, AwgUnavailable) as e:
        flash(request, t("Failed: {error}", error=e), "error")
    return RedirectResponse(back_url(back), status_code=303)


def _scope(peer_id: str) -> int | None:
    return int(peer_id) if peer_id.isdigit() else None


@app.post("/blocks/add")
def blocks_add(request: Request, values: str = Form(""), peer_id: str = Form(""), note: str = Form(""),
               back: str = Form("/blocks"), csrf: str = Form("")):
    def go(**kw):
        added, errors = blocker(request).add(values.replace(",", "\n").splitlines(), _scope(peer_id), note, **kw)
        return t("Rules added: {n}.", n=added) + (" " + t("Skipped: {items}", items="; ".join(errors)) if errors else "")
    return block_action(request, csrf, back, go, "")


@app.post("/blocks/preset")
def blocks_preset(request: Request, preset: str = Form(""), peer_id: str = Form(""), back: str = Form("/blocks"),
                  csrf: str = Form("")):
    check_csrf(request, csrf)
    if preset not in PRESETS:
        raise HTTPException(404)

    def go(**kw):
        added, _ = blocker(request).add(PRESETS[preset], _scope(peer_id), preset=preset, **kw)
        return t("Preset “{name}”: rules added {n}.", name=preset, n=added)
    return block_action(request, csrf, back, go, "")


@app.post("/blocks/{rule_id}/toggle")
def blocks_toggle(request: Request, rule_id: int, enabled: str = Form("0"), back: str = Form("/blocks"), csrf: str = Form("")):
    return block_action(request, csrf, back, lambda **kw: blocker(request).set_enabled(rule_id, enabled == "1", **kw),
                        t("Rule enabled.") if enabled == "1" else t("Rule disabled."))


@app.post("/blocks/{rule_id}/delete")
def blocks_delete(request: Request, rule_id: int, back: str = Form("/blocks"), csrf: str = Form("")):
    return block_action(request, csrf, back, lambda **kw: blocker(request).delete(rule_id, **kw), t("Rule deleted."))


@app.get("/hosts", response_class=HTMLResponse)
def hosts_page(request: Request, days: int = 1, q: str = ""):
    conn = request.app.state.db
    now = int(time.time())
    days = days if days in charts.RANGES else 1
    rows = sites(conn, now - days * 86400, limit=500)
    if q.strip():
        rows = [r for r in rows if q.strip().lower() in r["site"] or any(q.strip().lower() in n for n in r["names"])]
    return render(request, "hosts.html", rows=rows[:300], days=days, q=q, collect_hosts=settings.collect_hosts)


@app.get("/hosts/{site}", response_class=HTMLResponse)
def host_page(request: Request, site: str, days: int = 7):
    conn = request.app.state.db
    now = int(time.time())
    days = days if days in charts.RANGES else 7
    since = now - days * 86400
    pat = f"%.{site}"
    who = conn.execute(
        "SELECT p.id, p.name, p.ip, SUM(d.count) req, MIN(d.ts) first, MAX(d.ts) last FROM dns d JOIN peers p ON p.id = d.peer_id "
        "WHERE d.ts >= ? AND (d.name = ? OR d.name LIKE ?) GROUP BY p.id ORDER BY req DESC", (since, site, pat)).fetchall()
    traffic = {r["peer_id"]: r for r in conn.execute(
        "SELECT peer_id, SUM(conns) c, SUM(bytes_down) d, SUM(bytes_up) u FROM flows WHERE ts >= ? AND (host = ? OR host LIKE ?) "
        "GROUP BY peer_id", (since, site, pat))}
    names = conn.execute("SELECT name, SUM(count) n FROM dns WHERE ts >= ? AND (name = ? OR name LIKE ?) GROUP BY name "
                         "ORDER BY n DESC LIMIT 50", (since, site, pat)).fetchall()
    ips = conn.execute("SELECT dst_ip, dport, proto, SUM(conns) c FROM flows WHERE ts >= ? AND (host = ? OR host LIKE ?) "
                       "GROUP BY dst_ip, dport, proto ORDER BY c DESC LIMIT 30", (since, site, pat)).fetchall()
    return render(request, "host.html", site=site, days=days, who=who, traffic=traffic, names=names, ips=ips)


EVENTS_SQL = """SELECT e.id, e.ts, e.kind, e.detail, e.actor, e.actor_ip, e.acked, e.peer_id, p.name
FROM events e LEFT JOIN peers p ON p.id = e.peer_id WHERE e.ts >= ? {filters} ORDER BY e.id DESC"""


def events_query(conn, days: int, kind: str, peer_id: str, limit: int | None):
    filters, args = "", [int(time.time()) - days * 86400]
    if kind:
        filters += " AND e.kind LIKE ?"
        args.append(kind.rstrip("*") + "%" if kind.endswith("*") else kind)
    if peer_id.isdigit():
        filters += " AND e.peer_id = ?"
        args.append(int(peer_id))
    sql = EVENTS_SQL.format(filters=filters) + (f" LIMIT {int(limit)}" if limit else "")
    return conn.execute(sql, args).fetchall()


EVENT_GROUPS = {"": N_("all"), "connect": N_("connections"), "disconnect": N_("disconnections"), "endpoint_change": N_("IP changes"),
                "alert_*": N_("alerts"), "admin_*": N_("administrator actions"), "block_*": N_("blocking"),
                "peer_*": N_("client changes outside the panel")}


@app.get("/events", response_class=HTMLResponse)
def events_page(request: Request, days: int = 7, kind: str = "", peer_id: str = ""):
    conn = request.app.state.db
    days = max(1, min(days, 365))
    rows = events_query(conn, days, kind, peer_id, 1000)
    peers = conn.execute("SELECT id, name FROM peers ORDER BY name").fetchall()
    return render(request, "events.html", rows=rows, days=days, kind=kind, peer_id=peer_id, peers=peers, groups=EVENT_GROUPS)


@app.get("/events.csv")
def events_csv(request: Request, days: int = 7, kind: str = "", peer_id: str = ""):
    rows = events_query(request.app.state.db, max(1, min(days, 365)), kind, peer_id, None)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([t("time"), t("client"), t("event"), t("description"), t("who"), t("admin IP"), t("details JSON")])
    for r in rows:
        w.writerow(map(csv_cell, [fmt.dt(r["ts"], "%Y-%m-%d %H:%M:%S"), r["name"] or "", fmt.event_name(r["kind"]),
                                  fmt.event_text(r["kind"], r["detail"]), r["actor"] or "", r["actor_ip"] or "",
                                  r["detail"] or ""]))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="awg-events-{days}d.csv"', "Cache-Control": "no-store"})


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, days: int = 30):
    rows = request.app.state.db.execute(
        "SELECT e.*, p.name FROM events e LEFT JOIN peers p ON p.id = e.peer_id WHERE e.kind LIKE 'alert_%' AND e.ts >= ? "
        "ORDER BY e.acked, e.id DESC LIMIT 500", (int(time.time()) - max(1, min(days, 365)) * 86400,)).fetchall()
    return render(request, "alerts.html", rows=rows, days=days)


@app.post("/alerts/ack")
def alerts_ack(request: Request, alert_id: str = Form(""), csrf: str = Form("")):
    check_csrf(request, csrf)
    conn = request.app.state.db
    if alert_id.isdigit():
        conn.execute("UPDATE events SET acked = 1 WHERE id = ? AND kind LIKE 'alert_%'", (int(alert_id),))
    else:
        conn.execute("UPDATE events SET acked = 1 WHERE kind LIKE 'alert_%' AND acked = 0")
    return RedirectResponse("/alerts", status_code=303)


def server_info(request: Request) -> dict:
    """Состояние сервера и панели для страницы «Сервер». Ключи и PSK не показываются."""
    st = request.app.state
    info: dict = {"errors": []}
    try:
        awg = AWG(settings)
        info["pid"] = awg.pid()
        info["started"] = int(awg.started_at())
        info["version"] = awg.run(["awg", "--version"]).strip()
        iface = awg.read_conf().interface
        info["params"] = {k: ("•••" if "Key" in k else v) for k, v in iface.items() if k not in ("PrivateKey",)}
        cnt, mx = awg.run(["sysctl", "-n", "net.netfilter.nf_conntrack_count", "net.netfilter.nf_conntrack_max"], mount=False).split()[:2]
        info["conntrack"] = (int(cnt), int(mx))
    except Exception as e:  # noqa: BLE001 — страница должна открываться и при недоступном AmneziaWG
        info["errors"].append(f"AmneziaWG: {e}")
    try:
        la = open("/proc/loadavg").read().split()[:3]
        mem = dict(line.split(":", 1) for line in open("/proc/meminfo").read().splitlines() if ":" in line)
        kb = lambda k: int(mem[k].split()[0]) * 1024  # noqa: E731
        info["load"] = la
        info["mem"] = (kb("MemTotal") - kb("MemAvailable"), kb("MemTotal"))
        info["cpus"] = os.cpu_count()
    except (OSError, KeyError, ValueError) as e:
        info["errors"].append(f"/proc: {e}")
    vfs = os.statvfs(settings.data_dir)
    info["disk"] = ((vfs.f_blocks - vfs.f_bavail) * vfs.f_frsize, vfs.f_blocks * vfs.f_frsize)
    info["db_size"] = sum(p.stat().st_size for p in settings.data_dir.glob("panel.db*") if p.exists())
    info["geo"] = st.geo.built() if st.geo else None
    info["collectors"] = {
        N_("AmneziaWG polling"): st.poller and (st.poller.status.last_ok, st.poller.status.last_error),
        "DNS/SNI": st.sniffer and (None, st.sniffer.last_error, t("packets {n}", n=st.sniffer.packets)),
        N_("Connections (conntrack)"): st.flows and (None, st.flows.last_error, t("events {n}", n=st.flows.events)),
        N_("Blocking"): st.blocker and (None, st.blocker.last_error, t("kernel rules {n}", n=st.blocker.applied_rules)),
    }
    root = settings.data_dir / "backups"
    info["backups"] = sorted((p.name for p in root.iterdir() if p.is_dir()), reverse=True)[:15] if root.exists() else []
    info["backups_total"] = len(list(root.iterdir())) if root.exists() else 0
    return info


@app.get("/server", response_class=HTMLResponse)
def server_page(request: Request):
    return render(request, "server.html", info=server_info(request), now=int(time.time()))


@app.get("/archive", response_class=HTMLResponse)
def archive_page(request: Request, month: str = ""):
    conn = request.app.state.db
    months = [r[0] for r in conn.execute("SELECT DISTINCT month FROM monthly_archive ORDER BY month DESC")]
    month = month if month in months else (months[0] if months else "")
    rows = conn.execute("SELECT * FROM monthly_archive WHERE month = ? ORDER BY tx DESC", (month,)).fetchall()
    chart = charts.hbars([(r["name"] or r["ip"], r["tx"], f"/peer/{r['peer_id']}") for r in rows[:10] if r["tx"]])
    return render(request, "archive.html", months=months, month=month, rows=rows, chart=chart,
                  total=(sum(r["tx"] for r in rows), sum(r["rx"] for r in rows)))


def csv_cell(v):
    """Ячейка CSV без формул: имя клиента вида «=HYPERLINK(…)» Excel иначе выполнит при открытии."""
    return "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


@app.get("/archive/{month}.csv")
def archive_csv(request: Request, month: str):
    if not re.fullmatch(r"\d{4}-\d{2}", month):
        raise HTTPException(404)
    rows = request.app.state.db.execute("SELECT * FROM monthly_archive WHERE month = ? ORDER BY tx DESC", (month,)).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow([t("month"), t("client"), "IP", t("downloaded, bytes"), t("uploaded, bytes"), t("sessions"), t("online, h")])
    for r in rows:
        w.writerow(map(csv_cell, [r["month"], r["name"], r["ip"], r["tx"], r["rx"], r["sessions"],
                                  round(r["online_sec"] / 3600, 1)]))
    return Response("\ufeff" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="awg-{month}.csv"'})


def extra_portal(conn, peer_id: int) -> bool:
    return bool(conn.execute("SELECT portal_hash FROM peers WHERE id = ?", (peer_id,)).fetchone()[0])


def notifier(request: Request) -> notify.Notifier:
    n = request.app.state.notifier
    if n is None:
        n = request.app.state.notifier = notify.Notifier(settings, request.app.state.db)
    return n


@app.post("/peer/{peer_id}/portal")
def peer_portal(request: Request, peer_id: int, action: str = Form(""), csrf: str = Form("")):
    """Личный кабинет клиента: выдать/отозвать ссылку, разрешить скачивание конфига, тестовое уведомление."""
    check_csrf(request, csrf)
    conn, who, ip = request.app.state.db, current_user(request), client_ip(request)
    if action == "issue":
        token = portal.issue_link(conn, peer_id, who, ip)
        flash(request, t("Personal link (shown once, the old one no longer works): {url}", url=f"{settings.base_url}/me/k/{token}"))
    elif action == "revoke":
        portal.revoke_link(conn, peer_id, who, ip)
        flash(request, t("Link revoked: the client portal is closed."))
    elif action in ("config_on", "config_off"):
        conn.execute("UPDATE peers SET portal_config = ? WHERE id = ?", (int(action == "config_on"), peer_id))
        flash(request, t("Config download in the portal is allowed.") if action == "config_on" else t("Config download in the portal is forbidden."))
    elif action == "test":
        n = notifier(request).daily(peer_id)
        flash(request, t("Report sent: channels {n}.", n=n) if n else t("Not sent: the client has no connected channels or they are not configured."),
              "ok" if n else "error")
    return RedirectResponse(f"/peer/{peer_id}#portal", status_code=303)


# ---- личный кабинет клиента ----

ME_COOKIE = "awgme"
me_signer = URLSafeTimedSerializer((settings.session_secret or secrets.token_urlsafe(48)) + ":me", salt="portal")
me_limiter = auth.RateLimiter(per_ip=10, window=900, block=900, global_limit=200, global_window=3600)


def me_peer(request: Request):
    """Клиент из cookie кабинета; ссылка отозвана или перевыпущена — сессия недействительна."""
    try:
        data = me_signer.loads(request.cookies.get(ME_COOKIE, ""), max_age=30 * 86400)
    except BadSignature:
        return None, None
    row = request.app.state.db.execute("SELECT * FROM peers WHERE id = ? AND deleted_at IS NULL", (data.get("p"),)).fetchone()
    if not row or not row["portal_hash"] or not row["portal_hash"].startswith(data.get("h", "-")):
        return None, None
    return row, data


def me_redirect(path: str = "/me") -> RedirectResponse:
    return RedirectResponse(path, status_code=303)


def me_check(request: Request, data: dict, csrf: str) -> None:
    if not secrets.compare_digest(csrf or "", data.get("c", "")):
        raise HTTPException(403, "CSRF")


@app.get("/me/k/{token}")
def me_login(request: Request, token: str):
    ip = client_ip(request)
    if me_limiter.blocked(ip):
        raise HTTPException(429, t("Too many attempts, try again later."))
    row = portal.peer_by_token(request.app.state.db, token)
    if not row:
        me_limiter.fail(ip)
        raise HTTPException(404, t("The link is invalid — ask the administrator for a new one."))
    db.event(request.app.state.db, "client_view", row["id"], {"via": "link"}, actor_ip=ip)
    resp = me_redirect()
    resp.set_cookie(ME_COOKIE, me_signer.dumps({"p": row["id"], "h": row["portal_hash"][:16], "c": secrets.token_urlsafe(24)}),
                    max_age=30 * 86400, httponly=True, secure=settings.cookie_secure, samesite="lax", path="/me")  # lax: вход по ссылке из Telegram/почты — переход с чужого сайта
    return resp


@app.get("/me", response_class=HTMLResponse)
def me_page(request: Request, days: int = 1):
    peer, data = me_peer(request)
    if not peer:
        return HTMLResponse(f"<h1>{t('Sign in with a personal link')}</h1><p>{t('Open the link given to you by the VPN administrator.')}</p>", status_code=401)
    conn, now = request.app.state.db, int(time.time())
    days = days if days in charts.RANGES else 1
    bucket, label = charts.RANGES[days]
    row = conn.execute(CLIENTS_SQL.replace("WHERE p.deleted_at IS NULL", "WHERE p.id = ?"), (fmt.day_start(now), peer["id"])).fetchone()
    me = dict(row) | {"status": fmt.status(row, now, settings.online_window)}
    rules = conn.execute("SELECT * FROM block_rules WHERE enabled = 1 AND (peer_id = ? OR peer_id IS NULL) ORDER BY kind, value",
                         (peer["id"],)).fetchall()
    site_rows = sites(conn, now - days * 86400, peer["id"], limit=50)
    for x in site_rows:
        x["blocked"] = any(rule_matches(r["kind"], r["value"], n) for r in rules for n in x["names"] | {x["site"]})
    sessions = conn.execute("SELECT s.*, e.country, e.org FROM sessions s LEFT JOIN endpoints e ON e.peer_id = s.peer_id "
                            "AND e.ip = s.endpoint_ip WHERE s.peer_id = ? ORDER BY s.start DESC LIMIT 30", (peer["id"],)).fetchall()
    endpoints = conn.execute("SELECT * FROM endpoints WHERE peer_id = ? ORDER BY last_seen DESC LIMIT 20", (peer["id"],)).fetchall()
    n = request.app.state.notifier
    tg_name = None
    if n and n.tg:
        try:
            tg_name = n.tg.me()
        except Exception:  # noqa: BLE001 — кабинет открывается и без Telegram
            tg_name = None
    return templates.TemplateResponse(request, "me.html", {
        "me": me, "now": now, "days": days, "sites": site_rows, "sessions": sessions, "endpoints": endpoints, "rules": rules,
        "contact": portal.contact(conn, peer["id"]), "csrf": data["c"], "tg_bot": tg_name, "email_on": bool(n and n.email_on),
        "can_config": bool(peer["portal_config"] and peer["private_key_enc"]),
        "traffic_chart": charts.bars(charts.traffic_series(conn, now - days * 86400, now, bucket, peer["id"]), fmt.TZ, label),
        "flash": None, "user": None, "lang": i18n.get(), "theme": theme_of(request), "path": request.url.path})


@app.post("/me/prefs")
def me_prefs(request: Request, daily: str = Form(""), hour: int = Form(21), events: str = Form(""), csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    portal.set_prefs(request.app.state.db, peer["id"], daily == "1", hour, events == "1")
    return me_redirect("/me#notify")


@app.post("/me/telegram")
def me_telegram(request: Request, csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    n = notifier(request)
    if not n.tg:
        raise HTTPException(404)
    code = portal.telegram_code(request.app.state.db, peer["id"])
    return RedirectResponse(f"https://t.me/{n.tg.me()}?start={code}", status_code=303)


@app.post("/me/email")
def me_email(request: Request, email: str = Form(""), csrf: str = Form("")):
    peer, data = me_peer(request)
    if not peer:
        return me_redirect()
    me_check(request, data, csrf)
    n = notifier(request)
    try:
        code = portal.set_email(request.app.state.db, peer["id"], email)
    except ValueError:
        return me_redirect("/me?bad_email=1#notify")
    if code and n.email_on:
        try:
            notify.send_email(settings, email.strip(), t("VPN: confirm your address"),
                              t("To receive VPN notifications at this address, open the link:") + f"\n{settings.base_url}/me/verify/{code}")
        except Exception as e:  # noqa: BLE001
            db.event(request.app.state.db, "alert_server", None, {"reason": "smtp", "error": str(e)[:200]})
    return me_redirect("/me#notify")


@app.get("/me/verify/{code}")
def me_verify(request: Request, code: str):
    pid = portal.verify_email(request.app.state.db, code)
    if not pid:
        raise HTTPException(404, t("The confirmation link is invalid."))
    return HTMLResponse(f"<h1>{t('Address confirmed')}</h1><p>{t('VPN notifications will be sent to this e-mail. You can close this window.')}</p>")


@app.get("/me/config.conf")
def me_config(request: Request):
    peer, _ = me_peer(request)
    if not peer or not peer["portal_config"]:
        raise HTTPException(404)
    cfg = client_config(request, peer["id"])
    db.event(request.app.state.db, "client_view", peer["id"], {"via": "config"}, actor_ip=client_ip(request))
    return Response(cfg["conf"], media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": content_disposition(cfg["name"], cfg["ip"]), "Cache-Control": "no-store"})


@app.get("/me/qr/{kind}.svg")
def me_qr(request: Request, kind: str):
    peer, _ = me_peer(request)
    if not peer or not peer["portal_config"] or kind not in ("conf", "vpn"):
        raise HTTPException(404)
    return Response(clientconf.qr_svg(client_config(request, peer["id"])[kind]), media_type="image/svg+xml",
                    headers={"Cache-Control": "no-store"})


@app.get("/me/stats.png")
def me_stats_png(request: Request):
    peer, _ = me_peer(request)
    if not peer:
        raise HTTPException(404)
    png, _ = report.daily_png(request.app.state.db, peer["id"], int(time.time()))
    return Response(png, media_type="image/png", headers={"Cache-Control": "no-store"})


@app.post("/me/logout")
def me_logout(request: Request):
    resp = me_redirect()
    resp.delete_cookie(ME_COOKIE, path="/me")
    return resp


@app.get("/healthz")
async def healthz(request: Request):
    if client_ip(request) not in ("127.0.0.1", "::1"):
        raise HTTPException(404)
    p = request.app.state.poller
    return {"ok": bool(p and p.status.last_ok and time.time() - p.status.last_ok < 3 * settings.poll_interval),
            "version": __version__, "schema": db.version(request.app.state.db),
            "poller": p and {"last_ok": int(p.status.last_ok), "error": p.status.last_error,
                             "online": p.status.online, "peers": p.status.peers},
            "geo": request.app.state.geo.built(),
            "sniffer": (sn := request.app.state.sniffer) and {"packets": sn.packets, "error": sn.last_error},
            "flows": (fl := request.app.state.flows) and {"events": fl.events, "error": fl.last_error},
            "blocker": (bl := request.app.state.blocker) and {"rules": bl.applied_rules, "error": bl.last_error}}
