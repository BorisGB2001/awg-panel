"""Traffic of the host the panel runs on, from vnStat (Server page).

vnStat is read as `nsenter -t 1 -m -- vnstat --json` in the host mount namespace: the container already runs with
`pid: host` and `privileged`, so no extra volume is needed, and the JSON output is vnStat's public interface (the
SQLite schema is internal and may change between versions). The output is cached for CACHE_TTL seconds.

Days and months follow the host's local dates, so the panel's TZ should match the host's time zone ("today" is
computed in the panel's TZ).
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import threading
import time
from typing import Callable
from zoneinfo import ZoneInfo

from . import charts
from .fmt import N_
from .i18n import t

CACHE_TTL = 60
TIMEOUT = 5
DEFAULT_IFACE = "eth0"
HIDDEN_PREFIXES = ("veth", "docker")
VNSTAT = ["nsenter", "-t", "1", "-m", "--", "vnstat", "--json"]
SYSTEMCTL = ["nsenter", "-t", "1", "-m", "--", "systemctl", "is-active", "vnstat"]

Runner = Callable[[list[str], float], tuple[int, str, str]]


def _run(argv: list[str], timeout: float) -> tuple[int, str, str]:
    try:
        # without the container's TZ vnStat uses the host's /etc/localtime, so its "timestamp" fields are right
        env = {k: v for k, v in os.environ.items() if k != "TZ"}
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)
    return r.returncode, r.stdout, r.stderr


def visible(names) -> list[str]:
    """Interfaces worth showing: without lo, veth* and docker*; the default interface first."""
    out = sorted(n for n in names if n != "lo" and not n.startswith(HIDDEN_PREFIXES))
    if DEFAULT_IFACE in out:
        out.remove(DEFAULT_IFACE)
        out.insert(0, DEFAULT_IFACE)
    return out


class VnStat:
    """Reads vnStat with a cache; last_ok / last_error are shown in the "Panel collectors" list."""

    def __init__(self, runner: Runner = _run, ttl: int = CACHE_TTL, timeout: float = TIMEOUT):
        self.runner = runner
        self.ttl = ttl
        self.timeout = timeout
        self.last_ok: int | None = None
        self.last_error: str | None = None
        self._cache: tuple[float, dict] | None = None
        self._lock = threading.Lock()

    def snapshot(self, now: float | None = None) -> dict:
        """{"state": ok | empty | missing | error, "doc": vnstat JSON or None, "active": service state, "error"}."""
        now = time.time() if now is None else now
        with self._lock:
            if self._cache and now - self._cache[0] < self.ttl:
                return self._cache[1]
            snap = self._fetch()
            self._cache = (now, snap)
        if snap["state"] in ("ok", "empty"):
            self.last_ok, self.last_error = int(now), None
        else:
            self.last_error = snap["error"]
        return snap

    def _fetch(self) -> dict:
        rc, out, err = self.runner(VNSTAT, self.timeout)
        src, active = {"doc": None, "active": None, "error": None}, None
        if rc == 127 or "No such file" in err:
            return src | {"state": "missing", "error": t("vnstat is not installed on the host")}
        arc, aout, _ = self.runner(SYSTEMCTL, self.timeout)
        active = aout.strip() or ("unknown" if arc else None)
        src["active"] = active
        if rc != 0:
            msg = (err.strip() or out.strip() or f"exit {rc}")[:200]
            low = msg.lower()
            if "no interfaces" in low or "0 interfaces" in low or "unable to open database" in low:
                return src | {"state": "empty", "error": None}
            return src | {"state": "error", "error": f"vnstat: {msg}"}
        try:
            doc = json.loads(out)
        except ValueError as e:
            return src | {"state": "error", "error": f"vnstat: {e}"}
        if not doc.get("interfaces"):
            return src | {"state": "empty", "doc": doc}
        return src | {"state": "ok", "doc": doc}


# ---- parsing ----

def _ts(entry: dict, tz: ZoneInfo) -> int:
    """Start of a vnStat entry as a Unix time: its "timestamp" or, in older output, the host's local date and time."""
    if isinstance(entry.get("timestamp"), int):
        return entry["timestamp"]
    d, tm = entry.get("date") or {}, entry.get("time") or {}
    return int(datetime.datetime(d["year"], d.get("month", 1), d.get("day", 1), tm.get("hour", 0), tm.get("minute", 0),
                                 tzinfo=tz).timestamp())


def _day(entry: dict) -> datetime.date:
    d = entry["date"]
    return datetime.date(d["year"], d["month"], d.get("day", 1))


def _pair(e: dict | None) -> dict:
    rx, tx = (e or {}).get("rx", 0), (e or {}).get("tx", 0)
    return {"rx": rx, "tx": tx, "total": rx + tx}


def _month_start(d: datetime.date, shift: int = 0) -> datetime.date:
    m = d.year * 12 + d.month - 1 + shift
    return datetime.date(m // 12, m % 12 + 1, 1)


def summary(iface: dict, tz: ZoneInfo, now: int) -> dict:
    """KPI of one interface: today, yesterday, this and last month, speed of the last full 5 minutes, month forecast."""
    tr = iface.get("traffic") or {}
    today = datetime.datetime.fromtimestamp(now, tz).date()
    yday = today - datetime.timedelta(days=1)
    days = {_day(e): e for e in tr.get("day") or []}
    months = {(e["date"]["year"], e["date"]["month"]): e for e in tr.get("month") or []}
    this_m, last_m = _month_start(today), _month_start(today, -1)
    out = {"today": _pair(days.get(today)), "yesterday": _pair(days.get(yday)),
           "month": _pair(months.get((this_m.year, this_m.month))),
           "last_month": _pair(months.get((last_m.year, last_m.month)))}

    # speed: the newest five-minute entry that is already complete (the current one is still being filled)
    updated = _ts(iface["updated"], tz) if iface.get("updated") else now
    done = [e for e in tr.get("fiveminute") or [] if _ts(e, tz) + 300 <= updated]
    if done:
        last = max(done, key=lambda e: _ts(e, tz))
        out["rate"] = {"rx": last["rx"] * 8 / 300 / 1e6, "tx": last["tx"] * 8 / 300 / 1e6, "ts": _ts(last, tz)}
    else:
        out["rate"] = None

    # forecast: this month so far + yesterday's volume for every remaining day. vnStat's own "estimated" extrapolates
    # the current day and is far off in its first hours, so only a full day is used.
    created = iface.get("created") or {}
    full_yday = bool(created.get("date")) and _day(created) < yday     # created yesterday: the day is incomplete
    if yday in days and full_yday:
        end = _month_start(today, 1)
        end_ts = int(datetime.datetime(end.year, end.month, 1, tzinfo=tz).timestamp())
        left = max(end_ts - now, 0) / 86400
        y = _pair(days[yday])
        rx, tx = out["month"]["rx"] + y["rx"] * left, out["month"]["tx"] + y["tx"] * left
        out["forecast"] = {"rx": rx, "tx": tx, "total": rx + tx}
    else:
        out["forecast"] = None
    return out


def _fill(entries: list[dict], tz: ZoneInfo, since: int, now: int, step: int) -> list[tuple[int, float, float]]:
    got: dict[int, tuple[float, float]] = {}
    for e in entries:
        ts = _ts(e, tz)
        k = ts - ts % step
        a = got.get(k, (0, 0))
        got[k] = (a[0] + e["rx"], a[1] + e["tx"])
    start = since - since % step
    return [(k, *got.get(k, (0, 0))) for k in range(start, now + 1, step)]


def series(iface: dict, tz: ZoneInfo, now: int) -> dict[str, list[tuple[int, float, float]]]:
    """Points (start, received, sent) for the charts: 5 minutes for 24 h, hours for 4 days, days of this and
    last month, months for a year."""
    tr = iface.get("traffic") or {}
    out = {"five": _fill(tr.get("fiveminute") or [], tz, now - 86400 + 300, now, 300),
           "hour": _fill(tr.get("hour") or [], tz, now - 4 * 86400 + 3600, now, 3600)}
    today = datetime.datetime.fromtimestamp(now, tz).date()
    days = {_day(e): e for e in tr.get("day") or []}
    d, pts = _month_start(today, -1), []
    while d <= today:
        e = days.get(d) or {}
        pts.append((int(datetime.datetime(d.year, d.month, d.day, tzinfo=tz).timestamp()), e.get("rx", 0), e.get("tx", 0)))
        d += datetime.timedelta(days=1)
    out["day"] = pts
    months = {(e["date"]["year"], e["date"]["month"]): e for e in tr.get("month") or []}
    pts = []
    for shift in range(-11, 1):
        m = _month_start(today, shift)
        e = months.get((m.year, m.month)) or {}
        pts.append((int(datetime.datetime(m.year, m.month, 1, tzinfo=tz).timestamp()), e.get("rx", 0), e.get("tx", 0)))
    out["month"] = pts
    return out


def top_days(iface: dict, n: int = 5) -> list[dict]:
    """Busiest days of all time: vnStat keeps them in "top" even after the daily entries expire."""
    tr = iface.get("traffic") or {}
    src = tr.get("top") or tr.get("day") or []
    rows = [{"date": _day(e), **_pair(e)} for e in src]
    return sorted(rows, key=lambda r: -r["total"])[:n]


CHARTS = (("five", N_("Last 24 hours, by 5 minutes"), "%H:%M"), ("hour", N_("Last 4 days, by hour"), "%d.%m %H"),
          ("day", N_("This and last month, by day"), "%d.%m"), ("month", N_("Last 12 months"), "%m.%Y"))


def view(snap: dict | None, pref: str | None, tz: ZoneInfo, now: int) -> dict:
    """Everything the "Server traffic" block shows; snap=None — collectors are off (PANEL_COLLECTORS=0)."""
    if snap is None:
        return {"state": "off"}
    out = {k: snap.get(k) for k in ("state", "active", "error")}
    doc = snap.get("doc") or {}
    out["version"] = doc.get("vnstatversion")
    by_name = {i["name"]: i for i in doc.get("interfaces") or []}
    names = visible(by_name)
    out["ifaces"] = names
    upd = [_ts(i["updated"], tz) for i in by_name.values() if i.get("updated")]
    created = [_ts(i["created"], tz) for i in by_name.values() if i.get("created")]
    out["updated"] = max(upd) if upd else None
    out["since"] = min(created) if created else None
    if snap.get("state") != "ok" or not names:
        if snap.get("state") == "ok":
            out["state"] = "empty"
        return out
    name = pref if pref in names else (DEFAULT_IFACE if DEFAULT_IFACE in names else names[0])
    iface = by_name[name]
    out["iface"] = name
    out["kpi"] = summary(iface, tz, now)
    pts = series(iface, tz, now)
    legend = (t("incoming"), t("outgoing"))
    out["charts"] = [(t(title), charts.bars(pts[key], tz, lab, legend=legend)) for key, title, lab in CHARTS]
    out["top"] = top_days(iface)
    others = [{"name": n, **{k: v for k, v in summary(by_name[n], tz, now).items() if k in ("today", "month")}}
              for n in names if n != name]
    # busiest first: hosts list many idle tunnels (gre0, erspan0, ...) with no traffic at all
    out["others"] = sorted(others, key=lambda o: (-o["month"]["total"], -o["today"]["total"], o["name"]))
    return out
