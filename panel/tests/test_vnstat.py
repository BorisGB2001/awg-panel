import datetime
import json
from zoneinfo import ZoneInfo

from app import vnstat
from tests.test_auth import _csrf, _login, client  # noqa: F401 — фикстура

TZ = ZoneInfo("Europe/Amsterdam")
NOW = int(datetime.datetime(2026, 11, 13, 12, 7, tzinfo=TZ).timestamp())   # 13 Nov, 18 days left incl. the rest of today
GIB = 1 << 30


def _d(y, m, d=None, h=None, mi=None):
    out = {"date": {"year": y, "month": m, **({"day": d} if d else {})}}
    if h is not None:
        out["time"] = {"hour": h, "minute": mi}
    return out


def _iface(name, created=(2026, 10, 1), days=None, months=None, five=None, top=None):
    return {"name": name, "alias": "", "created": _d(*created), "updated": _d(2026, 11, 13, 12, 5),
            "traffic": {"total": {"rx": 0, "tx": 0},
                        "fiveminute": five or [], "hour": [{**_d(2026, 11, 13, 11, 0), "rx": GIB, "tx": GIB // 2}],
                        "day": days or [], "month": months or [], "year": [], "top": top or []}}


ETH0 = _iface(
    "eth0",
    days=[{**_d(2026, 11, 12), "rx": 10 * GIB, "tx": 4 * GIB}, {**_d(2026, 11, 13), "rx": 3 * GIB, "tx": GIB},
          {**_d(2026, 10, 20), "rx": 50 * GIB, "tx": 20 * GIB}],
    months=[{**_d(2026, 10), "rx": 300 * GIB, "tx": 100 * GIB}, {**_d(2026, 11), "rx": 120 * GIB, "tx": 40 * GIB}],
    five=[{**_d(2026, 11, 13, 11, 55), "rx": 375_000_000, "tx": 75_000_000},     # complete: 10 / 2 Mbit/s
          {**_d(2026, 11, 13, 12, 0), "rx": 37_500_000, "tx": 7_500_000},        # complete: 1 / 0.2 Mbit/s
          {**_d(2026, 11, 13, 12, 5), "rx": 1, "tx": 1}],                        # still being filled
    top=[{**_d(2026, 10, d), "rx": d * GIB, "tx": GIB} for d in range(1, 9)])
DOC = {"vnstatversion": "2.13", "jsonversion": "2",
       "interfaces": [ETH0, _iface("wt0", days=[{**_d(2026, 11, 13), "rx": GIB, "tx": GIB}]),
                      _iface("lo"), _iface("veth1a2b"), _iface("docker0"), _iface("amn0", created=(2026, 11, 13))]}


def runner(vn_rc=0, vn_out=None, vn_err="", active="active"):
    calls = []

    def run(argv, timeout):
        calls.append(argv)
        if "systemctl" in argv:
            return (0 if active == "active" else 3), active + "\n", ""
        return vn_rc, json.dumps(DOC) if vn_out is None else vn_out, vn_err
    run.calls = calls
    return run


def test_interface_filter():
    assert vnstat.visible(["lo", "veth9", "docker0", "wt0", "eth0", "amn0", "gre1"]) == ["eth0", "amn0", "gre1", "wt0"]


def test_summary_today_yesterday_month_rate():
    k = vnstat.summary(ETH0, TZ, NOW)
    assert k["today"] == {"rx": 3 * GIB, "tx": GIB, "total": 4 * GIB}
    assert k["yesterday"] == {"rx": 10 * GIB, "tx": 4 * GIB, "total": 14 * GIB}
    assert k["month"]["total"] == 160 * GIB and k["last_month"]["total"] == 400 * GIB
    assert round(k["rate"]["rx"], 3) == 1.0 and round(k["rate"]["tx"], 3) == 0.2


def test_forecast_from_last_full_day():
    k = vnstat.summary(ETH0, TZ, NOW)
    end = datetime.datetime(2026, 12, 1, tzinfo=TZ).timestamp()
    left = (end - NOW) / 86400
    assert abs(k["forecast"]["rx"] - (120 * GIB + 10 * GIB * left)) < 1
    assert abs(k["forecast"]["total"] - (160 * GIB + 14 * GIB * left)) < 1
    # the interface appeared yesterday: no full day yet, no forecast
    young = {**ETH0, "created": _d(2026, 11, 12)}
    assert vnstat.summary(young, TZ, NOW)["forecast"] is None


def test_view_full():
    v = vnstat.view(vnstat.VnStat(runner()).snapshot(NOW), None, TZ, NOW)
    assert v["state"] == "ok" and v["iface"] == "eth0" and v["ifaces"] == ["eth0", "amn0", "wt0"]
    # busiest first: wt0 has traffic today, amn0 has none
    assert [o["name"] for o in v["others"]] == ["wt0", "amn0"] and v["others"][0]["today"]["total"] == 2 * GIB
    assert [d["total"] for d in v["top"]] == [(d + 1) * GIB for d in (8, 7, 6, 5, 4)]
    assert len(v["charts"]) == 4 and all("<svg" in c for _, c in v["charts"])
    assert v["version"] == "2.13" and v["active"] == "active"
    assert v["since"] == int(datetime.datetime(2026, 10, 1, tzinfo=TZ).timestamp())
    pts = vnstat.series(ETH0, TZ, NOW)
    assert len(pts["five"]) == 288 and len(pts["hour"]) == 96 and len(pts["month"]) == 12
    assert len(pts["day"]) == 31 + 13 and pts["day"][-1][1:] == (3 * GIB, GIB)
    # remembered interface; an unknown one falls back to eth0
    assert vnstat.view(vnstat.VnStat(runner()).snapshot(NOW), "wt0", TZ, NOW)["iface"] == "wt0"
    assert vnstat.view(vnstat.VnStat(runner()).snapshot(NOW), "gone0", TZ, NOW)["iface"] == "eth0"


def test_timestamp_preferred_over_local_date():
    # vnStat's own timestamp wins: a panel TZ different from the host's does not shift entries
    e = {**_d(2026, 11, 13, 12, 0), "timestamp": NOW - 7 * 60 - 3600}
    assert vnstat._ts(e, TZ) == NOW - 7 * 60 - 3600
    assert vnstat._ts(_d(2026, 11, 13, 12, 0), TZ) == NOW - 7 * 60


def test_cache_and_collector_status():
    run = runner()
    vn = vnstat.VnStat(run)
    vn.snapshot(NOW)
    vn.snapshot(NOW + 30)
    assert len(run.calls) == 2                      # vnstat + systemctl once, the second read is cached
    vn.snapshot(NOW + 61)
    assert len(run.calls) == 4 and vn.last_ok == NOW + 61 and vn.last_error is None


def test_vnstat_missing():
    vn = vnstat.VnStat(runner(vn_rc=127, vn_out="", vn_err="nsenter: failed to execute vnstat: No such file or directory"))
    v = vnstat.view(vn.snapshot(NOW), None, TZ, NOW)
    assert v["state"] == "missing" and vn.last_error


def test_empty_database():
    vn = vnstat.VnStat(runner(vn_rc=1, vn_out="", vn_err="Error: No interfaces found in the database, nothing to do.",
                              active="inactive"))
    v = vnstat.view(vn.snapshot(NOW), None, TZ, NOW)
    assert v["state"] == "empty" and v["active"] == "inactive" and vn.last_error is None
    empty = vnstat.VnStat(runner(vn_out=json.dumps({"vnstatversion": "2.13", "interfaces": []})))
    assert vnstat.view(empty.snapshot(NOW), None, TZ, NOW)["state"] == "empty"
    only_hidden = vnstat.VnStat(runner(vn_out=json.dumps({"interfaces": [_iface("lo")]})))
    assert vnstat.view(only_hidden.snapshot(NOW), None, TZ, NOW)["state"] == "empty"


def test_timeout_is_an_error_not_a_crash():
    vn = vnstat.VnStat(runner(vn_rc=124, vn_out="", vn_err="timeout"))
    v = vnstat.view(vn.snapshot(NOW), None, TZ, NOW)
    assert v["state"] == "error" and "timeout" in v["error"] and vn.last_error


def test_server_page_and_interface_choice(client):  # noqa: F811
    _login(client)
    assert "PANEL_COLLECTORS=0" in client.get("/server").text            # collectors off: vnStat is not read
    client.app.state.vnstat = vnstat.VnStat(runner())
    page = client.get("/server").text
    assert "Server traffic" in page and "Top 5 days" in page
    tok = _csrf(page)
    r = client.post("/server/vnstat/iface", data={"iface": "wt0", "csrf": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/server#host-traffic"
    page = client.get("/server").text
    assert "Saved." in page and "<option selected>wt0</option>" in page
    assert "Unknown interface: lo" in client.post("/server/vnstat/iface", data={"iface": "lo", "csrf": tok}).text
    client.app.state.vnstat = vnstat.VnStat(runner(vn_rc=127, vn_out="", vn_err="No such file or directory"))
    assert "apt install vnstat" in client.get("/server").text
