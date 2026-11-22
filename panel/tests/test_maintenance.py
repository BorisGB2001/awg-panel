from app import db, fmt, maintenance
from app.config import Settings

DAY = 86400


def test_aggregate_then_cleanup(tmp_path):
    s = Settings(data_dir=tmp_path, retention_raw_days=30, retention_min_days=7, retention_events_days=365)
    conn = db.open_db(tmp_path / "p.db")
    now = 1_800_000_000
    old = fmt.day_start(now - 40 * DAY) + 3600
    conn.execute("INSERT INTO dns VALUES (?, 1, 'www.youtube.com', 'dns', 5)", (old,))
    conn.execute("INSERT INTO flows VALUES (?, 1, '1.1.1.1', 443, 'tcp', 'rr.googlevideo.com', 2, 10, 900)", (old,))
    conn.execute("INSERT INTO traffic_min VALUES (?, 1, 1, 1)", (now - 8 * DAY,))
    conn.execute("INSERT INTO traffic_hour VALUES (?, 1, 1, 1)", (now - 400 * DAY,))
    maintenance.aggregate_hosts(conn, fmt.TZ, fmt.day_start(now))
    hd = {r["host"]: r for r in conn.execute("SELECT * FROM hosts_day")}
    assert hd["youtube.com"]["requests"] == 5 and hd["googlevideo.com"]["bytes_down"] == 900
    removed = maintenance.cleanup(conn, s, now)
    assert removed["dns"] == 1 and removed["flows"] == 1 and removed["traffic_min"] == 1
    assert conn.execute("SELECT COUNT(*) FROM traffic_hour").fetchone()[0] == 1   # часовой трафик — бессрочно


def test_raw_not_deleted_before_aggregation(tmp_path):
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(tmp_path / "p.db")
    now = 1_800_000_000
    conn.execute("INSERT INTO dns VALUES (?, 1, 'a.com', 'dns', 1)", (now - 40 * DAY,))
    assert maintenance.cleanup(conn, s, now)["dns"] == 0


def test_backup_rotation(tmp_path, monkeypatch):
    import gzip
    import sqlite3
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(tmp_path / "p.db")
    conn.execute("INSERT INTO peers (id, pubkey, name, ip) VALUES (1, 'k', 'Анна', '10.8.1.1')")
    conn.execute("INSERT INTO dns VALUES (1800000000, 1, 'a.com', 'dns', 1)")
    d = tmp_path / "backups" / "db"
    d.mkdir(parents=True)
    (d / "panel-20261101-0400.db").write_bytes(b"old uncompressed copy")
    monkeypatch.setattr(maintenance, "KEEP_DB_BACKUPS", 3)
    monkeypatch.setattr(maintenance, "KEEP_FULL_DB_BACKUPS", 2)
    for i in range(4):
        maintenance.backup_db(conn, s, 1_800_000_000 + i * 120)
    full = sorted(p for p in d.glob("*.db.gz") if ".nolog" not in p.name)
    slim = sorted(d.glob("*.nolog.db.gz"))
    assert len(full) == 2 and len(slim) == 3 and not list(d.glob("*.db")) and not list(d.glob(".*"))
    assert all(oct(p.stat().st_mode)[-3:] == "600" for p in full + slim)

    def rows(p, sql):
        out = tmp_path / "check.db"
        out.write_bytes(gzip.decompress(p.read_bytes()))
        c = sqlite3.connect(out)
        try:
            return c.execute(sql).fetchone()[0]
        finally:
            c.close()
    assert rows(full[-1], "SELECT COUNT(*) FROM dns") == 1 and rows(slim[-1], "SELECT COUNT(*) FROM dns") == 0
    assert rows(slim[-1], "SELECT name FROM peers") == "Анна"
