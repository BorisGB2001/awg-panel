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
    s = Settings(data_dir=tmp_path)
    conn = db.open_db(tmp_path / "p.db")
    monkeypatch.setattr(maintenance, "KEEP_DB_BACKUPS", 2)
    for i in range(4):
        maintenance.backup_db(conn, s, 1_800_000_000 + i * 120)
    files = sorted((tmp_path / "backups" / "db").glob("*.db"))
    assert len(files) == 2 and oct(files[0].stat().st_mode)[-3:] == "600"
