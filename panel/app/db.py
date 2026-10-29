"""SQLite: схема, миграции, соединения. Каждый поток открывает своё соединение через connect()."""
from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path

# Каждая миграция применяется один раз, по порядку; номер версии = индекс + 1.
MIGRATIONS: list[str] = [
    """
    CREATE TABLE peers (
        id INTEGER PRIMARY KEY,
        pubkey TEXT UNIQUE NOT NULL,
        name TEXT,
        ip TEXT,
        note TEXT,
        source TEXT,                      -- 'amnezia_app' | 'panel'
        private_key_enc BLOB,             -- только для созданных панелью, Fernet(DATA_KEY)
        created_at INT,
        deleted_at INT,
        disabled INT NOT NULL DEFAULT 0,
        first_handshake INT,
        last_handshake INT,
        last_endpoint TEXT,
        rx_total INT NOT NULL DEFAULT 0,
        tx_total INT NOT NULL DEFAULT 0
    );
    CREATE INDEX peers_ip ON peers(ip);

    CREATE TABLE traffic_min (ts INT, peer_id INT, rx INT, tx INT, PRIMARY KEY (ts, peer_id));
    CREATE INDEX traffic_min_peer ON traffic_min(peer_id, ts);
    CREATE TABLE traffic_hour (ts INT, peer_id INT, rx INT, tx INT, PRIMARY KEY (ts, peer_id));
    CREATE INDEX traffic_hour_peer ON traffic_hour(peer_id, ts);
    CREATE TABLE online_min (ts INT PRIMARY KEY, online INT);

    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        peer_id INT NOT NULL,
        start INT NOT NULL,
        end INT,
        endpoint_ip TEXT,
        rx INT NOT NULL DEFAULT 0,
        tx INT NOT NULL DEFAULT 0
    );
    CREATE INDEX sessions_peer ON sessions(peer_id, start);
    CREATE INDEX sessions_open ON sessions(end) WHERE end IS NULL;

    CREATE TABLE endpoints (
        peer_id INT, ip TEXT, first_seen INT, last_seen INT, count INT NOT NULL DEFAULT 1,
        country TEXT, city TEXT, asn INT, org TEXT,
        PRIMARY KEY (peer_id, ip)
    );

    CREATE TABLE events (
        id INTEGER PRIMARY KEY,
        ts INT NOT NULL,
        peer_id INT,
        kind TEXT NOT NULL,
        detail TEXT,                      -- JSON
        actor TEXT,
        actor_ip TEXT,
        acked INT NOT NULL DEFAULT 0
    );
    CREATE INDEX events_ts ON events(ts);
    CREATE INDEX events_peer ON events(peer_id, ts);
    CREATE INDEX events_kind ON events(kind, ts);

    CREATE TABLE flows (
        ts INT, peer_id INT, dst_ip TEXT, dport INT, proto TEXT, host TEXT,
        conns INT, bytes_up INT, bytes_down INT,
        PRIMARY KEY (ts, peer_id, dst_ip, dport, proto)
    );
    CREATE INDEX flows_peer ON flows(peer_id, ts);

    CREATE TABLE dns (
        ts INT, peer_id INT, name TEXT, kind TEXT, count INT,
        PRIMARY KEY (ts, peer_id, name, kind)
    );
    CREATE INDEX dns_peer ON dns(peer_id, ts);

    CREATE TABLE hosts_day (
        day INT, peer_id INT, host TEXT, requests INT NOT NULL DEFAULT 0, conns INT NOT NULL DEFAULT 0,
        bytes_up INT NOT NULL DEFAULT 0, bytes_down INT NOT NULL DEFAULT 0,
        PRIMARY KEY (day, peer_id, host)
    );
    CREATE INDEX hosts_day_host ON hosts_day(host, day);

    CREATE TABLE ipnames (ip TEXT PRIMARY KEY, name TEXT, ts INT);
    CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT);
    """,
    # 2: время последней активности открытой сессии — по нему сессия закрывается
    """
    ALTER TABLE sessions ADD COLUMN last_active INT;
    """,
    # 3: блокировка доменов и IP; peer_id NULL — для всех клиентов
    """
    CREATE TABLE block_rules (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL,                -- 'domain' | 'ip'
        value TEXT NOT NULL,
        peer_id INT,
        enabled INT NOT NULL DEFAULT 1,
        note TEXT,
        preset TEXT,
        created_at INT,
        actor TEXT,
        hits INT NOT NULL DEFAULT 0,
        hits_ts INT
    );
    CREATE UNIQUE INDEX block_rules_uniq ON block_rules(kind, value, COALESCE(peer_id, 0));
    """,
    # 4: помесячный архив: итоги месяца по клиенту фиксируются 1-го числа в 00:00 (часовой пояс TZ)
    """
    CREATE TABLE monthly_archive (
        month TEXT NOT NULL,              -- 'YYYY-MM'
        peer_id INT NOT NULL,
        name TEXT, ip TEXT,
        rx INT NOT NULL DEFAULT 0,        -- клиент отдал
        tx INT NOT NULL DEFAULT 0,        -- клиент скачал
        sessions INT NOT NULL DEFAULT 0,
        online_sec INT NOT NULL DEFAULT 0,
        created_at INT,
        PRIMARY KEY (month, peer_id)
    );
    """,
    # 5: личный кабинет клиента и уведомления
    """
    ALTER TABLE peers ADD COLUMN portal_hash TEXT;
    ALTER TABLE peers ADD COLUMN portal_config INT NOT NULL DEFAULT 0;
    CREATE TABLE contacts (
        peer_id INT PRIMARY KEY,
        email TEXT, email_verified INT NOT NULL DEFAULT 0, email_code TEXT,
        tg_chat_id INT, tg_name TEXT, tg_code TEXT, tg_code_exp INT,
        daily INT NOT NULL DEFAULT 1, daily_hour INT NOT NULL DEFAULT 21, events INT NOT NULL DEFAULT 1,
        last_daily TEXT
    );
    CREATE TABLE notify_log (id INTEGER PRIMARY KEY, ts INT, peer_id INT, channel TEXT, kind TEXT, ok INT, error TEXT);
    CREATE INDEX notify_log_ts ON notify_log(ts);
    """,
    # 6: язык клиента для уведомлений и сводки (выбирается в кабинете)
    """
    ALTER TABLE contacts ADD COLUMN lang TEXT;
    """,
]


def connect(path: Path | str) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (v INT NOT NULL)")
    row = conn.execute("SELECT v FROM schema_version").fetchone()
    return row[0] if row else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Доводит схему до последней версии; возвращает итоговую версию."""
    v = version(conn)
    for i, sql in enumerate(MIGRATIONS[v:], start=v + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for stmt in _split(sql):
                conn.execute(stmt)
            conn.execute("DELETE FROM schema_version")
            conn.execute("INSERT INTO schema_version (v) VALUES (?)", (i,))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return len(MIGRATIONS)


def _split(sql: str) -> list[str]:
    """Делит скрипт миграции на операторы (executescript нельзя — он коммитит посреди транзакции)."""
    out, buf = [], []
    for line in sql.splitlines():
        line = line.split("--", 1)[0].rstrip()
        if not line:
            continue
        buf.append(line)
        if line.endswith(";"):
            out.append("\n".join(buf))
            buf = []
    if buf:
        out.append("\n".join(buf))
    return out


def open_db(path: Path | str) -> sqlite3.Connection:
    """Открыть и смигрировать БД. Каталог данных и файлы БД — только для владельца: в них история клиентов."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)  # всё, что панель создаёт дальше (БД, -wal/-shm, гео, бэкапы), — 600/700
    conn = connect(path)
    migrate(conn)
    os.chmod(path.parent, 0o700)
    for f in (path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")):
        if f.exists():
            os.chmod(f, 0o600)
    return conn


def event(conn: sqlite3.Connection, kind: str, peer_id: int | None = None, detail: dict | None = None,
          actor: str | None = None, actor_ip: str | None = None, ts: int | None = None) -> None:
    conn.execute(
        "INSERT INTO events (ts, peer_id, kind, detail, actor, actor_ip) VALUES (?, ?, ?, ?, ?, ?)",
        (ts or int(time.time()), peer_id, kind,
         json.dumps(detail, ensure_ascii=False) if detail is not None else None, actor, actor_ip),
    )


def get_state(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM state WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))
