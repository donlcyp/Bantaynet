"""Database persistence layer for BantayNet alerts.

Supports both XAMPP MySQL/MariaDB and SQLite with seamless fallback:
- When configured for MySQL, connects to XAMPP MariaDB/MySQL (port 3306).
- If MySQL is unreachable (e.g. XAMPP stopped), gracefully falls back to local SQLite.
- Fully parameterized queries across both database engines.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.mitre import attach_mitre_info
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger("bantaynet.db")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "bantaynet.db"
DB_PATH = DEFAULT_SQLITE_PATH

# Default XAMPP MySQL connection parameters
DEFAULT_MYSQL_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "",
    "database": "bantaynet_db",
}


ACTIVE_ENGINE: str | None = None


def _mark_sqlite_fallback(exc: Exception) -> None:
    """Warn once, then stay on SQLite for the rest of this process."""
    global ACTIVE_ENGINE
    if ACTIVE_ENGINE != "sqlite":
        logger.warning("MySQL unavailable (%s); using SQLite for this session", exc)
    ACTIVE_ENGINE = "sqlite"


def _get_active_engine(db_path: Path | str | None = None) -> tuple[str, dict[str, Any]]:
    """Determine whether to use MySQL or SQLite based on configuration and arguments."""
    if db_path is not None:
        return "sqlite", {"path": Path(db_path)}

    if ACTIVE_ENGINE == "sqlite":
        return "sqlite", {"path": DB_PATH}

    try:
        from src.config import load_config
        cfg = load_config()
        if cfg.database.engine == "mysql":
            return "mysql", cfg.database.mysql
        else:
            return "sqlite", {"path": PROJECT_ROOT / cfg.database.sqlite.get("path", "bantaynet.db")}
    except Exception:
        return "mysql", DEFAULT_MYSQL_CONFIG



def get_mysql_connection(config: dict[str, Any] | None = None):
    import pymysql
    import pymysql.cursors

    c = config or DEFAULT_MYSQL_CONFIG
    # First ensure database exists
    root_conn = pymysql.connect(
        host=c.get("host", "127.0.0.1"),
        port=int(c.get("port", 3306)),
        user=c.get("user", "root"),
        password=c.get("password", ""),
    )
    with root_conn.cursor() as cur:
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{c.get('database', 'bantaynet_db')}` "
            f"CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        )
    root_conn.close()

    # Connect to the target database
    return pymysql.connect(
        host=c.get("host", "127.0.0.1"),
        port=int(c.get("port", 3306)),
        user=c.get("user", "root"),
        password=c.get("password", ""),
        database=c.get("database", "bantaynet_db"),
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def get_sqlite_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else DEFAULT_SQLITE_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path | str | None = None) -> str:
    """Initialize alerts table on the active database engine."""
    engine, conf = _get_active_engine(db_path)
    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        detected_at VARCHAR(64) NOT NULL,
                        packet_time VARCHAR(64) NOT NULL,
                        rule VARCHAR(64) NOT NULL,
                        severity VARCHAR(32) NOT NULL,
                        src_ip VARCHAR(64) NOT NULL,
                        dst_ip VARCHAR(64),
                        dst_port VARCHAR(64),
                        protocol VARCHAR(32),
                        description TEXT,
                        evidence_file VARCHAR(512),
                        source_pcap VARCHAR(256),
                        packet_count INT DEFAULT 1,
                        details_json TEXT,
                        INDEX idx_alerts_rule (rule),
                        INDEX idx_alerts_src (src_ip),
                        INDEX idx_alerts_severity (severity)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                    """
                )
                for col_def in [
                    "dst_port VARCHAR(64)",
                    "status VARCHAR(32) DEFAULT 'new'",
                    "analyst_note TEXT",
                    "updated_at VARCHAR(64)",
                    "client_name VARCHAR(128) DEFAULT 'Default'",
                ]:
                    try:
                        cur.execute(f"ALTER TABLE alerts ADD COLUMN {col_def};")
                    except Exception:
                        pass

                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(64) NOT NULL UNIQUE,
                        password_hash VARCHAR(256) NOT NULL,
                        role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                        created_at VARCHAR(64) NOT NULL,
                        INDEX idx_users_username (username)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                    """
                )
            conn.close()
            _seed_default_users("mysql", conf)
            return "mysql"
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite fallback / default
    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at TEXT NOT NULL,
                packet_time TEXT NOT NULL,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT,
                dst_port TEXT,
                protocol TEXT,
                description TEXT,
                evidence_file TEXT,
                source_pcap TEXT,
                packet_count INTEGER DEFAULT 1,
                details_json TEXT,
                status TEXT DEFAULT 'new',
                analyst_note TEXT,
                updated_at TEXT,
                client_name TEXT DEFAULT 'Default'
            );
            """
        )
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        migration_cols = [
            ("dst_port", "TEXT"),
            ("status", "TEXT DEFAULT 'new'"),
            ("analyst_note", "TEXT"),
            ("updated_at", "TEXT"),
            ("client_name", "TEXT DEFAULT 'Default'"),
        ]
        for col_name, col_type in migration_cols:
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_type};")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_client ON alerts(client_name);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.commit()

    _seed_default_users("sqlite", conf)
    return "sqlite"


VALID_ROLES = ("admin", "analyst", "viewer")


def _seed_default_users(engine: str, conf: dict[str, Any]) -> None:
    """Ensure default accounts (admin, analyst, viewer) exist if users table is empty."""
    default_accounts = [
        ("admin", "admin123!", "admin"),
        ("analyst", "analyst123!", "analyst"),
        ("viewer", "viewer123!", "viewer"),
    ]
    now_str = datetime.now(timezone.utc).isoformat()

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as cnt FROM users")
                cnt = cur.fetchone()["cnt"]
                if cnt == 0:
                    for u, p, r in default_accounts:
                        cur.execute(
                            "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                            (u, generate_password_hash(p), r, now_str),
                        )
            conn.close()
            return
        except Exception:
            pass

    # SQLite
    try:
        with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
            cnt = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if cnt == 0:
                for u, p, r in default_accounts:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
                        (u, generate_password_hash(p), r, now_str),
                    )
                conn.commit()
    except Exception:
        pass


def create_user(
    username: str,
    password: str,
    role: str = "viewer",
    db_path: Path | str | None = None,
) -> int:
    """Create a new user with hashed credentials. Raises ValueError if invalid."""
    username = (username or "").strip().lower()
    if not username:
        raise ValueError("Username cannot be empty")
    role = (role or "viewer").strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}")
    if not password:
        raise ValueError("Password cannot be empty")

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)
    pwd_hash = generate_password_hash(password)
    now_str = datetime.now(timezone.utc).isoformat()

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    raise ValueError(f"Username '{username}' already exists")
                cur.execute(
                    "INSERT INTO users (username, password_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                    (username, pwd_hash, role, now_str),
                )
                last_id = cur.lastrowid
            conn.close()
            return int(last_id)
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"Username '{username}' already exists")
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, pwd_hash, role, now_str),
        )
        conn.commit()
        return int(cursor.lastrowid)


def authenticate_user(
    username: str,
    password: str,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    """Validate username and password. Returns user dict (without password_hash) if successful, else None."""
    username = (username or "").strip().lower()
    if not username or not password:
        return None

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    user_row = None
    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                user_row = cur.fetchone()
            conn.close()
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    if user_row is None and (engine == "sqlite" or ACTIVE_ENGINE == "sqlite"):
        with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                user_row = dict(row)

    if not user_row:
        return None

    stored_hash = user_row.get("password_hash") or ""
    if not check_password_hash(stored_hash, password):
        return None

    user = dict(user_row)
    user.pop("password_hash", None)
    return user


def get_user_by_id(user_id: int, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve user by ID without password_hash."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, role, created_at FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
            conn.close()
            return dict(row) if row else None
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        row = conn.execute("SELECT id, username, role, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_all_users(db_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Retrieve all users without password_hash ordered by ID."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC")
                rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        rows = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


def update_user_role(user_id: int, role: str, db_path: Path | str | None = None) -> bool:
    """Update role for a user."""
    role = (role or "").strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}")

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
    return True


def delete_user(user_id: int, db_path: Path | str | None = None) -> bool:
    """Delete a user by ID."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return True


def _extract_port(details: dict[str, Any] | None) -> str | None:
    if not details:
        return None
    if "dport" in details:
        return str(details["dport"])
    if "port" in details:
        return str(details["port"])
    if "ports" in details and details["ports"]:
        p_list = details["ports"]
        if len(p_list) <= 3:
            return ", ".join(map(str, p_list))
        return f"Multiple ({len(p_list)})"
    if "sample_ports" in details:
        return f"Multiple ({details.get('distinct_ports', len(details['sample_ports']))})"
    return None


def insert_alert(
    rule: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    packet_time: str | float,
    description: str,
    evidence_file: str | None = None,
    source_pcap: str | None = None,
    protocol: str = "TCP",
    packet_count: int = 1,
    details: dict[str, Any] | None = None,
    detected_at: str | None = None,
    db_path: Path | str | None = None,
    dst_port: str | None = None,
    client_name: str = "Default",
    status: str = "new",
    analyst_note: str = "",
) -> int:
    """Insert a new alert record into active database (MySQL or SQLite)."""
    if detected_at is None:
        detected_at = datetime.now(timezone.utc).isoformat()
    if isinstance(packet_time, (int, float)):
        packet_time = datetime.fromtimestamp(packet_time, tz=timezone.utc).isoformat()

    if not dst_port:
        dst_port = _extract_port(details)

    details_str = json.dumps(details or {})
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO alerts (
                        detected_at, packet_time, rule, severity, src_ip, dst_ip, dst_port,
                        protocol, description, evidence_file, source_pcap, packet_count, details_json,
                        client_name, status, analyst_note, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        detected_at,
                        packet_time,
                        rule,
                        severity,
                        src_ip,
                        dst_ip,
                        dst_port,
                        protocol,
                        description,
                        evidence_file,
                        source_pcap,
                        packet_count,
                        details_str,
                        client_name or "Default",
                        status or "new",
                        analyst_note or "",
                        detected_at,
                    ),
                )
                last_id = cur.lastrowid
            conn.close()
            return int(last_id)
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite
    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute(
            """
            INSERT INTO alerts (
                detected_at, packet_time, rule, severity, src_ip, dst_ip, dst_port,
                protocol, description, evidence_file, source_pcap, packet_count, details_json,
                client_name, status, analyst_note, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                detected_at,
                packet_time,
                rule,
                severity,
                src_ip,
                dst_ip,
                dst_port,
                protocol,
                description,
                evidence_file,
                source_pcap,
                packet_count,
                details_str,
                client_name or "Default",
                status or "new",
                analyst_note or "",
                detected_at,
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)


def update_alert_status_and_note(
    alert_id: int,
    status: str,
    analyst_note: str,
    db_path: Path | str | None = None,
) -> bool:
    """Update the status and analyst note for a specific alert."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)
    now_str = datetime.now(timezone.utc).isoformat()
    status = (status or "").strip().lower()
    valid_statuses = ("new", "investigating", "resolved", "false_positive")
    if status not in valid_statuses:
        status = "investigating"

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE alerts SET status = %s, analyst_note = %s, updated_at = %s WHERE id = %s",
                    (status, analyst_note, now_str, alert_id),
                )
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute(
            "UPDATE alerts SET status = ?, analyst_note = ?, updated_at = ? WHERE id = ?",
            (status, analyst_note, now_str, alert_id),
        )
        conn.commit()
    return True



def _format_alert_dict(row: Any) -> dict[str, Any]:
    """Normalize a database row into an enriched alert dictionary."""
    d = dict(row)
    try:
        d["details"] = json.loads(d.get("details_json") or "{}")
    except Exception:
        d["details"] = {}
    if not d.get("dst_port"):
        d["dst_port"] = _extract_port(d.get("details")) or "-"
    d["status"] = d.get("status") or "new"
    d["client_name"] = d.get("client_name") or "Default"
    d["analyst_note"] = d.get("analyst_note") or ""
    attach_mitre_info(d)
    return d


def get_alerts(
    rule: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    status: str | None = None,
    client_name: str | None = None,
    search: str | None = None,
    limit: int = 200,
    offset: int = 0,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve filtered alerts."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            query = "SELECT * FROM alerts WHERE 1=1"
            params: list[Any] = []
            if rule:
                query += " AND rule = %s"
                params.append(rule)
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            if src_ip:
                query += " AND src_ip = %s"
                params.append(src_ip)
            if status:
                query += " AND status = %s"
                params.append(status)
            if client_name:
                query += " AND client_name = %s"
                params.append(client_name)
            if search:
                query += " AND (description LIKE %s OR src_ip LIKE %s OR dst_ip LIKE %s OR dst_port LIKE %s OR source_pcap LIKE %s OR client_name LIKE %s OR analyst_note LIKE %s)"
                term = f"%{search}%"
                params.extend([term, term, term, term, term, term, term])
            query += " ORDER BY id DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
            conn.close()

            return [_format_alert_dict(row) for row in rows]
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if rule:
        query += " AND rule = ?"
        params.append(rule)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if src_ip:
        query += " AND src_ip = ?"
        params.append(src_ip)
    if status:
        query += " AND status = ?"
        params.append(status)
    if client_name:
        query += " AND client_name = ?"
        params.append(client_name)
    if search:
        query += " AND (description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dst_port LIKE ? OR source_pcap LIKE ? OR client_name LIKE ? OR analyst_note LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term, term, term, term])
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        return [_format_alert_dict(row) for row in rows]


def get_alert_by_id(alert_id: int, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve a single alert by ID."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                row = cur.fetchone()
            conn.close()
            if not row:
                return None
            return _format_alert_dict(row)
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite
    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return _format_alert_dict(row)



def get_summary_stats(db_path: Path | str | None = None) -> dict[str, Any]:
    """Return summary counters: total alerts, counts by severity, counts by rule."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) as total FROM alerts")
                total = cur.fetchone()["total"]
                cur.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
                by_sev_rows = cur.fetchall()
                cur.execute("SELECT rule, COUNT(*) as cnt FROM alerts GROUP BY rule")
                by_rule_rows = cur.fetchall()
            conn.close()

            by_severity = {row["severity"]: row["cnt"] for row in by_sev_rows}
            by_rule = {row["rule"]: row["cnt"] for row in by_rule_rows}
            return {
                "engine": "MySQL (XAMPP)",
                "total": total,
                "high": by_severity.get("high", 0),
                "medium": by_severity.get("medium", 0),
                "low": by_severity.get("low", 0),
                "by_rule": by_rule,
            }
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite
    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity"
        ).fetchall()
        by_rule_rows = conn.execute(
            "SELECT rule, COUNT(*) as cnt FROM alerts GROUP BY rule"
        ).fetchall()

        by_severity = {row["severity"]: row["cnt"] for row in by_sev_rows}
        by_rule = {row["rule"]: row["cnt"] for row in by_rule_rows}

        return {
            "engine": "SQLite",
            "total": total,
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "by_rule": by_rule,
        }


def get_chart_data(db_path: Path | str | None = None) -> dict[str, Any]:
    """Return aggregated statistics formatted for frontend Chart.js rendering."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    rows: list[dict[str, Any]] = []
    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT detected_at, rule, severity, status, src_ip FROM alerts ORDER BY id ASC")
                raw = cur.fetchall()
            conn.close()
            rows = [dict(r) for r in raw]
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    if not rows and (engine == "sqlite" or ACTIVE_ENGINE == "sqlite"):
        with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
            cur = conn.execute("SELECT detected_at, rule, severity, status, src_ip FROM alerts ORDER BY id ASC")
            rows = [dict(r) for r in cur.fetchall()]

    # Timeline bucketed by hour (or date if spans days)
    time_counter: Counter[str] = Counter()
    for r in rows:
        ts = str(r.get("detected_at") or "").strip()
        if len(ts) >= 13:
            bucket = ts[:13].replace("T", " ") + ":00"
            if len(bucket) >= 16 and bucket[4] == "-":
                display_bucket = bucket[5:16]
            else:
                display_bucket = bucket
            time_counter[display_bucket] += 1
        elif ts:
            time_counter[ts] += 1

    timeline_labels = list(time_counter.keys())
    timeline_counts = [time_counter[k] for k in timeline_labels]

    # Top 5 source IPs
    ip_counter: Counter[str] = Counter()
    for r in rows:
        ip = str(r.get("src_ip") or "").strip()
        if ip:
            ip_counter[ip] += 1
    top_ips = ip_counter.most_common(5)
    top_sources_labels = [item[0] for item in top_ips]
    top_sources_counts = [item[1] for item in top_ips]

    # Detections by Rule
    rule_counter: Counter[str] = Counter()
    for r in rows:
        rl = str(r.get("rule") or "").strip()
        if rl:
            rule_counter[rl] += 1
    rules_sorted = rule_counter.most_common()
    by_rule_labels = [item[0] for item in rules_sorted]
    by_rule_counts = [item[1] for item in rules_sorted]

    # By Severity
    sev_counter: Counter[str] = Counter()
    for r in rows:
        sev = str(r.get("severity") or "").lower().strip()
        if sev:
            sev_counter[sev] += 1
    by_severity = {
        "labels": ["High", "Medium", "Low"],
        "counts": [sev_counter.get("high", 0), sev_counter.get("medium", 0), sev_counter.get("low", 0)],
    }

    # By Triage Status
    status_counter: Counter[str] = Counter()
    for r in rows:
        st = str(r.get("status") or "new").lower().strip()
        status_counter[st] += 1
    by_status = {
        "labels": ["New", "Investigating", "Resolved", "False Positive"],
        "counts": [
            status_counter.get("new", 0),
            status_counter.get("investigating", 0),
            status_counter.get("resolved", 0),
            status_counter.get("false_positive", 0),
        ],
    }

    return {
        "timeline": {"labels": timeline_labels, "counts": timeline_counts},
        "top_sources": {"labels": top_sources_labels, "counts": top_sources_counts},
        "by_rule": {"labels": by_rule_labels, "counts": by_rule_counts},
        "by_severity": by_severity,
        "by_status": by_status,
        "total": len(rows),
    }


def clear_alerts(db_path: Path | str | None = None) -> None:
    """Clear all stored alerts."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("TRUNCATE TABLE alerts;")
            conn.close()
            return
        except Exception as exc:
            logger.warning("MySQL clear_alerts failed (%s); clearing SQLite", exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute("DELETE FROM alerts;")
        conn.commit()


def migrate_sqlite_to_mysql(sqlite_path: Path | str | None = None) -> int:
    """Migrate all alerts from SQLite database into XAMPP MySQL database."""
    init_db()  # Ensures MySQL table exists
    alerts = get_alerts(db_path=sqlite_path or DEFAULT_SQLITE_PATH, limit=10000)
    if not alerts:
        return 0

    count = 0
    mysql_conn = get_mysql_connection()
    with mysql_conn.cursor() as cur:
        for a in alerts:
            cur.execute(
                """
                INSERT INTO alerts (
                    id, detected_at, packet_time, rule, severity, src_ip, dst_ip,
                    protocol, description, evidence_file, source_pcap, packet_count, details_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE description=VALUES(description)
                """,
                (
                    a["id"],
                    a["detected_at"],
                    a["packet_time"],
                    a["rule"],
                    a["severity"],
                    a["src_ip"],
                    a["dst_ip"],
                    a["protocol"],
                    a["description"],
                    a["evidence_file"],
                    a["source_pcap"],
                    a["packet_count"],
                    json.dumps(a.get("details", {})),
                ),
            )
            count += 1
    mysql_conn.close()
    return count
