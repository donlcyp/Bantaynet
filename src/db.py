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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
                try:
                    cur.execute("ALTER TABLE alerts ADD COLUMN dst_port VARCHAR(64);")
                except Exception:
                    pass
            conn.close()
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
                details_json TEXT
            );
            """
        )
        try:
            conn.execute("ALTER TABLE alerts ADD COLUMN dst_port TEXT;")
        except Exception:
            pass
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
        conn.commit()
    return "sqlite"


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
                        protocol, description, evidence_file, source_pcap, packet_count, details_json
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                protocol, description, evidence_file, source_pcap, packet_count, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)



def get_alerts(
    rule: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
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
            if search:
                query += " AND (description LIKE %s OR src_ip LIKE %s OR dst_ip LIKE %s OR dst_port LIKE %s OR source_pcap LIKE %s)"
                term = f"%{search}%"
                params.extend([term, term, term, term, term])
            query += " ORDER BY id DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
            conn.close()

            alerts = []
            for row in rows:
                d = dict(row)
                try:
                    d["details"] = json.loads(d.get("details_json") or "{}")
                except Exception:
                    d["details"] = {}
                if not d.get("dst_port"):
                    d["dst_port"] = _extract_port(d.get("details")) or "-"
                alerts.append(d)
            return alerts
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
    if search:
        query += " AND (description LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR dst_port LIKE ? OR source_pcap LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term, term])
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        alerts = []
        for row in rows:
            d = dict(row)
            try:
                d["details"] = json.loads(d.get("details_json") or "{}")
            except Exception:
                d["details"] = {}
            if not d.get("dst_port"):
                d["dst_port"] = _extract_port(d.get("details")) or "-"
            alerts.append(d)
        return alerts


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
            d = dict(row)
            try:
                d["details"] = json.loads(d.get("details_json") or "{}")
            except Exception:
                d["details"] = {}
            if not d.get("dst_port"):
                d["dst_port"] = _extract_port(d.get("details")) or "-"
            return d
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    # SQLite
    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["details"] = json.loads(d.get("details_json") or "{}")
        except Exception:
            d["details"] = {}
        if not d.get("dst_port"):
            d["dst_port"] = _extract_port(d.get("details")) or "-"
        return d



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
