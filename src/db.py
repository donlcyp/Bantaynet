"""Database persistence layer for BantayNet alerts.

Supports both XAMPP MySQL/MariaDB and SQLite with seamless fallback:
- When configured for MySQL, connects to XAMPP MariaDB/MySQL (port 3306).
- If MySQL is unreachable (e.g. XAMPP stopped), gracefully falls back to local SQLite.
- Fully parameterized queries across both database engines.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.mitre import attach_mitre_info
from src.security import EMAIL_REGEX
from werkzeug.security import check_password_hash, generate_password_hash

# Automatically load environment variables from .env if present
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass

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
    import os

    if db_path is not None:
        return "sqlite", {"path": Path(db_path)}

    if ACTIVE_ENGINE == "sqlite":
        return "sqlite", {"path": DB_PATH}

    supabase_dsn = (os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL") or "").strip()
    if supabase_dsn:
        return "mysql", {"dsn": supabase_dsn, "is_postgres": True}

    try:
        from src.config import load_config
        cfg = load_config()
        if cfg.database.engine in ("postgres", "postgresql", "supabase"):
            dsn = cfg.database.mysql.get("dsn") or supabase_dsn
            return "mysql", {"dsn": dsn, "is_postgres": True}
        elif cfg.database.engine == "mysql":
            mysql_conf = dict(cfg.database.mysql)
            mysql_conf["host"] = os.environ.get("MYSQL_HOST") or os.environ.get("MYSQLHOST") or mysql_conf.get("host", "127.0.0.1")
            mysql_conf["port"] = int(os.environ.get("MYSQL_PORT") or os.environ.get("MYSQLPORT") or mysql_conf.get("port", 3306))
            mysql_conf["user"] = os.environ.get("MYSQL_USER") or os.environ.get("MYSQLUSER") or mysql_conf.get("user", "root")
            if "MYSQL_PASSWORD" in os.environ or "MYSQLPASSWORD" in os.environ:
                mysql_conf["password"] = os.environ.get("MYSQL_PASSWORD") or os.environ.get("MYSQLPASSWORD") or ""
            mysql_conf["database"] = os.environ.get("MYSQL_DATABASE") or os.environ.get("MYSQLDATABASE") or mysql_conf.get("database", "bantaynet_db")
            return "mysql", mysql_conf
        else:
            return "sqlite", {"path": PROJECT_ROOT / cfg.database.sqlite.get("path", "bantaynet.db")}
    except Exception:
        return "mysql", DEFAULT_MYSQL_CONFIG


class _PostgresCursorWrapper:
    """Adapter around psycopg2 RealDictCursor providing PyMySQL DictCursor compatibility (including lastrowid)."""

    def __init__(self, raw_cursor: Any) -> None:
        self._cur = raw_cursor
        self.lastrowid: int = 0

    def execute(self, sql: str, params: Any = None) -> Any:
        stripped = sql.strip().rstrip(";")
        upper = stripped.upper()
        is_insert_returning = upper.startswith("INSERT INTO") and "RETURNING" not in upper and "ON CONFLICT" not in upper
        if is_insert_returning:
            stripped = f"{stripped} RETURNING id"
        res = self._cur.execute(stripped, params)
        if is_insert_returning:
            row = self._cur.fetchone()
            if row and "id" in row:
                self.lastrowid = int(row["id"])
        return res

    def fetchone(self) -> dict[str, Any] | None:
        row = self._cur.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._cur.fetchall()]

    def __enter__(self) -> "_PostgresCursorWrapper":
        self._cur.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self._cur.__exit__(exc_type, exc_val, exc_tb)


class _PostgresConnectionWrapper:
    """Adapter around psycopg2 connection matching PyMySQL's cursor context manager."""

    def __init__(self, raw_conn: Any, cursor_factory: Any) -> None:
        self._conn = raw_conn
        self._cursor_factory = cursor_factory

    def cursor(self) -> _PostgresCursorWrapper:
        return _PostgresCursorWrapper(self._conn.cursor(cursor_factory=self._cursor_factory))

    def close(self) -> None:
        self._conn.close()


def get_postgres_connection(dsn: str) -> _PostgresConnectionWrapper:
    """Connect to Supabase / PostgreSQL using a connection URI (SUPABASE_DB_URL / DATABASE_URL)."""
    import psycopg2
    import psycopg2.extras

    if not dsn:
        raise ValueError("PostgreSQL / Supabase connection URL (SUPABASE_DB_URL) is empty")
    raw_conn = psycopg2.connect(dsn, connect_timeout=5)
    raw_conn.autocommit = True
    return _PostgresConnectionWrapper(raw_conn, psycopg2.extras.RealDictCursor)


def get_mysql_connection(config: dict[str, Any] | None = None):
    c = config or DEFAULT_MYSQL_CONFIG
    if c.get("is_postgres") or c.get("dsn"):
        return get_postgres_connection(str(c.get("dsn") or ""))

    import pymysql
    import pymysql.cursors

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
    if engine == "mysql" and conf.get("is_postgres"):
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS alerts (
                        id SERIAL PRIMARY KEY,
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
                        status VARCHAR(32) DEFAULT 'new',
                        analyst_note TEXT,
                        updated_at VARCHAR(64),
                        client_name VARCHAR(128) DEFAULT 'Default'
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(64) NOT NULL UNIQUE,
                        email VARCHAR(128) UNIQUE,
                        password_hash VARCHAR(256) NOT NULL,
                        role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                        created_at VARCHAR(64) NOT NULL,
                        is_2fa_enabled INT DEFAULT 0,
                        backup_codes TEXT,
                        must_change_password INT DEFAULT 0
                    );
                    """
                )
                try:
                    cur.execute("ALTER TABLE users ADD COLUMN email VARCHAR(128) UNIQUE;")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE users ADD COLUMN is_2fa_enabled INT DEFAULT 0;")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT;")
                except Exception:
                    pass
                try:
                    cur.execute("ALTER TABLE users ADD COLUMN must_change_password INT DEFAULT 0;")
                except Exception:
                    pass
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id SERIAL PRIMARY KEY,
                        timestamp VARCHAR(64) NOT NULL,
                        username VARCHAR(64) NOT NULL,
                        action VARCHAR(64) NOT NULL,
                        target VARCHAR(256),
                        details TEXT
                    );
                    """
                )
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")
            conn.close()
            _seed_default_users("mysql", conf)
            return "postgres"
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    elif engine == "mysql":
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
                        email VARCHAR(128) UNIQUE,
                        password_hash VARCHAR(256) NOT NULL,
                        role VARCHAR(32) NOT NULL DEFAULT 'viewer',
                        created_at VARCHAR(64) NOT NULL,
                        is_2fa_enabled INT DEFAULT 0,
                        backup_codes TEXT,
                        must_change_password INT DEFAULT 0,
                        INDEX idx_users_username (username),
                        INDEX idx_users_email (email)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                    """
                )
                for col_sql in [
                    "ALTER TABLE users ADD COLUMN email VARCHAR(128) UNIQUE;",
                    "ALTER TABLE users ADD COLUMN is_2fa_enabled INT DEFAULT 0;",
                    "ALTER TABLE users ADD COLUMN backup_codes TEXT;",
                    "ALTER TABLE users ADD COLUMN must_change_password INT DEFAULT 0;",
                ]:
                    try:
                        cur.execute(col_sql)
                    except Exception:
                        pass
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        timestamp VARCHAR(64) NOT NULL,
                        username VARCHAR(64) NOT NULL,
                        action VARCHAR(64) NOT NULL,
                        target VARCHAR(256),
                        details TEXT,
                        INDEX idx_audit_time (timestamp),
                        INDEX idx_audit_user (username),
                        INDEX idx_audit_action (action)
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
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_at TEXT NOT NULL,
                is_2fa_enabled INTEGER DEFAULT 0,
                backup_codes TEXT,
                must_change_password INTEGER DEFAULT 0
            );
            """
        )
        existing_user_cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "email" not in existing_user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN email TEXT;")
        if "is_2fa_enabled" not in existing_user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_2fa_enabled INTEGER DEFAULT 0;")
        if "backup_codes" not in existing_user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT;")
        if "must_change_password" not in existing_user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                details TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(username);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);")
        conn.commit()

    _seed_default_users("sqlite", conf)
    return "sqlite"


VALID_ROLES = ("admin", "analyst", "viewer")


def _get_static_test_accounts() -> dict[str, dict[str, Any]]:
    """In-memory test accounts available for testing without touching the database."""
    import os
    admin_pwd = os.environ.get("BANTAYNET_ADMIN_PASSWORD") or "admin123!"
    analyst_pwd = os.environ.get("BANTAYNET_ANALYST_PASSWORD") or "analyst123!"
    viewer_pwd = os.environ.get("BANTAYNET_VIEWER_PASSWORD") or "viewer123!"

    return {
        "admin": {
            "id": -1,
            "username": "admin",
            "email": "admin@bantaynet.local",
            "password": admin_pwd,
            "role": "admin",
            "created_at": "2026-01-01T00:00:00Z",
            "is_virtual": True,
            "is_2fa_enabled": False,
            "backup_codes": "",
            "must_change_password": False,
        },
        "analyst": {
            "id": -2,
            "username": "analyst",
            "email": "analyst@bantaynet.local",
            "password": analyst_pwd,
            "role": "analyst",
            "created_at": "2026-01-01T00:00:00Z",
            "is_virtual": True,
            "is_2fa_enabled": False,
            "backup_codes": "",
            "must_change_password": False,
        },
        "viewer": {
            "id": -3,
            "username": "viewer",
            "email": "viewer@bantaynet.local",
            "password": viewer_pwd,
            "role": "viewer",
            "created_at": "2026-01-01T00:00:00Z",
            "is_virtual": True,
            "is_2fa_enabled": False,
            "backup_codes": "",
            "must_change_password": False,
        },
    }


def is_default_admin_password_active(db_path: Path | str | None = None) -> bool:
    """Return True if the 'admin' account still uses the known default password 'admin123!'."""
    try:
        user = authenticate_user("admin", "admin123!", db_path=db_path)
        return user is not None
    except Exception:
        return False


def _seed_default_users(engine: str, conf: dict[str, Any]) -> None:
    """Default accounts are no longer saved to external databases (handled in-memory / purely in DB for new accounts)."""
    return


def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate cryptographically secure single-use emergency backup codes."""
    import secrets
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(4).upper()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def create_user(
    username: str,
    password: str,
    role: str = "viewer",
    email: str | None = None,
    must_change_password: bool = True,
    is_2fa_enabled: bool = False,
    backup_codes: list[str] | str | None = None,
    db_path: Path | str | None = None,
) -> int:
    """Create a new user with hashed credentials. Raises ValueError if invalid."""
    # Defensive support for legacy callers passing db_path as 4th or 5th positional argument
    if isinstance(email, Path) or (isinstance(email, str) and ("/" in email or "\\" in email or email.endswith(".db"))):
        db_path = email
        email = None
    if isinstance(must_change_password, (Path, str)) and (isinstance(must_change_password, Path) or "/" in str(must_change_password) or "\\" in str(must_change_password) or str(must_change_password).endswith(".db")):
        db_path = must_change_password
        must_change_password = True

    username = (username or "").strip().lower()
    if not username:
        raise ValueError("Username cannot be empty")
    role = (role or "viewer").strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role '{role}'. Must be one of {VALID_ROLES}")
    if not password:
        raise ValueError("Password cannot be empty")

    clean_email: str | None = None
    if email is not None and str(email).strip():
        clean_email = str(email).strip().lower()
        if len(clean_email) > 128 or not EMAIL_REGEX.match(clean_email):
            raise ValueError(f"Invalid email address format: '{email}'")

    # Guard: prevent colliding with in-memory virtual test accounts
    static_accounts = _get_static_test_accounts()
    if username in static_accounts:
        raise ValueError(f"Username '{username}' already exists (reserved system account)")

    if clean_email:
        for v in static_accounts.values():
            if v.get("email", "").lower() == clean_email:
                raise ValueError(f"Email '{clean_email}' already exists (reserved system account)")

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)
    pwd_hash = generate_password_hash(password)
    now_str = datetime.now(timezone.utc).isoformat()
    codes_str = ",".join(backup_codes) if isinstance(backup_codes, list) else (backup_codes or "")
    mcp_val = 1 if must_change_password else 0
    tfa_val = 1 if is_2fa_enabled else 0

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE LOWER(username) = %s", (username,))
                if cur.fetchone():
                    raise ValueError(f"Username '{username}' already exists")
                if clean_email:
                    cur.execute("SELECT id FROM users WHERE LOWER(email) = %s", (clean_email,))
                    if cur.fetchone():
                        raise ValueError(f"Email '{clean_email}' already exists")
                cur.execute(
                    "INSERT INTO users (username, email, password_hash, role, created_at, is_2fa_enabled, backup_codes, must_change_password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (username, clean_email, pwd_hash, role, now_str, tfa_val, codes_str, mcp_val),
                )
                last_id = cur.lastrowid
            conn.close()
            return int(last_id)
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            err_str = str(exc).lower()
            if "unique" in err_str or "duplicate" in err_str or "already exists" in err_str:
                if "email" in err_str:
                    raise ValueError(f"Email '{clean_email}' already exists") from exc
                raise ValueError(f"Username '{username}' already exists") from exc
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        existing = conn.execute("SELECT id FROM users WHERE LOWER(username) = ?", (username,)).fetchone()
        if existing:
            raise ValueError(f"Username '{username}' already exists")
        if clean_email:
            existing_email = conn.execute("SELECT id FROM users WHERE LOWER(email) = ?", (clean_email,)).fetchone()
            if existing_email:
                raise ValueError(f"Email '{clean_email}' already exists")
        try:
            cursor = conn.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at, is_2fa_enabled, backup_codes, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (username, clean_email, pwd_hash, role, now_str, tfa_val, codes_str, mcp_val),
            )
            conn.commit()
            return int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            if "email" in str(exc).lower():
                raise ValueError(f"Email '{clean_email}' already exists") from exc
            raise ValueError(f"Username '{username}' already exists") from exc


def _normalize_user_dict(d: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalize user dictionary fields ensuring consistent boolean and string representations."""
    if not d:
        return None
    res = dict(d)
    res.pop("password_hash", None)
    res.pop("password", None)
    res["is_2fa_enabled"] = bool(res.get("is_2fa_enabled"))
    res["must_change_password"] = bool(res.get("must_change_password"))
    res["backup_codes"] = res.get("backup_codes") or ""
    return res


def authenticate_user(
    identifier: str,
    password: str,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    """Validate username or email alongside password (hybrid login). Returns user dict without password_hash."""
    identifier = (identifier or "").strip().lower()
    if not identifier or not password:
        return None

    # 1. First check if real database contains this account by username OR email
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    user_row = None
    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM users WHERE LOWER(username) = %s OR LOWER(COALESCE(email, '')) = %s",
                    (identifier, identifier),
                )
                user_row = cur.fetchone()
            conn.close()
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    if user_row is None and (engine == "sqlite" or ACTIVE_ENGINE == "sqlite"):
        with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(COALESCE(email, '')) = ?",
                (identifier, identifier),
            ).fetchone()
            if row:
                user_row = dict(row)

    if user_row:
        stored_hash = user_row.get("password_hash") or ""
        if check_password_hash(stored_hash, password):
            return _normalize_user_dict(user_row)
        return None

    # 2. In-memory virtual test account check (matches username or email)
    static_users = _get_static_test_accounts()
    for target in static_users.values():
        if target["username"].lower() == identifier or target.get("email", "").lower() == identifier:
            # Match against either plaintext env password or hashed equivalent
            if password == target["password"] or check_password_hash(generate_password_hash(target["password"]), password):
                return _normalize_user_dict(target)

    return None


def get_user_by_id(user_id: int, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve user by ID without password_hash."""
    # Check in-memory virtual test accounts
    for target in _get_static_test_accounts().values():
        if target["id"] == user_id:
            return _normalize_user_dict(target)

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE id = %s", (user_id,))
                row = cur.fetchone()
            conn.close()
            return _normalize_user_dict(dict(row)) if row else None
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        row = conn.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE id = ?", (user_id,)).fetchone()
        return _normalize_user_dict(dict(row)) if row else None


def get_user_by_username(username: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve user by username without password_hash (case-insensitive)."""
    username = (username or "").strip().lower()
    if not username:
        return None

    # Check in-memory virtual test accounts
    static_users = _get_static_test_accounts()
    if username in static_users:
        return _normalize_user_dict(static_users[username])

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE LOWER(username) = %s", (username,))
                row = cur.fetchone()
            conn.close()
            return _normalize_user_dict(dict(row)) if row else None
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        row = conn.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE LOWER(username) = ?", (username,)).fetchone()
        return _normalize_user_dict(dict(row)) if row else None


def get_user_by_email(email: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Retrieve user by email without password_hash (case-insensitive)."""
    email = (email or "").strip().lower()
    if not email:
        return None

    # Check in-memory virtual test accounts
    for target in _get_static_test_accounts().values():
        if target.get("email", "").lower() == email:
            return _normalize_user_dict(target)

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE LOWER(email) = %s", (email,))
                row = cur.fetchone()
            conn.close()
            return _normalize_user_dict(dict(row)) if row else None
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        row = conn.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
        return _normalize_user_dict(dict(row)) if row else None


def get_all_users(db_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Retrieve all users without password_hash ordered by ID. Database users take precedence; virtual accounts are included for display if not in DB."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    db_rows: list[dict[str, Any]] = []
    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users ORDER BY id ASC")
                db_rows = [_normalize_user_dict(dict(r)) for r in cur.fetchall()]  # type: ignore[misc]
            conn.close()
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    if not db_rows and (engine == "sqlite" or ACTIVE_ENGINE == "sqlite"):
        with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
            db_rows = [_normalize_user_dict(dict(r)) for r in conn.execute("SELECT id, username, email, role, created_at, is_2fa_enabled, backup_codes, must_change_password FROM users ORDER BY id ASC").fetchall()]  # type: ignore[misc]

    existing_usernames = {r["username"] for r in db_rows if r}
    # Append virtual test accounts only if not already registered in DB
    result = [r for r in db_rows if r]
    for v in _get_static_test_accounts().values():
        if v["username"] not in existing_usernames:
            norm_v = _normalize_user_dict(v)
            if norm_v:
                result.append(norm_v)

    return result


def update_user_password(
    user_id: int,
    new_password: str,
    must_change_password: bool = False,
    db_path: Path | str | None = None,
) -> bool:
    """Update password hash and mandatory password change flag."""
    if not new_password:
        raise ValueError("Password cannot be empty")
    pwd_hash = generate_password_hash(new_password)
    must_change_val = 1 if must_change_password else 0

    if user_id in (-1, -2, -3):
        for target in _get_static_test_accounts().values():
            if target["id"] == user_id:
                target["password"] = new_password
                target["must_change_password"] = must_change_password
                return True
        return True

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET password_hash = %s, must_change_password = %s WHERE id = %s",
                    (pwd_hash, must_change_val, user_id),
                )
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ? WHERE id = ?",
            (pwd_hash, must_change_val, user_id),
        )
        conn.commit()
    return True


def toggle_user_2fa(
    user_id: int,
    enabled: bool,
    backup_codes: list[str] | str | None = None,
    db_path: Path | str | None = None,
) -> bool:
    """Enable or disable 2FA for a user and optionally store emergency backup codes."""
    enabled_val = 1 if enabled else 0
    codes_str = ",".join(backup_codes) if isinstance(backup_codes, list) else (backup_codes or "")

    if user_id in (-1, -2, -3):
        for target in _get_static_test_accounts().values():
            if target["id"] == user_id:
                target["is_2fa_enabled"] = enabled
                if backup_codes is not None:
                    target["backup_codes"] = codes_str
                return True
        return True

    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                if backup_codes is not None:
                    cur.execute(
                        "UPDATE users SET is_2fa_enabled = %s, backup_codes = %s WHERE id = %s",
                        (enabled_val, codes_str, user_id),
                    )
                else:
                    cur.execute(
                        "UPDATE users SET is_2fa_enabled = %s WHERE id = %s",
                        (enabled_val, user_id),
                    )
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        if backup_codes is not None:
            conn.execute(
                "UPDATE users SET is_2fa_enabled = ?, backup_codes = ? WHERE id = ?",
                (enabled_val, codes_str, user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET is_2fa_enabled = ? WHERE id = ?",
                (enabled_val, user_id),
            )
        conn.commit()
    return True


def consume_backup_code(
    user_id: int,
    code: str,
    db_path: Path | str | None = None,
) -> bool:
    """Verify and consume a single-use emergency backup code."""
    code = (code or "").strip().upper()
    if not code:
        return False

    user = get_user_by_id(user_id, db_path=db_path)
    if not user:
        return False

    raw_codes = user.get("backup_codes") or ""
    existing_list = [c.strip().upper() for c in re.split(r"[\n,]+", raw_codes) if c.strip()]
    if code not in existing_list:
        return False

    existing_list.remove(code)
    new_codes_str = ",".join(existing_list)
    toggle_user_2fa(user_id, enabled=True, backup_codes=new_codes_str, db_path=db_path)
    return True
    for v in _get_static_test_accounts().values():
        if v["username"] not in existing_usernames:
            v_copy = dict(v)
            v_copy.pop("password", None)
            result.append(v_copy)

    return result


def update_user_role(user_id: int, role: str, db_path: Path | str | None = None) -> bool:
    """Update role for a user."""
    if user_id in (-1, -2, -3):
        return True

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
    if user_id in (-1, -2, -3):
        raise ValueError("Virtual test account cannot be deleted from database")

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


def log_audit_event(
    username: str,
    action: str,
    target: str = "",
    details: str = "",
    timestamp: str | None = None,
    db_path: Path | str | None = None,
) -> int:
    """Record an audit trail event."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    username = (username or "anonymous").strip()
    action = (action or "").strip()
    target = (target or "").strip()[:256]

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO audit_logs (timestamp, username, action, target, details) VALUES (%s, %s, %s, %s, %s)",
                    (timestamp, username, action, target, details),
                )
                last_id = cur.lastrowid
            conn.close()
            return int(last_id)
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        cursor = conn.execute(
            "INSERT INTO audit_logs (timestamp, username, action, target, details) VALUES (?, ?, ?, ?, ?)",
            (timestamp, username, action, target, details),
        )
        conn.commit()
        return int(cursor.lastrowid)


def get_audit_logs(
    limit: int = 200,
    action: str | None = None,
    username: str | None = None,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve recent audit logs in descending chronological order."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params: list[Any] = []
    if action:
        query += " AND action = %s" if engine == "mysql" else " AND action = ?"
        params.append(action)
    if username:
        query += " AND username = %s" if engine == "mysql" else " AND username = ?"
        params.append(username)
    query += " ORDER BY id DESC LIMIT %s" if engine == "mysql" else " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


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
    d["evidence_sha256"] = d.get("evidence_sha256") or d["details"].get("evidence_sha256")
    d["source_pcap_sha256"] = d.get("source_pcap_sha256") or d["details"].get("source_pcap_sha256")
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


def delete_alert(alert_id: int, db_path: Path | str | None = None) -> bool:
    """Delete a single alert record by ID."""
    init_db(db_path)
    engine, conf = _get_active_engine(db_path)

    if engine == "mysql":
        try:
            conn = get_mysql_connection(conf)
            with conn.cursor() as cur:
                cur.execute("DELETE FROM alerts WHERE id = %s", (alert_id,))
            conn.close()
            return True
        except Exception as exc:
            _mark_sqlite_fallback(exc)

    with get_sqlite_connection(conf.get("path", DEFAULT_SQLITE_PATH)) as conn:
        conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
        conn.commit()
    return True


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


def check_db_connection() -> dict[str, Any]:
    """Inspect and test the active database connection, returning diagnostic status."""
    engine, conf = _get_active_engine()
    is_postgres = conf.get("is_postgres", False)

    label = (
        "Supabase (PostgreSQL)"
        if (engine == "mysql" and is_postgres)
        else ("MySQL (XAMPP)" if engine == "mysql" else "SQLite Fallback")
    )

    info: dict[str, Any] = {
        "configured_engine": engine,
        "is_postgres": is_postgres,
        "engine_label": label,
        "connected": False,
        "active_engine": None,
        "error": None,
        "alert_count": 0,
        "user_count": 0,
    }

    try:
        active = init_db()
        info["connected"] = True
        info["active_engine"] = active
        stats = get_summary_stats()
        info["alert_count"] = stats.get("total", 0)
        users = get_all_users()
        info["user_count"] = len(users)
    except Exception as exc:
        info["error"] = str(exc)

    return info


if __name__ == "__main__":
    import sys

    print("=" * 60)
    print(" BantayNet Database Connection Diagnostic")
    print("=" * 60)

    status = check_db_connection()
    supabase_configured = bool((os.environ.get("SUPABASE_DB_URL") or os.environ.get("DATABASE_URL") or "").strip())

    print(f"Target Engine:     {status['engine_label']}")
    print(f"Active Engine:     {status['active_engine'] or 'None'}")
    print(f"Connection Status: {'Connected (OK)' if status['connected'] else 'Failed'}")
    print(f"Alerts in DB:      {status['alert_count']}")
    print(f"Users in DB:       {status['user_count']}")

    if status["is_postgres"] and status["connected"]:
        print("\n[+] SUCCESS: BantayNet is actively connected to Supabase PostgreSQL!")
        sys.exit(0)
    else:
        print("\n[-] NOTICE: BantayNet is currently NOT connected to Supabase.")
        if not supabase_configured:
            print("    Reason: 'SUPABASE_DB_URL' is not set or is commented out in your .env file.")
            print("    Current Fallback: Operating safely on local " + (status['active_engine'] or 'SQLite') + ".")
            print("\nTo connect to Supabase:")
            print("  1. In Supabase Dashboard -> Project Settings -> Database -> Connection string (URI)")
            print("  2. In your .env file, uncomment and set:")
            print("     SUPABASE_DB_URL=postgresql://postgres.[project-ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres")
        else:
            print(f"    Connection Attempt Error: {status.get('error')}")
        sys.exit(0)
