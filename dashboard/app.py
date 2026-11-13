"""Flask web dashboard for BantayNet suspicious activity detection system."""

from __future__ import annotations

import hmac
import io
import os
import re
import secrets
import sys
import time
import uuid
from collections import defaultdict
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Automatically load environment variables from .env if present
try:
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from src.analyze import analyze
from src.config import ConfigError, DEFAULT_RULES_PATH, load_config, save_rules_config
from src.evidence import calculate_sha256
from src.db import (
    authenticate_user,
    clear_alerts,
    consume_backup_code,
    create_user,
    delete_alert,
    delete_user,
    generate_backup_codes,
    get_alert_by_id,
    get_alerts,
    get_all_users,
    get_audit_logs,
    get_chart_data,
    get_summary_stats,
    get_user_by_email,
    get_user_by_id,
    get_user_by_username,
    init_db,
    is_default_admin_password_active,
    log_audit_event,
    toggle_user_2fa,
    update_user_password,
    update_user_role,
)
from src.export import write_alerts_csv
from src.notifier import send_2fa_otp_email, send_account_created_email
from src.report_pdf import generate_alert_pdf, generate_summary_pdf
from src.security import validate_email_standards, validate_password_standards, validate_username_standards
from src.store import store_alerts

DEFAULT_INITIAL_PASSWORD = "ChangeMe2026!Temp"

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "dashboard" / "templates"),
    static_folder=str(PROJECT_ROOT / "dashboard" / "static"),
)

# Deployment & Session Security Configurations
app.secret_key = os.environ.get("BANTAYNET_SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("BANTAYNET_SECRET_KEY") and not app.config.get("TESTING"):
    app.logger.warning(
        "SECURITY WARNING: BANTAYNET_SECRET_KEY environment variable is not set! "
        "A temporary random secret key was generated. Operator sessions will not survive server restarts. "
        "Please configure BANTAYNET_SECRET_KEY before deploying to production."
    )

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("BANTAYNET_COOKIE_SECURE") == "1":
    app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(
    hours=int(os.environ.get("BANTAYNET_SESSION_HOURS", 8))
)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB maximum upload
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
PCAP_MAGIC_NUMBERS = (
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG section header block
)

UPLOAD_DIR = PROJECT_ROOT / "pcaps" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# Inactivity auto-logout timeout window (default: 15 minutes, configurable via BANTAYNET_INACTIVITY_MINUTES)
INACTIVITY_TIMEOUT_SECONDS = int(os.environ.get("BANTAYNET_INACTIVITY_MINUTES", 15)) * 60


def generate_csrf_token() -> str:
    """Generate or retrieve a cryptographically secure CSRF token for the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.before_request
def security_and_auth_middleware():
    init_db()

    # 1. CSRF Verification for state-changing HTTP methods
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if not (app.config.get("TESTING") and not app.config.get("FORCE_CSRF_TESTING")):
            token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            expected = session.get("csrf_token")
            if not token or not expected or not hmac.compare_digest(str(token), str(expected)):
                app.logger.warning(
                    f"CSRF protection triggered: missing or invalid token for {request.path} from IP {request.remote_addr}"
                )
                abort(403, description="CSRF security validation failed: missing or invalid security token.")

    # 2. Inactivity Session Timeout Enforcement
    user_id = session.get("user_id")
    if user_id is not None and not (app.config.get("TESTING") and not app.config.get("FORCE_AUTH_TESTING")):
        last_activity = session.get("last_activity")
        now_ts = time.time()
        if last_activity and (now_ts - last_activity > INACTIVITY_TIMEOUT_SECONDS):
            expired_user = get_user_by_id(user_id)
            uname = expired_user.get("username", "operator") if expired_user else "operator"
            session.clear()
            log_audit_event(uname, "session_timeout", "Web Portal", f"Auto-logged out after {INACTIVITY_TIMEOUT_SECONDS // 60}m inactivity")
            flash("Session expired due to inactivity. For security, please sign in again.", "error")
            return redirect(url_for("login", next=request.url))
        session["last_activity"] = now_ts

    # 3. User Authentication Load
    if user_id is not None:
        g.current_user = get_user_by_id(user_id)
    elif app.config.get("TESTING") and not app.config.get("FORCE_AUTH_TESTING"):
        # Auto-mock user for legacy non-RBAC test fixtures
        g.current_user = {"id": 1, "username": "analyst", "role": "analyst"}
    else:
        g.current_user = None

    # 4. Mandatory First-Time Password Change Enforcement
    if user_id is not None and getattr(g, "current_user", None) and g.current_user.get("must_change_password"):
        allowed_endpoints = {"first_time_change_password", "logout", "static"}
        if request.endpoint not in allowed_endpoints:
            return redirect(url_for("first_time_change_password"))


@app.after_request
def apply_security_headers(response: Response) -> Response:
    """Inject OWASP recommended HTTP security headers."""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"

    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp

    if request.is_secure or os.environ.get("BANTAYNET_COOKIE_SECURE") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Browser caching optimization for static assets vs dynamic pages
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    elif "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"

    # HTTP payload compression (gzip) for text/css, html, json responses
    if not app.config.get("TESTING") and not response.direct_passthrough and "Content-Encoding" not in response.headers:
        accept_encoding = request.headers.get("Accept-Encoding", "")
        if "gzip" in accept_encoding.lower():
            content_type = response.content_type or ""
            if any(t in content_type for t in ("text/", "application/json", "application/javascript")):
                data = response.get_data()
                if len(data) >= 1024:
                    import gzip
                    response.set_data(gzip.compress(data, compresslevel=6))
                    response.headers["Content-Encoding"] = "gzip"
                    response.headers["Content-Length"] = len(response.get_data())

    response.headers.pop("Server", None)
    return response


@app.context_processor
def inject_global_data():
    from src.db import _get_active_engine, ACTIVE_ENGINE
    engine, conf = _get_active_engine()
    if engine == "mysql" and ACTIVE_ENGINE != "sqlite":
        engine_name = "Supabase (PostgreSQL)" if conf.get("is_postgres") else "MySQL (XAMPP)"
    else:
        engine_name = "SQLite Fallback"
    return {
        "db_engine_name": engine_name,
        "current_user": getattr(g, "current_user", None),
        "csrf_token": generate_csrf_token,
        "is_default_admin_pw": is_default_admin_password_active(),
        "session_inactivity_minutes": INACTIVITY_TIMEOUT_SECONDS // 60,
    }



def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if getattr(g, "current_user", None) is None:
            return redirect(url_for("login", next=request.url))
        return view(**kwargs)
    return wrapped_view


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            user = getattr(g, "current_user", None)
            if user is None:
                return redirect(url_for("login", next=request.url))
            if user.get("role") not in roles:
                roles_str = " or ".join(r.title() for r in roles)
                flash(f"Access restricted: this action requires {roles_str} role.", "error")
                return redirect(url_for("index"))
            return view(**kwargs)
        return wrapped_view
    return decorator


def is_allowed_file(filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    return ext in ALLOWED_EXTENSIONS


def is_valid_pcap_header(stream) -> bool:
    """Validate PCAP / PCAPNG magic numbers to prevent malicious non-pcap files from being accepted."""
    try:
        pos = stream.tell()
        magic = stream.read(4)
        stream.seek(pos)
        return any(magic == m for m in PCAP_MAGIC_NUMBERS)
    except Exception:
        return False


def is_safe_url(target: str) -> bool:
    """Ensure redirection target belongs strictly to the local host (prevents CWE-601 Open Redirect)."""
    if not target:
        return False
    ref_url = urlsplit(request.host_url)
    test_url = urlsplit(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# Rate limiting storage for login endpoint
_login_failures: dict[str, list[float]] = defaultdict(list)
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 300  # 5-minute lockout window


def is_login_rate_limited(ip: str, username: str) -> bool:
    """Check if IP or username has exceeded maximum failed authentication attempts."""
    now = time.time()
    for key in (ip, f"{ip}:{username.lower()}"):
        recent = [t for t in _login_failures[key] if now - t < LOGIN_LOCKOUT_SECONDS]
        _login_failures[key] = recent
        if len(recent) >= LOGIN_MAX_FAILURES:
            return True
    return False


def record_login_failure(ip: str, username: str):
    now = time.time()
    _login_failures[ip].append(now)
    _login_failures[f"{ip}:{username.lower()}"].append(now)


def clear_login_failures(ip: str, username: str):
    _login_failures.pop(ip, None)
    _login_failures.pop(f"{ip}:{username.lower()}", None)


def _resolve_evidence(stored: str | None) -> Path | None:
    """Turn a stored (project-relative or legacy absolute) evidence path into a real path."""
    if not stored:
        return None
    p = Path(stored)
    real_path = p if p.is_absolute() else PROJECT_ROOT / p
    try:
        resolved = real_path.resolve()
        # Path traversal guard: ensure target is within PROJECT_ROOT
        if not resolved.is_relative_to(PROJECT_ROOT.resolve()):
            return None
        return resolved
    except Exception:
        return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("index"))

    raw_next = request.args.get("next") or request.form.get("next") or url_for("index")
    next_url = raw_next if is_safe_url(raw_next) else url_for("index")

    if request.method == "POST":
        username = (request.form.get("username") or request.form.get("identifier") or "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        # 1. Error checking: Empty fields
        if not username or not password:
            flash("Authentication error: Please provide both username and password.", "error")
            return render_template("login.html", next=next_url), 400

        # 2. Error checking: Input bounds (prevent memory/buffer exhaustion)
        if len(username) > 128 or len(password) > 128:
            flash("Authentication error: Input exceeds allowed credential limits (max 128 username/email, 128 password).", "error")
            return render_template("login.html", next=next_url), 400

        # 3. Error checking: Rate limiting lockout check
        if is_login_rate_limited(client_ip, username):
            app.logger.warning(f"Login rate limit exceeded for '{username}' from {client_ip}")
            log_audit_event("system", "rate_limit_lockout", f"IP: {client_ip}", f"Account: {username}")
            failures = _login_failures.get(f"{client_ip}:{username.lower()}", []) or _login_failures.get(client_ip, [])
            remaining_sec = max(1, int(LOGIN_LOCKOUT_SECONDS - (time.time() - failures[0]))) if failures else LOGIN_LOCKOUT_SECONDS
            flash(
                f"Security Lockout: Too many failed attempts. For security, you are temporarily locked out. Please try again in {remaining_sec} seconds.",
                "error",
            )
            return render_template("login.html", next=next_url), 429

        user = authenticate_user(username, password)
        if user:
            clear_login_failures(client_ip, username)

            # Two-Step Login Experience: Step 2 2FA Check
            if user.get("is_2fa_enabled"):
                session.clear()
                otp = f"{secrets.randbelow(900000) + 100000}"
                session["2fa_pending_user_id"] = user["id"]
                session["2fa_pending_code"] = generate_password_hash(otp)
                session["2fa_pending_expires"] = time.time() + 600  # 10 minutes
                session["2fa_pending_next"] = next_url
                session["2fa_email"] = user.get("email") or ""
                session["2fa_username"] = user.get("username") or ""
                session["csrf_token"] = secrets.token_hex(32)

                if user.get("email"):
                    sent_ok, send_msg = send_2fa_otp_email(user["email"], otp, user["username"])
                    if sent_ok:
                        flash(f"Two-factor verification code dispatched to {user['email']}.", "info")
                    else:
                        flash(f"2FA email notice: {send_msg}. You may enter an emergency backup code if email delivery is delayed.", "warning")
                else:
                    flash("Two-Factor Authentication is active. Please enter your 6-digit code or emergency backup code.", "info")

                app.logger.warning(f"[2FA AUTH] Generated code for '{user['username']}': {otp}")
                return redirect(url_for("login_2fa"))

            # Single-factor login path
            session.clear()
            session["user_id"] = user["id"]
            session["last_activity"] = time.time()
            # Ensure fresh CSRF token upon privilege change
            session["csrf_token"] = secrets.token_hex(32)

            log_audit_event(user["username"], "login", "Web Portal", f"Role: {user['role']}")
            flash(f"Logged in successfully as {user['username']} ({user['role'].title()} role).", "success")

            if user.get("must_change_password"):
                return redirect(url_for("first_time_change_password"))
            return redirect(next_url)
        else:
            record_login_failure(client_ip, username)
            app.logger.warning(f"Failed authentication attempt for '{username}' from {client_ip}")
            log_audit_event("anonymous", "failed_login", f"IP: {client_ip}", f"Attempted identifier: {username}")
            flash("Authentication error: Invalid username or password. Please verify credentials.", "error")

    return render_template("login.html", next=next_url)



@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("index"))

    user_id = session.get("2fa_pending_user_id")
    expires = session.get("2fa_pending_expires", 0)
    if not user_id or time.time() > expires:
        session.pop("2fa_pending_user_id", None)
        flash("Your two-factor authentication session has expired. Please sign in again.", "error")
        return redirect(url_for("login"))

    pending_user = get_user_by_id(user_id)
    if not pending_user:
        session.clear()
        return redirect(url_for("login"))

    client_ip = request.remote_addr or "127.0.0.1"
    next_url = session.get("2fa_pending_next") or url_for("index")

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        # Brute-Force Guard: Strict rate limiting (max 5 failed attempts before 5-minute lockout)
        rate_key = f"2fa:{user_id}"
        if is_login_rate_limited(client_ip, rate_key):
            app.logger.warning(f"2FA rate limit exceeded for user #{user_id} from {client_ip}")
            log_audit_event("system", "2fa_rate_limit_lockout", f"IP: {client_ip}", f"User ID: {user_id}")
            failures = _login_failures.get(f"{client_ip}:{rate_key.lower()}", []) or _login_failures.get(client_ip, [])
            remaining_sec = max(1, int(LOGIN_LOCKOUT_SECONDS - (time.time() - failures[0]))) if failures else LOGIN_LOCKOUT_SECONDS
            flash(
                f"Security Lockout: Too many failed 2FA attempts. For security, you are temporarily locked out. Please try again in {remaining_sec} seconds.",
                "error",
            )
            return render_template("login_2fa.html", email=session.get("2fa_email"), username=session.get("2fa_username")), 429

        if not code:
            flash("Please enter your 6-digit authentication code or emergency backup code.", "error")
            return render_template("login_2fa.html", email=session.get("2fa_email"), username=session.get("2fa_username")), 400

        verified = False
        consumed_backup = False

        # 1. Check 6-digit OTP code
        stored_hash = session.get("2fa_pending_code", "")
        if stored_hash and check_password_hash(stored_hash, code):
            verified = True

        # 2. Check single-use emergency backup recovery code
        if not verified:
            if consume_backup_code(user_id, code):
                verified = True
                consumed_backup = True

        if verified:
            clear_login_failures(client_ip, rate_key)
            session.pop("2fa_pending_user_id", None)
            session.pop("2fa_pending_code", None)
            session.pop("2fa_pending_expires", None)
            session.pop("2fa_pending_next", None)
            session.pop("2fa_email", None)
            session.pop("2fa_username", None)

            session["user_id"] = pending_user["id"]
            session["last_activity"] = time.time()
            session["csrf_token"] = secrets.token_hex(32)

            backup_note = " (emergency backup code used)" if consumed_backup else ""
            log_audit_event(pending_user["username"], "login_2fa", "Web Portal", f"2FA verification successful{backup_note}")
            flash(f"Two-factor authentication verified successfully. Welcome, {pending_user['username']}!", "success")

            if pending_user.get("must_change_password"):
                return redirect(url_for("first_time_change_password"))
            return redirect(next_url)
        else:
            record_login_failure(client_ip, rate_key)
            app.logger.warning(f"Failed 2FA attempt for user #{user_id} from {client_ip}")
            log_audit_event("anonymous", "failed_2fa", f"IP: {client_ip}", f"User: {pending_user['username']}")
            flash("Authentication error: Invalid 6-digit verification code or emergency backup code.", "error")

    return render_template("login_2fa.html", email=session.get("2fa_email"), username=session.get("2fa_username"))


@app.route("/login/2fa/resend", methods=["POST"])
def login_2fa_resend():
    user_id = session.get("2fa_pending_user_id")
    expires = session.get("2fa_pending_expires", 0)
    if not user_id or time.time() > expires:
        flash("Your two-factor authentication session has expired. Please sign in again.", "error")
        return redirect(url_for("login"))

    pending_user = get_user_by_id(user_id)
    if not pending_user or not pending_user.get("email"):
        flash("Cannot resend code: no email address associated with account.", "error")
        return redirect(url_for("login_2fa"))

    otp = f"{secrets.randbelow(900000) + 100000}"
    session["2fa_pending_code"] = generate_password_hash(otp)
    session["2fa_pending_expires"] = time.time() + 600

    sent_ok, send_msg = send_2fa_otp_email(pending_user["email"], otp, pending_user["username"])
    app.logger.warning(f"[2FA AUTH RESEND] Code for '{pending_user['username']}': {otp}")
    if sent_ok:
        flash(f"A new 6-digit verification code was dispatched to {pending_user['email']}.", "success")
    else:
        flash(f"Could not resend email code: {send_msg}", "error")

    return redirect(url_for("login_2fa"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def first_time_change_password():
    user = getattr(g, "current_user", None)
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        test_auth = authenticate_user(user["username"], current_password)
        if not test_auth:
            flash("Current temporary password verification failed. Please enter your temporary password correctly.", "error")
            return render_template("change_password.html", user=user)

        if new_password != confirm_password:
            flash("Password error: Password confirmation does not match.", "error")
            return render_template("change_password.html", user=user)

        if new_password == current_password:
            flash("Password error: New permanent password cannot be identical to your temporary password.", "error")
            return render_template("change_password.html", user=user)

        pwd_errors = validate_password_standards(new_password, user["username"])
        if pwd_errors:
            for err in pwd_errors:
                flash(f"Password standards error: {err}", "error")
            return render_template("change_password.html", user=user)

        update_user_password(user["id"], new_password, must_change_password=False)
        user["must_change_password"] = False
        log_audit_event(user["username"], "change_password", "Security Policy", "Operator set permanent password")
        flash("Password successfully updated! Welcome to BantayNet.", "success")
        return redirect(url_for("index"))

    return render_template("change_password.html", user=user)



@app.route("/logout")
def logout():
    username = g.current_user.get("username", "user") if getattr(g, "current_user", None) else "user"
    log_audit_event(username, "logout", "Web Portal", "Operator signed out")
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/audit")
@role_required("admin")
def audit_logs_view():
    action = request.args.get("action", "").strip() or None
    username = request.args.get("username", "").strip() or None
    logs = get_audit_logs(limit=250, action=action, username=username)
    return render_template(
        "audit.html",
        logs=logs,
        filter_action=action or "",
        filter_username=username or "",
    )


@app.route("/users")
@role_required("admin")
def manage_users():
    users = get_all_users()
    return render_template("users.html", users=users)


@app.route("/users/add", methods=["POST"])
@role_required("admin")
def add_user():
    username = request.form.get("username", "").strip()
    email = (request.form.get("email") or "").strip().lower() or None
    raw_password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    use_generic_pw = request.form.get("use_generic_pw") == "on" or not raw_password
    enable_2fa = request.form.get("enable_2fa") == "on"
    role = request.form.get("role", "viewer").strip().lower()

    if use_generic_pw:
        password = DEFAULT_INITIAL_PASSWORD
    else:
        password = raw_password

    # 1. Error checking: Username format & length standards
    user_errors = validate_username_standards(username)
    if user_errors:
        for err in user_errors:
            flash(f"Username error: {err}", "error")
        return redirect(url_for("manage_users"))

    # 2. Error checking: Email format standards (if provided)
    if email:
        email_errors = validate_email_standards(email)
        if email_errors:
            for err in email_errors:
                flash(f"Email error: {err}", "error")
            return redirect(url_for("manage_users"))

    # 3. Error checking: Password confirmation match (when manual password provided)
    if not use_generic_pw and confirm_password and password != confirm_password:
        flash("Password error: Password confirmation does not match.", "error")
        return redirect(url_for("manage_users"))

    # 4. Error checking: Comprehensive NIST/OWASP password standards
    if not use_generic_pw:
        pwd_errors = validate_password_standards(password, username)
        if pwd_errors:
            for err in pwd_errors:
                flash(f"Password standards error: {err}", "error")
            return redirect(url_for("manage_users"))

    # 5. Error checking: Prevent duplicate / double account creation
    existing_user = get_user_by_username(username)
    if existing_user is not None:
        flash(f"Account creation failed: An account with username '{username}' already exists. Usernames must be unique.", "error")
        return redirect(url_for("manage_users"))

    if email:
        existing_email_user = get_user_by_email(email)
        if existing_email_user is not None:
            flash(f"Account creation failed: An account with email '{email}' already exists. Email addresses must be unique.", "error")
            return redirect(url_for("manage_users"))

    backup_codes = generate_backup_codes(8) if enable_2fa else None

    try:
        create_user(
            username,
            password,
            role=role,
            email=email,
            must_change_password=True,
            is_2fa_enabled=enable_2fa,
            backup_codes=backup_codes,
        )
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        email_info = f", Email: {email}" if email else ""
        tfa_info = ", 2FA: Enabled" if enable_2fa else ""
        log_audit_event(admin_user, "create_user", f"User '{username}'", f"Role: {role}{email_info}{tfa_info}")

        if email:
            sent_ok, send_msg = send_account_created_email(email, username, password, url_for("login", _external=True))
            if sent_ok:
                flash(f"User '{username}' created successfully ({role.title()} role). Welcome notification email with temporary credentials was dispatched to {email}.", "success")
            else:
                flash(f"User '{username}' created successfully with temporary password '{password}', but email could not be delivered: {send_msg}. Please provide the credentials to the operator manually.", "warning")
        else:
            flash(f"User '{username}' created successfully with initial temporary password '{password}'. Operator must change password upon first sign-in.", "success")

        if enable_2fa and backup_codes:
            codes_str = ", ".join(backup_codes)
            flash(f"Emergency backup codes for '{username}': {codes_str}", "info")
    except ValueError as exc:
        flash(f"Account creation failed: {exc}", "error")
    except Exception as exc:
        flash(f"Unexpected error creating user: {exc}", "error")

    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/toggle-2fa", methods=["POST"])
@role_required("admin")
def admin_toggle_2fa(user_id: int):
    user = get_user_by_id(user_id)
    if not user:
        abort(404, description="User not found")

    enable = not user.get("is_2fa_enabled", False)
    backup_codes = generate_backup_codes(8) if enable else None
    toggle_user_2fa(user_id, enable, backup_codes=backup_codes)

    admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
    status_str = "enabled" if enable else "disabled"
    log_audit_event(admin_user, "toggle_2fa", f"User #{user_id} ({user['username']})", f"Set 2FA to {status_str}")

    if enable:
        codes_str = ", ".join(backup_codes) if backup_codes else ""
        flash(f"Two-Factor Authentication enabled for '{user['username']}'. Emergency backup recovery codes: {codes_str}", "success")
    else:
        flash(f"Two-Factor Authentication disabled for '{user['username']}'.", "success")

    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def change_user_role(user_id: int):
    new_role = request.form.get("role", "").strip().lower()
    if g.current_user and g.current_user.get("id") == user_id and new_role != "admin":
        flash("Cannot demote your own active admin account.", "error")
        return redirect(url_for("manage_users"))

    try:
        update_user_role(user_id, new_role)
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        log_audit_event(admin_user, "update_role", f"User #{user_id}", f"Role changed to {new_role}")
        flash(f"User role updated to '{new_role.title()}'.", "success")
    except Exception as exc:
        flash(f"Error updating role: {exc}", "error")

    return redirect(url_for("manage_users"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def remove_user(user_id: int):
    if g.current_user and g.current_user.get("id") == user_id:
        flash("Cannot delete your own active administrator account.", "error")
        return redirect(url_for("manage_users"))

    try:
        delete_user(user_id)
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        log_audit_event(admin_user, "delete_user", f"User #{user_id}", "Account deleted")
        flash("User removed successfully.", "success")
    except Exception as exc:
        flash(f"Error removing user: {exc}", "error")

    return redirect(url_for("manage_users"))


@app.route("/")
@login_required
def index():
    user_role = g.current_user.get("role") if getattr(g, "current_user", None) else "viewer"
    if user_role in ("admin", "analyst"):
        rule = request.args.get("rule", "").strip() or None
        severity = request.args.get("severity", "").strip() or None
        src_ip = request.args.get("src_ip", "").strip() or None
        status = request.args.get("status", "").strip() or None
        client_name = request.args.get("client_name", "").strip() or None
        search = request.args.get("search", "").strip() or None
    else:
        rule = severity = src_ip = status = client_name = search = None

    stats = get_summary_stats()
    chart_data = get_chart_data()
    alerts = get_alerts(
        rule=rule,
        severity=severity,
        src_ip=src_ip,
        status=status,
        client_name=client_name,
        search=search,
        limit=500,
    )

    filters = {
        "rule": rule or "",
        "severity": severity or "",
        "src_ip": src_ip or "",
        "status": status or "",
        "client_name": client_name or "",
        "search": search or "",
    }
    return render_template(
        "index.html",
        stats=stats,
        alerts=alerts,
        filters=filters,
        chart_data=chart_data,
    )


@app.route("/alert/<int:alert_id>")
@login_required
def alert_detail(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert:
        abort(404, description=f"Alert #{alert_id} not found")

    evidence_packets = []
    evidence_path = _resolve_evidence(alert.get("evidence_file"))
    evidence_hash = None
    evidence_status = "none"

    if evidence_path and evidence_path.is_file():
        live_sha = calculate_sha256(evidence_path)
        evidence_hash = live_sha
        stored_sha = alert.get("evidence_sha256") or alert.get("details", {}).get("evidence_sha256")
        if stored_sha:
            if stored_sha.lower() == live_sha.lower():
                evidence_status = "verified"
            else:
                evidence_status = "tampered"
        else:
            evidence_status = "verified"

        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.utils import PcapReader

            with PcapReader(str(evidence_path)) as reader:
                first_ts = None
                for idx, pkt in enumerate(reader):
                    if idx >= 100:  # Preview cap in UI
                        break
                    ts = float(pkt.time)
                    if first_ts is None:
                        first_ts = ts
                    rel_time = f"{ts - first_ts:.4f}"

                    src = pkt[IP].src if IP in pkt else "Unknown"
                    dst = pkt[IP].dst if IP in pkt else "Unknown"
                    proto = "OTHER"
                    flags = ""

                    if TCP in pkt:
                        proto = f"TCP/{pkt[TCP].dport}"
                        flags = pkt[TCP].flags
                    elif UDP in pkt:
                        proto = f"UDP/{pkt[UDP].dport}"
                    elif ICMP in pkt:
                        proto = f"ICMP Type {pkt[ICMP].type}"

                    evidence_packets.append(
                        {
                            "num": idx + 1,
                            "rel_time": rel_time,
                            "src": src,
                            "dst": dst,
                            "proto": proto,
                            "flags": str(flags),
                            "len": len(pkt),
                            "summary": pkt.summary(),
                        }
                    )
        except Exception as e:
            app.logger.warning(f"Could not parse evidence PCAP {evidence_path}: {e}")

    return render_template(
        "alert.html",
        alert=alert,
        evidence_packets=evidence_packets,
        evidence_hash=evidence_hash,
        evidence_status=evidence_status,
    )


@app.route("/alert/<int:alert_id>/status", methods=["POST"])
@role_required("analyst")
def update_alert_status(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert:
        abort(404, description=f"Alert #{alert_id} not found")

    new_status = request.form.get("status", "new").strip().lower()
    analyst_note = request.form.get("analyst_note", "").strip()
    from src.db import update_alert_status_and_note

    update_alert_status_and_note(alert_id, new_status, analyst_note)
    operator = g.current_user.get("username", "analyst") if getattr(g, "current_user", None) else "analyst"
    log_audit_event(
        operator,
        "update_alert",
        f"Alert #{alert_id} ({alert.get('rule')})",
        f"Status: {new_status}. Note: {analyst_note[:100]}",
    )
    flash(
        f"Alert #{alert_id} updated: status is now '{new_status.replace('_', ' ').title()}'.",
        "success",
    )
    return redirect(url_for("alert_detail", alert_id=alert_id))


@app.route("/upload", methods=["POST"])
@role_required("analyst")
def upload_pcap():
    if "pcap_file" not in request.files:
        flash("No file part in upload request.", "error")
        return redirect(url_for("index"))

    file = request.files["pcap_file"]
    if file.filename == "":
        flash("No file selected for upload.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    if not is_allowed_file(filename):
        flash("Invalid file type! Only .pcap and .pcapng files are permitted.", "error")
        return redirect(url_for("index"))

    # Security check: verify PCAP / PCAPNG magic header bytes
    if not is_valid_pcap_header(file.stream):
        flash("Security validation failed: uploaded file does not contain a valid PCAP or PCAPNG header.", "error")
        return redirect(url_for("index"))

    # Sanitize client name: keep only alphanumeric, spaces, and safe punctuation
    raw_client = request.form.get("client_name", "Default")
    client_name = re.sub(r"[^\w\s\.\-_/]", "", raw_client).strip()[:64] or "Default"
    dest_path = UPLOAD_DIR / f"{uuid.uuid4().hex[:8]}_{filename}"  # never overwrite earlier uploads
    file.save(str(dest_path))

    # Guard: verify non-empty file to prevent downstream zero-byte crashes
    if dest_path.stat().st_size == 0:
        dest_path.unlink(missing_ok=True)
        flash("Upload rejected: file is empty (0 bytes).", "error")
        return redirect(url_for("index"))

    pcap_sha256 = calculate_sha256(dest_path)

    try:
        cfg = load_config()
        result = analyze(dest_path, cfg=cfg)

        store_alerts(result.alerts, filename, client_name=client_name)

        operator = g.current_user.get("username", "analyst") if getattr(g, "current_user", None) else "analyst"
        log_audit_event(
            operator,
            "upload_pcap",
            filename,
            f"SHA-256: {pcap_sha256[:16]}... | Client: {client_name}, {result.stats.parsed} pkts, {len(result.alerts)} alert(s) detected",
        )

        msg = f"Successfully analyzed '{filename}' ({client_name}): {result.stats.parsed} packets parsed, {len(result.alerts)} alert(s) detected."
        if result.stats.skipped_allowlist > 0:
            msg += f" ({result.stats.skipped_allowlist} packets skipped via allowlist)."
        flash(msg, "success")
    except Exception as exc:
        flash(f"Error analyzing capture file: {exc}", "error")

    return redirect(url_for("index"))


@app.route("/evidence/<int:alert_id>")
@role_required("admin", "analyst")
def download_evidence(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert or not alert.get("evidence_file"):
        abort(404, description="No evidence file associated with this alert")

    file_path = _resolve_evidence(alert["evidence_file"])
    if file_path is None or not file_path.is_file():
        abort(404, description="Evidence file does not exist on disk")

    operator = g.current_user.get("username", "analyst") if getattr(g, "current_user", None) else "analyst"
    log_audit_event(
        operator,
        "download_evidence",
        f"Alert #{alert_id} ({file_path.name})",
        "Evidence PCAP downloaded for offline forensic analysis.",
    )

    return send_file(
        str(file_path),
        as_attachment=True,
        download_name=file_path.name,
        mimetype="application/vnd.tcpdump.pcap",
    )


@app.route("/export.csv")
@role_required("analyst")
def export_csv():
    rule = request.args.get("rule", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    src_ip = request.args.get("src_ip", "").strip() or None
    status = request.args.get("status", "").strip() or None
    client_name = request.args.get("client_name", "").strip() or None
    search = request.args.get("search", "").strip() or None

    alerts = get_alerts(
        rule=rule,
        severity=severity,
        src_ip=src_ip,
        status=status,
        client_name=client_name,
        search=search,
        limit=5000,
    )

    output = io.StringIO()
    write_alerts_csv(output, alerts)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=bantaynet_alerts.csv"},
    )


@app.route("/alert/<int:alert_id>/report.pdf")
@role_required("admin", "analyst")
def alert_report_pdf(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert:
        abort(404, description=f"Alert #{alert_id} not found")

    evidence_packets = []
    evidence_path = _resolve_evidence(alert.get("evidence_file"))
    if evidence_path and evidence_path.is_file():
        alert["evidence_sha256"] = alert.get("evidence_sha256") or calculate_sha256(evidence_path)
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.utils import PcapReader

            reader = None
            try:
                reader = PcapReader(str(evidence_path))
                first_ts = None
                for idx, pkt in enumerate(reader):
                    if idx >= 50:
                        break
                    ts = float(pkt.time)
                    if first_ts is None:
                        first_ts = ts
                    rel_time = f"{ts - first_ts:.4f}"
                    src = pkt[IP].src if IP in pkt else "Unknown"
                    dst = pkt[IP].dst if IP in pkt else "Unknown"
                    proto = "OTHER"
                    flags = ""
                    if TCP in pkt:
                        proto = f"TCP/{pkt[TCP].dport}"
                        flags = str(pkt[TCP].flags)
                    elif UDP in pkt:
                        proto = f"UDP/{pkt[UDP].dport}"
                    elif ICMP in pkt:
                        proto = f"ICMP Type {pkt[ICMP].type}"

                    evidence_packets.append(
                        {
                            "num": idx + 1,
                            "rel_time": rel_time,
                            "src": src,
                            "dst": dst,
                            "proto": proto,
                            "flags": flags,
                            "len": len(pkt),
                        }
                    )
            finally:
                if reader is not None:
                    try:
                        reader.close()
                    except Exception:
                        pass
                import gc
                gc.collect()
        except Exception as e:
            app.logger.warning(f"Could not parse evidence PCAP {evidence_path}: {e}")

    pdf_buffer = io.BytesIO()
    generate_alert_pdf(alert, evidence_packets, pdf_buffer)
    pdf_buffer.seek(0)

    operator = g.current_user.get("username", "user") if getattr(g, "current_user", None) else "user"
    log_audit_event(operator, "export_pdf", f"Incident #{alert_id}", "Downloaded incident PDF report")

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"bantaynet_incident_{alert_id}.pdf",
    )


@app.route("/report/summary.pdf")
@role_required("admin", "analyst")
def executive_summary_pdf():
    rule = request.args.get("rule", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    src_ip = request.args.get("src_ip", "").strip() or None
    status = request.args.get("status", "").strip() or None
    client_name = request.args.get("client_name", "").strip() or None
    search = request.args.get("search", "").strip() or None

    alerts = get_alerts(
        rule=rule,
        severity=severity,
        src_ip=src_ip,
        status=status,
        client_name=client_name,
        search=search,
        limit=500,
    )
    stats = get_summary_stats()

    pdf_buffer = io.BytesIO()
    generate_summary_pdf(alerts, stats, client_name, pdf_buffer)
    pdf_buffer.seek(0)

    operator = g.current_user.get("username", "user") if getattr(g, "current_user", None) else "user"
    scope_str = f"Client: {client_name}" if client_name else "All Clients"
    log_audit_event(operator, "export_summary_pdf", scope_str, f"Downloaded threat summary PDF ({len(alerts)} alerts)")

    filename = f"bantaynet_summary_{client_name}.pdf" if client_name else "bantaynet_threat_summary.pdf"
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/settings/rules", methods=["GET", "POST"])
@role_required("admin")
def manage_rules():
    """IT Administrator view to configure detection thresholds and rules."""
    rules_path = DEFAULT_RULES_PATH
    if request.method == "POST":
        try:
            def _float(key: str, default: float) -> float:
                val = float(request.form.get(key, default))
                return int(val) if val.is_integer() else val

            def _int(key: str, default: int) -> int:
                return int(request.form.get(key, default))

            raw_ips = request.form.get("allowlist_ips", "")
            ips_list = [ip.strip() for ip in re.split(r"[\n,]+", raw_ips) if ip.strip()]
            import ipaddress
            for ip_entry in ips_list:
                try:
                    ipaddress.ip_network(ip_entry, strict=False)
                except ValueError as exc:
                    raise ConfigError(f"Invalid IP or CIDR in allowlist: '{ip_entry}'") from exc

            updates = {
                "port_scan": {
                    "enabled": request.form.get("port_scan_enabled") == "on",
                    "severity": request.form.get("port_scan_severity", "high").strip().lower(),
                    "window_seconds": _float("port_scan_window", 5.0),
                    "distinct_ports": _int("port_scan_ports", 50),
                },
                "slow_scan": {
                    "enabled": request.form.get("slow_scan_enabled") == "on",
                    "severity": request.form.get("slow_scan_severity", "medium").strip().lower(),
                    "window_seconds": _float("slow_scan_window", 300.0),
                    "distinct_ports": _int("slow_scan_ports", 20),
                },
                "host_sweep": {
                    "enabled": request.form.get("host_sweep_enabled") == "on",
                    "severity": request.form.get("host_sweep_severity", "medium").strip().lower(),
                    "window_seconds": _float("host_sweep_window", 10.0),
                    "distinct_hosts": _int("host_sweep_hosts", 50),
                },
                "syn_burst": {
                    "enabled": request.form.get("syn_burst_enabled") == "on",
                    "severity": request.form.get("syn_burst_severity", "high").strip().lower(),
                    "window_seconds": _float("syn_burst_window", 2.0),
                    "syn_count": _int("syn_burst_count", 200),
                },
                "suspicious_flags": {
                    "enabled": request.form.get("suspicious_flags_enabled") == "on",
                    "severity": request.form.get("suspicious_flags_severity", "medium").strip().lower(),
                    "null_scan": request.form.get("suspicious_flags_null") == "on",
                    "xmas_scan": request.form.get("suspicious_flags_xmas") == "on",
                    "fin_only": request.form.get("suspicious_flags_fin") == "on",
                },
                "cleartext_protocols": {
                    "enabled": request.form.get("cleartext_enabled") == "on",
                    "severity": request.form.get("cleartext_severity", "low").strip().lower(),
                },
                "icmp_flood": {
                    "enabled": request.form.get("icmp_flood_enabled") == "on",
                    "severity": request.form.get("icmp_flood_severity", "medium").strip().lower(),
                    "window_seconds": _float("icmp_flood_window", 2.0),
                    "echo_requests": _int("icmp_flood_requests", 100),
                },
                "allowlist": {
                    "enabled": request.form.get("allowlist_enabled") == "on",
                    "ips": ips_list,
                },
                "alerts": {
                    "cooldown_seconds": _float("alerts_cooldown", 30.0),
                },
                "evidence": {
                    "enabled": request.form.get("evidence_enabled") == "on",
                    "max_packets": _int("evidence_max_packets", 500),
                },
            }

            save_rules_config(updates, path=rules_path)
            admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
            log_audit_event(
                admin_user,
                "update_rules",
                "rules/rules.yaml",
                "Updated detection thresholds and rule configurations",
            )
            flash("Detection rules and thresholds updated successfully.", "success")
            return redirect(url_for("manage_rules"))
        except (ConfigError, ValueError) as exc:
            flash(f"Configuration validation error: {exc}", "error")
        except Exception as exc:
            flash(f"Error saving configuration: {exc}", "error")

    cfg = load_config(rules_path)
    return render_template("rules.html", cfg=cfg)


def _list_pcap_directory(directory: Path) -> list[dict[str, object]]:
    """Return metadata for .pcap/.pcapng files in a directory."""
    if not directory.is_dir():
        return []
    files = []
    for p in sorted(directory.iterdir(), key=lambda x: x.stat().st_mtime if x.is_file() else 0, reverse=True):
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS:
            st = p.stat()
            files.append(
                {
                    "name": p.name,
                    "size_kb": round(st.st_size / 1024.0, 2),
                    "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(st.st_mtime)),
                }
            )
    return files


@app.route("/settings/storage")
@role_required("admin")
def manage_storage():
    """IT Administrator view to manage the database and stored evidence/capture files."""
    cfg = load_config(DEFAULT_RULES_PATH)
    evidence_dir = PROJECT_ROOT / cfg.evidence.output_dir
    stats = get_summary_stats()
    evidence_files = _list_pcap_directory(evidence_dir)
    upload_files = _list_pcap_directory(UPLOAD_DIR)
    return render_template(
        "storage.html",
        stats=stats,
        evidence_files=evidence_files,
        upload_files=upload_files,
        evidence_dir_name=cfg.evidence.output_dir,
    )


@app.route("/settings/storage/clear-db", methods=["POST"])
@role_required("admin")
def admin_clear_database():
    """Clear all alerts from the database (and optionally purge stored evidence files)."""
    purge_evidence = request.form.get("purge_evidence") == "on"
    clear_alerts()
    removed_files = 0
    if purge_evidence:
        import gc
        gc.collect()
        cfg = load_config(DEFAULT_RULES_PATH)
        evidence_dir = (Path(PROJECT_ROOT) / cfg.evidence.output_dir).resolve()
        if not evidence_dir.is_dir():
            evidence_dir = Path("evidence").resolve()
        if not evidence_dir.is_dir():
            evidence_dir = Path("evidence").resolve()
        if evidence_dir.is_dir():
            for f in list(evidence_dir.iterdir()):
                if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS:
                    try:
                        f.unlink(missing_ok=True)
                        removed_files += 1
                    except OSError:
                        pass

    admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
    details = f"Cleared all alerts from database (purged {removed_files} evidence files)" if purge_evidence else "Cleared all alerts from database"
    log_audit_event(admin_user, "clear_database", "Alert Database", details)
    flash(details + ".", "success")
    return redirect(url_for("manage_storage"))


@app.route("/settings/storage/delete-alert/<int:alert_id>", methods=["POST"])
@role_required("admin")
def admin_delete_alert(alert_id: int):
    """Delete a single alert record and optionally its associated evidence file."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        abort(404, description=f"Alert #{alert_id} not found")

    if request.form.get("delete_evidence") == "on" and alert.get("evidence_file"):
        ev_path = _resolve_evidence(alert.get("evidence_file"))
        if ev_path and ev_path.is_file():
            try:
                ev_path.unlink()
            except OSError:
                pass

    delete_alert(alert_id)
    admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
    log_audit_event(admin_user, "delete_alert", f"Alert #{alert_id}", f"Deleted alert #{alert_id} ({alert.get('rule')})")
    flash(f"Alert #{alert_id} deleted from database.", "success")
    return redirect(url_for("index"))


@app.route("/settings/storage/delete-file", methods=["POST"])
@role_required("admin")
def admin_delete_file():
    """Delete a stored evidence PCAP or uploaded PCAP file."""
    category = request.form.get("category", "evidence").strip().lower()
    filename = secure_filename(request.form.get("filename", "").strip())

    cfg = load_config()
    base_dir = (PROJECT_ROOT / cfg.evidence.output_dir) if category == "evidence" else UPLOAD_DIR

    if request.form.get("purge_all") == "1":
        removed = 0
        if base_dir.is_dir():
            for f in base_dir.iterdir():
                if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS:
                    try:
                        f.unlink()
                        removed += 1
                    except OSError:
                        pass
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        log_audit_event(admin_user, "purge_files", category, f"Purged {removed} {category} PCAP file(s)")
        flash(f"Purged {removed} {category} file(s) from disk.", "success")
        return redirect(url_for("manage_storage"))

    if not filename:
        flash("Invalid filename specified.", "error")
        return redirect(url_for("manage_storage"))

    target_path = (base_dir / filename).resolve()
    if not target_path.is_relative_to(base_dir.resolve()) or not target_path.is_file():
        flash("Requested file does not exist or path is invalid.", "error")
        return redirect(url_for("manage_storage"))

    try:
        target_path.unlink()
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        log_audit_event(admin_user, "delete_file", filename, f"Deleted {category} file '{filename}'")
        flash(f"Deleted {category} file '{filename}'.", "success")
    except OSError as exc:
        flash(f"Could not delete file: {exc}", "error")

    return redirect(url_for("manage_storage"))


# ---------------------------------------------------------------------------
# User-Facing Error Output & Status Code Handlers
# ---------------------------------------------------------------------------


@app.errorhandler(400)
def handle_bad_request(err):
    desc = getattr(err, "description", "The server could not process the request due to malformed or invalid syntax.")
    return render_template("error.html", error_code=400, error_title="Bad Request", error_message=desc), 400


@app.errorhandler(403)
def handle_forbidden(err):
    desc = getattr(err, "description", "Access denied. You do not possess the required permissions to view this resource.")
    return render_template("error.html", error_code=403, error_title="Access Forbidden", error_message=desc), 403


@app.errorhandler(404)
def handle_not_found(err):
    desc = getattr(err, "description", "The requested page, alert record, or forensic evidence file could not be found.")
    return render_template("error.html", error_code=404, error_title="Resource Not Found", error_message=desc), 404


@app.errorhandler(413)
def handle_payload_too_large(err):
    desc = "The uploaded file exceeds the 50 MB maximum payload limit configured for BantayNet."
    return render_template("error.html", error_code=413, error_title="Upload Exceeds Limit", error_message=desc), 413


@app.errorhandler(429)
def handle_rate_limited(err):
    desc = getattr(err, "description", "Too many requests. Temporary security lockout active to prevent brute-force abuse.")
    return render_template("error.html", error_code=429, error_title="Rate Limit Exceeded", error_message=desc), 429


@app.errorhandler(500)
def handle_internal_server_error(err):
    desc = "An unexpected server error occurred while processing your request. The incident has been recorded."
    return render_template("error.html", error_code=500, error_title="Internal Server Error", error_message=desc), 500



def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    init_db()
    print(f"\n[*] BantayNet Security Dashboard running at http://{host}:{port}/")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard(debug=os.environ.get("BANTAYNET_DEBUG") == "1")
