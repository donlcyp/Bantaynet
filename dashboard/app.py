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
from src.db import (
    authenticate_user,
    clear_alerts,
    create_user,
    delete_alert,
    delete_user,
    get_alert_by_id,
    get_alerts,
    get_all_users,
    get_audit_logs,
    get_chart_data,
    get_summary_stats,
    get_user_by_id,
    init_db,
    is_default_admin_password_active,
    log_audit_event,
    update_user_role,
)
from src.export import write_alerts_csv
from src.report_pdf import generate_alert_pdf, generate_summary_pdf
from src.security import validate_password_standards, validate_username_standards
from src.store import store_alerts

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

    # 2. User Authentication Load
    user_id = session.get("user_id")
    if user_id is not None:
        g.current_user = get_user_by_id(user_id)
    elif app.config.get("TESTING") and not app.config.get("FORCE_AUTH_TESTING"):
        # Auto-mock user for legacy non-RBAC test fixtures
        g.current_user = {"id": 1, "username": "analyst", "role": "analyst"}
    else:
        g.current_user = None


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

    response.headers.pop("Server", None)
    return response


@app.context_processor
def inject_global_data():
    from src.db import _get_active_engine, ACTIVE_ENGINE
    engine, _ = _get_active_engine()
    engine_name = "MySQL (XAMPP)" if engine == "mysql" and ACTIVE_ENGINE != "sqlite" else "SQLite Fallback"
    return {
        "db_engine_name": engine_name,
        "current_user": getattr(g, "current_user", None),
        "csrf_token": generate_csrf_token,
        "is_default_admin_pw": is_default_admin_password_active(),
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
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "127.0.0.1"

        # 1. Error checking: Empty fields
        if not username or not password:
            flash("Authentication error: Please provide both username and password.", "error")
            return render_template("login.html", next=next_url), 400

        # 2. Error checking: Input bounds (prevent memory/buffer exhaustion)
        if len(username) > 64 or len(password) > 128:
            flash("Authentication error: Input exceeds allowed credential limits (max 64 username, 128 password).", "error")
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
            session.clear()
            session["user_id"] = user["id"]
            # Ensure fresh CSRF token upon privilege change
            session["csrf_token"] = secrets.token_hex(32)

            log_audit_event(user["username"], "login", "Web Portal", f"Role: {user['role']}")
            flash(f"Logged in successfully as {user['username']} ({user['role'].title()} role).", "success")
            return redirect(next_url)
        else:
            record_login_failure(client_ip, username)
            app.logger.warning(f"Failed authentication attempt for '{username}' from {client_ip}")
            log_audit_event("anonymous", "failed_login", f"IP: {client_ip}", f"Attempted username: {username}")
            flash("Authentication error: Invalid username or password. Please verify credentials.", "error")

    return render_template("login.html", next=next_url)



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
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    role = request.form.get("role", "viewer").strip().lower()

    # 1. Error checking: Username format & length standards
    user_errors = validate_username_standards(username)
    if user_errors:
        for err in user_errors:
            flash(f"Username error: {err}", "error")
        return redirect(url_for("manage_users"))

    # 2. Error checking: Password confirmation match
    if confirm_password and password != confirm_password:
        flash("Password error: Password confirmation does not match.", "error")
        return redirect(url_for("manage_users"))

    # 3. Error checking: Comprehensive NIST/OWASP password standards
    pwd_errors = validate_password_standards(password, username)
    if pwd_errors:
        for err in pwd_errors:
            flash(f"Password standards error: {err}", "error")
        return redirect(url_for("manage_users"))

    try:
        create_user(username, password, role)
        admin_user = g.current_user.get("username", "admin") if getattr(g, "current_user", None) else "admin"
        log_audit_event(admin_user, "create_user", f"User '{username}'", f"Role: {role}")
        flash(f"User '{username}' created successfully with {role.title()} role.", "success")
    except ValueError as exc:
        flash(f"Error creating user: {exc}", "error")
    except Exception as exc:
        flash(f"Unexpected error creating user: {exc}", "error")

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

    init_db()
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
    if evidence_path and evidence_path.is_file():
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

    return render_template("alert.html", alert=alert, evidence_packets=evidence_packets)


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

    try:
        cfg = load_config()
        result = analyze(dest_path, cfg=cfg)

        store_alerts(result.alerts, filename, client_name=client_name)

        operator = g.current_user.get("username", "analyst") if getattr(g, "current_user", None) else "analyst"
        log_audit_event(
            operator,
            "upload_pcap",
            filename,
            f"Client: {client_name}, {result.stats.parsed} pkts, {len(result.alerts)} alert(s) detected",
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
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
            from scapy.utils import PcapReader

            with PcapReader(str(evidence_path)) as reader:
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
    cfg = load_config()
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
        cfg = load_config()
        evidence_dir = PROJECT_ROOT / cfg.evidence.output_dir
        if evidence_dir.is_dir():
            for f in evidence_dir.iterdir():
                if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS:
                    try:
                        f.unlink()
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



def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    init_db()
    print(f"\n[*] BantayNet Security Dashboard running at http://{host}:{port}/")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard(debug=os.environ.get("BANTAYNET_DEBUG") == "1")
