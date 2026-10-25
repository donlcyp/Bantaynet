"""Flask web dashboard for BantayNet suspicious activity detection system."""

from __future__ import annotations

import io
import os
import secrets
import sys
import uuid
from functools import wraps
from pathlib import Path

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

from src.analyze import analyze
from src.config import load_config
from src.db import (
    authenticate_user,
    create_user,
    delete_user,
    get_alert_by_id,
    get_alerts,
    get_all_users,
    get_audit_logs,
    get_chart_data,
    get_summary_stats,
    get_user_by_id,
    init_db,
    log_audit_event,
    update_user_role,
)
from src.export import write_alerts_csv
from src.report_pdf import generate_alert_pdf, generate_summary_pdf
from src.store import store_alerts

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "dashboard" / "templates"),
    static_folder=str(PROJECT_ROOT / "dashboard" / "static"),
)

app.secret_key = os.environ.get("BANTAYNET_SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB maximum upload
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

UPLOAD_DIR = PROJECT_ROOT / "pcaps" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@app.before_request
def load_logged_in_user():
    init_db()
    user_id = session.get("user_id")
    if user_id is not None:
        g.current_user = get_user_by_id(user_id)
    elif app.config.get("TESTING") and not app.config.get("FORCE_AUTH_TESTING"):
        # Auto-mock admin user for existing test fixtures
        g.current_user = {"id": 1, "username": "admin", "role": "admin"}
    else:
        g.current_user = None


@app.context_processor
def inject_global_data():
    from src.db import _get_active_engine, ACTIVE_ENGINE
    engine, _ = _get_active_engine()
    engine_name = "MySQL (XAMPP)" if engine == "mysql" and ACTIVE_ENGINE != "sqlite" else "SQLite Fallback"
    return {
        "db_engine_name": engine_name,
        "current_user": getattr(g, "current_user", None),
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


def _resolve_evidence(stored: str | None) -> Path | None:
    """Turn a stored (project-relative or legacy absolute) evidence path into a real path."""
    if not stored:
        return None
    p = Path(stored)
    return p if p.is_absolute() else PROJECT_ROOT / p


@app.route("/login", methods=["GET", "POST"])
def login():
    if getattr(g, "current_user", None) is not None:
        return redirect(url_for("index"))

    next_url = request.args.get("next") or request.form.get("next") or url_for("index")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(username, password)
        if user:
            session.clear()
            session["user_id"] = user["id"]
            log_audit_event(user["username"], "login", "Web Portal", f"Role: {user['role']}")
            flash(f"Logged in successfully as {user['username']} ({user['role'].title()} role).", "success")
            return redirect(next_url)
        else:
            flash("Invalid username or password. Please verify credentials.", "error")

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
    role = request.form.get("role", "viewer").strip().lower()

    if not username or not password:
        flash("Username and password are required.", "error")
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
    rule = request.args.get("rule", "").strip() or None
    severity = request.args.get("severity", "").strip() or None
    src_ip = request.args.get("src_ip", "").strip() or None
    status = request.args.get("status", "").strip() or None
    client_name = request.args.get("client_name", "").strip() or None
    search = request.args.get("search", "").strip() or None

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
@role_required("admin", "analyst")
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
@role_required("admin", "analyst")
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

    client_name = request.form.get("client_name", "Default").strip()[:64] or "Default"
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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


def run_dashboard(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    init_db()
    print(f"\n[*] BantayNet Security Dashboard running at http://{host}:{port}/")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    run_dashboard(debug=os.environ.get("BANTAYNET_DEBUG") == "1")
