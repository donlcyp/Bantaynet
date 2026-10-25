"""Unit and integration tests for Phase D features:
- PDF Incident Report generation & Executive Summary Report generation
- Audit logging (table schema, query filters, action tracking)
- Admin Audit Log UI & access restrictions
- Email alert notification dispatch via smtplib (disabled by default)
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from dashboard.app import app
from src.config import Config, NotificationSettings
import src.db as db_mod
from src.db import (
    get_audit_logs,
    init_db,
    insert_alert,
    log_audit_event,
)
from src.notifier import send_alert_email
from src.report_pdf import generate_alert_pdf, generate_summary_pdf


@pytest.fixture
def phase_d_db(tmp_path: Path, monkeypatch):
    test_db = tmp_path / "test_phase_d.db"
    monkeypatch.setattr(db_mod, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db_mod, "DEFAULT_SQLITE_PATH", test_db)
    monkeypatch.setattr(db_mod, "DB_PATH", test_db)
    init_db(test_db)
    yield test_db


# ---------------------------------------------------------------------------
# 1. Audit Log Tests
# ---------------------------------------------------------------------------

def test_audit_log_crud_and_filtering(phase_d_db: Path):
    """Test logging audit events and querying with filters."""
    # Log several events
    log_audit_event(
        username="admin",
        action="USER_LOGIN_SUCCESS",
        target="127.0.0.1",
        details="Admin signed in",
        db_path=phase_d_db,
    )
    log_audit_event(
        username="analyst",
        action="ALERT_STATUS_UPDATE",
        target="Alert #1",
        details="Marked alert #1 as resolved",
        db_path=phase_d_db,
    )
    log_audit_event(
        username="admin",
        action="USER_CREATE",
        target="viewer2",
        details="Created user viewer2",
        db_path=phase_d_db,
    )

    # Fetch all
    all_logs = get_audit_logs(limit=50, db_path=phase_d_db)
    assert len(all_logs) == 3
    # Check reverse chronological ordering
    assert all_logs[0]["action"] == "USER_CREATE"
    assert all_logs[1]["action"] == "ALERT_STATUS_UPDATE"
    assert all_logs[2]["action"] == "USER_LOGIN_SUCCESS"

    # Filter by user
    analyst_logs = get_audit_logs(username="analyst", db_path=phase_d_db)
    assert len(analyst_logs) == 1
    assert analyst_logs[0]["details"] == "Marked alert #1 as resolved"

    # Filter by action
    login_logs = get_audit_logs(action="USER_LOGIN_SUCCESS", db_path=phase_d_db)
    assert len(login_logs) == 1
    assert login_logs[0]["username"] == "admin"

    # Limit check
    limited = get_audit_logs(limit=2, db_path=phase_d_db)
    assert len(limited) == 2


def test_audit_log_route_access(phase_d_db: Path):
    """Verify RBAC on /audit view and content rendering."""
    log_audit_event(
        username="analyst",
        action="ALERT_TRIAGE",
        target="10.0.0.1",
        details="Investigated port scan on 10.0.0.1",
        db_path=phase_d_db,
    )

    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    # 1. Admin should have access
    with app.test_client() as client:
        client.post("/login", data={"username": "admin", "password": "admin123!"})
        res = client.get("/audit")
        assert res.status_code == 200
        assert b"Audit Log" in res.data
        assert b"Investigated port scan on 10.0.0.1" in res.data
        assert b"ALERT_TRIAGE" in res.data


        # Filter query parameter test
        res_filter = client.get("/audit?action=ALERT_TRIAGE")
        assert res_filter.status_code == 200
        assert b"Investigated port scan on 10.0.0.1" in res_filter.data

    # 2. Analyst should NOT have access
    with app.test_client() as client:
        client.post("/login", data={"username": "analyst", "password": "analyst123!"})
        res = client.get("/audit", follow_redirects=True)
        assert b"Access restricted" in res.data

    # 3. Viewer should NOT have access
    with app.test_client() as client:
        client.post("/login", data={"username": "viewer", "password": "viewer123!"})
        res = client.get("/audit", follow_redirects=True)
        assert b"Access restricted" in res.data


# ---------------------------------------------------------------------------
# 2. PDF Report Generation Tests
# ---------------------------------------------------------------------------

def test_generate_alert_pdf_structure():
    """Test generating a single incident PDF with metadata, ATT&CK, and packets."""
    alert = {
        "id": 42,
        "rule": "port_scan",
        "severity": "high",
        "client_name": "Manila-Branch",
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.1",
        "timestamp": "2026-10-24 10:30:00",
        "description": "Port scan probing 60 ports <script>alert(1)</script>",
        "status": "in_progress",
        "analyst_note": "Triage notes with & special chars 'safe' check",
        "mitre_id": "T1046",
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Service Discovery",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
    }
    packets = [
        {"num": 1, "rel_time": "0.0010", "src": "10.0.0.99", "dst": "10.0.0.1", "proto": "TCP/80", "flags": "S", "len": 60},
        {"num": 2, "rel_time": "0.0020", "src": "10.0.0.99", "dst": "10.0.0.1", "proto": "TCP/443", "flags": "S", "len": 60},
    ]

    pdf_bytes = generate_alert_pdf(alert, packets)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_summary_pdf_structure():
    """Test generating executive summary PDF report."""
    alerts = [
        {
            "id": 1,
            "rule": "port_scan",
            "severity": "high",
            "status": "open",
            "client_name": "HQ",
            "src_ip": "10.0.0.50",
            "dst_ip": "10.0.0.1",
            "timestamp": "2026-10-24 09:00:00",
            "mitre_id": "T1046",
        },
        {
            "id": 2,
            "rule": "cleartext_protocols",
            "severity": "low",
            "status": "resolved",
            "client_name": "Branch-A",
            "src_ip": "192.168.1.10",
            "dst_ip": "192.168.1.2",
            "timestamp": "2026-10-24 09:15:00",
            "mitre_id": "T1040",
        },
    ]

    pdf_bytes = generate_summary_pdf(alerts, client_name="HQ")
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF-")


def test_pdf_routes(phase_d_db: Path):
    """Test web routes for downloading alert PDF and summary PDF."""
    aid = insert_alert(
        rule="syn_burst",
        severity="high",
        src_ip="172.16.0.4",
        dst_ip="172.16.0.1",
        packet_time="2026-10-24T08:00:00",
        description="SYN burst test alert",
        client_name="BPO-Client-1",
        db_path=phase_d_db,
    )

    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    with app.test_client() as client:
        client.post("/login", data={"username": "analyst", "password": "analyst123!"})

        # 1. Download incident PDF
        res_alert_pdf = client.get(f"/alert/{aid}/report.pdf")
        assert res_alert_pdf.status_code == 200
        assert res_alert_pdf.content_type == "application/pdf"
        assert f"filename=bantaynet_incident_{aid}.pdf" in res_alert_pdf.headers.get("Content-Disposition", "")
        assert res_alert_pdf.data.startswith(b"%PDF-")

        # 2. Download executive summary PDF
        res_sum_pdf = client.get("/report/summary.pdf")
        assert res_sum_pdf.status_code == 200
        assert res_sum_pdf.content_type == "application/pdf"
        assert "filename=bantaynet_threat_summary.pdf" in res_sum_pdf.headers.get("Content-Disposition", "")
        assert res_sum_pdf.data.startswith(b"%PDF-")

        # 3. Nonexistent alert returns 404
        res_404 = client.get("/alert/99999/report.pdf")
        assert res_404.status_code == 404

    # 4. Verify downloads logged in audit table
    logs = get_audit_logs(limit=10, db_path=phase_d_db)
    actions = [l["action"] for l in logs]
    assert "export_pdf" in actions
    assert "export_summary_pdf" in actions


# ---------------------------------------------------------------------------
# 3. Email Notifier Tests
# ---------------------------------------------------------------------------

def test_send_alert_email_when_disabled():
    """When notifications are disabled, function exits immediately without network operations."""
    cfg = Config(notifications=NotificationSettings(enabled=False))
    alert = {"id": 1, "rule": "syn_burst", "severity": "high"}
    assert send_alert_email(alert, settings=cfg) is False


def test_send_alert_email_severity_filter():
    """Alerts below min_severity threshold are ignored."""
    cfg = Config(notifications=NotificationSettings(enabled=True, min_severity="high"))
    # Low severity alert should be skipped
    alert_low = {"id": 1, "rule": "cleartext_protocols", "severity": "low"}
    assert send_alert_email(alert_low, settings=cfg) is False

    # Medium severity alert should be skipped when min_severity is high
    alert_med = {"id": 2, "rule": "host_sweep", "severity": "medium"}
    assert send_alert_email(alert_med, settings=cfg) is False


def test_send_alert_email_successful_dispatch():
    """Mock SMTP dispatch to verify email composition and send call."""
    cfg = Config(
        notifications=NotificationSettings(
            enabled=True,
            smtp_server="smtp.example.com",
            smtp_port=587,
            use_tls=True,
            sender="soc@example.com",
            recipient="oncall@example.com",
            min_severity="high",
        )
    )
    alert = {
        "id": 101,
        "rule": "port_scan",
        "severity": "high",
        "client_name": "Customer-A",
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "timestamp": "2026-10-24 10:00:00",
        "description": "Port scan probe against web server",
    }

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance) as mock_smtp_class:
        result = send_alert_email(alert, settings=cfg)
        assert result is True
        mock_smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.send_message.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()

        # Check msg content
        sent_msg = mock_smtp_instance.send_message.call_args[0][0]
        assert "[BantayNet HIGH] port_scan detected from 1.2.3.4 (Customer-A)" in sent_msg["Subject"]
        assert sent_msg["From"] == "soc@example.com"
        assert sent_msg["To"] == "oncall@example.com"


def test_send_alert_email_failure_graceful():
    """If SMTP connection fails, error is caught and logged, returning False without raising."""
    cfg = Config(
        notifications=NotificationSettings(
            enabled=True,
            smtp_server="nonexistent.example.local",
            smtp_port=25,
            use_tls=False,
            min_severity="low",
        )
    )
    alert = {"id": 102, "rule": "port_scan", "severity": "high"}

    with patch("smtplib.SMTP", side_effect=OSError("Network unreachable")):
        result = send_alert_email(alert, settings=cfg)
        assert result is False
