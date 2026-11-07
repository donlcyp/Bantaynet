"""Comprehensive security test suite verifying production deployment defenses:
- HTTP Security Headers (OWASP)
- CSRF Token Validation
- Open Redirect (CWE-601) Prevention
- Brute Force Login Rate Limiting
- PCAP File Magic Bytes Inspection
- Path Traversal (LFI) Mitigation
- CSV Formula Injection Sanitization
- Password Policy Enforcement
"""

from __future__ import annotations

import io
from pathlib import Path
import pytest

from dashboard.app import app, is_safe_url, is_valid_pcap_header, _login_failures
from src.db import create_user, init_db
from src.export import _sanitize_csv_cell, write_alerts_csv


@pytest.fixture
def test_app_client():
    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True
    with app.test_client() as client:
        yield client


def test_security_headers_present(test_app_client):
    """Verify OWASP recommended security headers on HTTP responses."""
    resp = test_app_client.get("/login")
    assert resp.status_code == 200
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-XSS-Protection") == "1; mode=block"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in resp.headers.get("Content-Security-Policy", "")


def test_open_redirect_prevention(test_app_client):
    """Verify external domains in next= are ignored to prevent CWE-601 Open Redirect."""
    with app.test_request_context("/login?next=https://evil.com/phishing"):
        assert not is_safe_url("https://evil.com/phishing")
        assert not is_safe_url("//evil.com")
        assert not is_safe_url("javascript:alert(1)")
        assert is_safe_url("/audit")
        assert is_safe_url("/")


def test_csrf_protection_blocks_unauthorized_post():
    """Verify CSRF middleware enforces tokens on state-changing POST requests."""
    app.config["TESTING"] = True
    app.config["FORCE_CSRF_TESTING"] = True

    try:
        with app.test_client() as client:
            # POST without CSRF token must fail with 403 Forbidden
            res = client.post("/login", data={"username": "admin", "password": "any"})
            assert res.status_code == 403
            assert b"CSRF" in res.data
    finally:
        app.config["FORCE_CSRF_TESTING"] = False


def test_login_rate_limiting(test_app_client):
    """Verify repeated failed logins trigger rate limit lockout."""
    _login_failures.clear()
    for _ in range(5):
        resp = test_app_client.post("/login", data={"username": "attacker", "password": "wrong"})
        assert resp.status_code == 200

    # 6th attempt should be blocked with 429
    blocked_resp = test_app_client.post("/login", data={"username": "attacker", "password": "wrong"})
    assert blocked_resp.status_code == 429
    assert b"locked out" in blocked_resp.data
    _login_failures.clear()


def test_pcap_magic_header_validation():
    """Verify PCAP magic bytes checker distinguishes real PCAPs from imposters."""
    # Real PCAP magic (little endian)
    pcap_valid = io.BytesIO(b"\xd4\xc3\xb2\xa1\x00\x02\x00\x04")
    assert is_valid_pcap_header(pcap_valid) is True

    # Real PCAPNG magic
    pcapng_valid = io.BytesIO(b"\x0a\x0d\x0d\x0a\x00\x00\x00\x00")
    assert is_valid_pcap_header(pcapng_valid) is True

    # Fake executable disguised as .pcap
    exe_fake = io.BytesIO(b"MZ\x90\x00\x03\x00\x00\x00")
    assert is_valid_pcap_header(exe_fake) is False

    # Shell script disguised as .pcap
    sh_fake = io.BytesIO(b"#!/bin/bash\nrm -rf /")
    assert is_valid_pcap_header(sh_fake) is False


def test_csv_injection_sanitization():
    """Verify leading formula trigger characters are escaped in CSV output."""
    assert _sanitize_csv_cell("=1+1") == "'=1+1"
    assert _sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert _sanitize_csv_cell("-2+3") == "'-2+3"
    assert _sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert _sanitize_csv_cell("Normal Description") == "Normal Description"


def test_password_standards_validation():
    """Verify NIST SP 800-63B and OWASP password complexity standards."""
    from src.security import validate_password_standards

    # Empty
    assert "empty" in validate_password_standards("")[0].lower()

    # Too short (< 8)
    errs = validate_password_standards("Ab1!")
    assert any("at least 8 characters" in e for e in errs)

    # Missing uppercase
    errs = validate_password_standards("lowercase123!")
    assert any("uppercase" in e for e in errs)

    # Missing lowercase
    errs = validate_password_standards("UPPERCASE123!")
    assert any("lowercase" in e for e in errs)

    # Missing digit
    errs = validate_password_standards("NoDigitsHere!!")
    assert any("number" in e for e in errs)

    # Missing special symbol
    errs = validate_password_standards("NoSpecialSymbol123")
    assert any("special character" in e for e in errs)

    # Contains username
    errs = validate_password_standards("MyAdminUser123!", username="admin")
    assert any("contain your username" in e for e in errs)

    # Common weak password
    errs = validate_password_standards("password123")
    assert any("too common" in e for e in errs)

    # Compliant passwords (including .env sample passwords)
    assert validate_password_standards("?andMIN31241!") == []
    assert validate_password_standards("!AnAlyzer3124!") == []
    assert validate_password_standards("&vIEwer31514!") == []
    assert validate_password_standards("Correct-Horse-Battery-Staple#99") == []


def test_username_standards_validation():
    """Verify username length and character set validation."""
    from src.security import validate_username_standards

    assert validate_username_standards("") != []
    assert validate_username_standards("ab") != []  # Too short (< 3)
    assert validate_username_standards("a" * 33) != []  # Too long (> 32)
    assert validate_username_standards("user<script>") != []  # Invalid chars

    # Valid
    assert validate_username_standards("soc_analyst") == []
    assert validate_username_standards("admin.soc-1") == []


def test_login_input_error_checking(test_app_client):
    """Verify login route rejects empty and oversized inputs with HTTP 400 and clear error messages."""
    # Empty credentials
    res_empty = test_app_client.post("/login", data={"username": "", "password": ""})
    assert res_empty.status_code == 400
    assert b"Please provide both username and password" in res_empty.data

    # Oversized credentials
    res_oversized = test_app_client.post("/login", data={"username": "a" * 70, "password": "p" * 150})
    assert res_oversized.status_code == 400
    assert b"exceeds allowed credential limits" in res_oversized.data


def test_session_inactivity_timeout():
    """Verify session inactivity middleware automatically expires idle sessions and redirects to login."""
    import time
    from dashboard.app import app

    app.config["TESTING"] = True
    app.config["FORCE_AUTH_TESTING"] = True

    with app.test_client() as client:
        # 1. Login successfully
        res = client.post("/login", data={"username": "analyst", "password": "analyst123!"}, follow_redirects=True)
        assert res.status_code == 200

        # 2. Simulate elapsed idle time beyond 15-minute threshold (901 seconds ago)
        with client.session_transaction() as sess:
            sess["last_activity"] = time.time() - 950

        # 3. Next request should trigger auto-logout and redirect
        resp_after_idle = client.get("/", follow_redirects=True)
        assert b"Session expired due to inactivity" in resp_after_idle.data
        assert b"Sign In" in resp_after_idle.data


def test_sha256_evidence_hashing_and_chain_of_custody(tmp_path):
    """Verify SHA-256 calculation on evidence files and chain-of-custody metadata preservation."""
    import hashlib
    from src.alerts import Alert
    from src.evidence import calculate_sha256
    from src.db import _format_alert_dict
    from src.report_pdf import generate_alert_pdf

    # 1. Test raw SHA-256 calculation
    sample_file = tmp_path / "sample.bin"
    sample_data = b"BantayNet Digital Forensic Evidence Preservation"
    sample_file.write_bytes(sample_data)

    expected_sha = hashlib.sha256(sample_data).hexdigest()
    assert calculate_sha256(sample_file) == expected_sha
    assert calculate_sha256(tmp_path / "non_existent.bin") == ""

    # 2. Test Alert data model serialization with SHA-256
    alert = Alert(
        rule="port_scan",
        severity="high",
        src="192.168.1.50",
        dst="192.168.1.1",
        first_ts=1700000000.0,
        last_ts=1700000010.0,
        packet_count=200,
        summary="Port scan detected",
        details={"evidence_sha256": expected_sha, "source_pcap_sha256": "abcdef123456"},
        evidence_sha256=expected_sha,
    )
    alert_dict = alert.to_dict()
    assert alert_dict["evidence_sha256"] == expected_sha
    assert alert_dict["details"]["evidence_sha256"] == expected_sha

    # 3. Test database row enrichment
    enriched = _format_alert_dict({
        "id": 42,
        "rule": "port_scan",
        "severity": "high",
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "details_json": '{"evidence_sha256": "' + expected_sha + '", "source_pcap_sha256": "abcdef123456"}',
    })
    assert enriched["evidence_sha256"] == expected_sha
    assert enriched["source_pcap_sha256"] == "abcdef123456"

    # 4. Test PDF generation with forensic hashes
    pdf_bytes = generate_alert_pdf(enriched, [])
    assert pdf_bytes is not None
    assert len(pdf_bytes) > 1000


def test_custom_error_pages_user_facing(test_app_client):
    """Verify custom branded user-facing error pages for 404, 403, and invalid endpoints."""
    # 404 Not Found on nonexistent route
    res_404 = test_app_client.get("/nonexistent-endpoint-xyz")
    assert res_404.status_code == 404
    assert b"404" in res_404.data
    assert b"Resource Not Found" in res_404.data
    assert b"Return to Dashboard" in res_404.data

    # Log in as analyst to test protected 404
    test_app_client.post("/login", data={"username": "analyst", "password": "analyst123!"})
    res_alert = test_app_client.get("/alert/99999")
    assert res_alert.status_code == 404
    assert b"Alert #99999 not found" in res_alert.data


def test_duplicate_account_creation_prevention(test_app_client, tmp_path):
    """Verify system rejects duplicate account creation for both virtual and existing DB accounts."""
    from src.db import create_user, get_user_by_username

    test_db = tmp_path / "test_auth_dup.db"

    # 1. Attempting to create reserved virtual test account (e.g. 'admin' or 'analyst') must fail
    with pytest.raises(ValueError, match="already exists"):
        create_user("admin", "ValidPass123!", "admin", db_path=test_db)

    with pytest.raises(ValueError, match="already exists"):
        create_user("analyst", "ValidPass123!", "analyst", db_path=test_db)

    # 2. Creating a unique account succeeds
    uid = create_user("brand_new_analyst", "ValidPass123!", "analyst", db_path=test_db)
    assert uid > 0

    # 3. Attempting to create duplicate of that newly created account must fail
    with pytest.raises(ValueError, match="already exists"):
        create_user("brand_new_analyst", "AnotherPass999!", "viewer", db_path=test_db)

    # 4. Case-insensitive duplicate check
    with pytest.raises(ValueError, match="already exists"):
        create_user("BRAND_NEW_ANALYST", "AnotherPass999!", "viewer", db_path=test_db)

    # 5. Verify get_user_by_username
    assert get_user_by_username("admin", db_path=test_db) is not None
    assert get_user_by_username("brand_new_analyst", db_path=test_db) is not None
    assert get_user_by_username("BRAND_NEW_ANALYST", db_path=test_db) is not None
    assert get_user_by_username("completely_nonexistent_user_xyz", db_path=test_db) is None


def test_hybrid_login_virtual_accounts(test_app_client):
    """Verify hybrid login allows authentication using either username or email for system accounts."""
    from src.db import authenticate_user

    # 1. Admin login by username and by email
    assert authenticate_user("admin", "admin123!") is not None
    assert authenticate_user("admin@bantaynet.local", "admin123!") is not None
    assert authenticate_user("ADMIN@BANTAYNET.LOCAL", "admin123!") is not None

    # 2. Analyst login by username and by email
    assert authenticate_user("analyst", "analyst123!") is not None
    assert authenticate_user("analyst@bantaynet.local", "analyst123!") is not None

    # 3. Viewer login by username and by email
    assert authenticate_user("viewer", "viewer123!") is not None
    assert authenticate_user("viewer@bantaynet.local", "viewer123!") is not None

    # 4. HTTP client login flow using email
    res = test_app_client.post(
        "/login",
        data={"username": "admin@bantaynet.local", "password": "admin123!"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"Logged in successfully as admin" in res.data


def test_hybrid_login_database_user(tmp_path):
    """Verify database accounts can be created with email and logged into using username or email."""
    from src.db import authenticate_user, create_user, get_user_by_email

    test_db = tmp_path / "test_hybrid_db.db"

    uid = create_user("soc_ranger", "RangerPass123!", "analyst", email="ranger@cybersecurity.gov", db_path=test_db)
    assert uid > 0

    # Retrieve by email
    user = get_user_by_email("ranger@cybersecurity.gov", db_path=test_db)
    assert user is not None
    assert user["username"] == "soc_ranger"
    assert user["email"] == "ranger@cybersecurity.gov"

    # Authenticate by username
    user_by_user = authenticate_user("soc_ranger", "RangerPass123!", db_path=test_db)
    assert user_by_user is not None
    assert user_by_user["id"] == uid

    # Authenticate by email (case-insensitive)
    user_by_email = authenticate_user("RANGER@CYBERSECURITY.GOV", "RangerPass123!", db_path=test_db)
    assert user_by_email is not None
    assert user_by_email["id"] == uid


def test_email_validation_and_duplicate_prevention(tmp_path):
    """Verify system enforces email format standards and prevents duplicate emails."""
    from src.db import create_user

    test_db = tmp_path / "test_email_dup.db"

    # 1. Invalid email format must be rejected
    with pytest.raises(ValueError, match="Invalid email address format"):
        create_user("bad_email_user", "ValidPass123!", "viewer", email="notanemail", db_path=test_db)

    # 2. Colliding with reserved system account email must be rejected
    with pytest.raises(ValueError, match="already exists"):
        create_user("imposter_admin", "ValidPass123!", "viewer", email="admin@bantaynet.local", db_path=test_db)

    # 3. Create initial valid user with email
    create_user("user_one", "ValidPass123!", "viewer", email="first_operator@soc.corp", db_path=test_db)

    # 4. Attempting to create another user with same email must be rejected
    with pytest.raises(ValueError, match="already exists"):
        create_user("user_two", "ValidPass123!", "viewer", email="first_operator@soc.corp", db_path=test_db)

    # 5. Case-insensitive duplicate email check
    with pytest.raises(ValueError, match="already exists"):
        create_user("user_three", "ValidPass123!", "viewer", email="FIRST_OPERATOR@SOC.CORP", db_path=test_db)






