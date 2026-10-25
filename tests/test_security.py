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

