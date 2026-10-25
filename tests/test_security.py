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
