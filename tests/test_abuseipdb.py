"""Unit tests for AbuseIPDB IP reputation integration (T4)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch
import pytest

from src.alerts import Alert
from src.config import AbuseIPDBSettings, Config, IntegrationsSettings
import src.db as db_mod
from src.db import get_alert_by_id, init_db, insert_alert
from src.integrations import dispatch
from src.integrations.abuseipdb import (
    check_abuseipdb_alerts,
    check_ip_reputation,
    clear_cache,
    is_public_ip,
)
from src.store import store_alerts


@pytest.fixture(autouse=True)
def _reset_reputation_cache():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def test_db(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_abuseipdb.db"
    monkeypatch.setattr(db_mod, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db_mod, "DEFAULT_SQLITE_PATH", db_file)
    monkeypatch.setattr(db_mod, "DB_PATH", db_file)
    init_db(db_file)
    yield db_file


def _mock_http_response(payload: dict[str, Any], status: int = 200):
    raw_bytes = json.dumps(payload).encode("utf-8")
    resp = io.BytesIO(raw_bytes)
    setattr(resp, "status", status)
    return resp


# ---------------------------------------------------------------------------
# Public vs Private IP filtering
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "ip_str, expected_public",
    [
        ("192.168.1.1", False),
        ("10.0.0.5", False),
        ("172.16.1.100", False),
        ("127.0.0.1", False),
        ("169.254.10.20", False),
        ("::1", False),
        ("fc00::1", False),
        ("fe80::1", False),
        ("invalid-ip", False),
        ("", False),
        ("118.25.6.39", True),
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("2001:4860:4860::8888", True),
    ],
)
def test_is_public_ip(ip_str: str, expected_public: bool):
    is_pub, label = is_public_ip(ip_str)
    assert is_pub is expected_public
    if not is_pub:
        assert label == "Internal address"
    else:
        assert label == "Public address"


def test_private_ip_is_skipped_and_labeled_internal():
    """Private IPs must never make an HTTP request and must return 'Internal address'."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        score, note = check_ip_reputation("192.168.1.50", api_key="dummy_key")
        assert score is None
        assert note == "Internal address"
        mock_urlopen.assert_not_called()


def test_no_api_key_means_silent_skip():
    """When no ABUSEIPDB_API_KEY is configured, public IPs return None without making network calls."""
    with patch("urllib.request.urlopen") as mock_urlopen:
        score, note = check_ip_reputation("118.25.6.39", api_key="")
        assert score is None
        assert note is None
        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# Successful API lookup and caching
# ---------------------------------------------------------------------------

def test_public_ip_successful_lookup():
    """Mocked API lookup returns parsed abuse score and formatted note."""
    payload = {
        "data": {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 85,
            "totalReports": 14,
            "countryCode": "CN",
        }
    }

    with patch("urllib.request.urlopen", return_value=_mock_http_response(payload)) as mock_urlopen:
        score, note = check_ip_reputation("118.25.6.39", api_key="valid_test_key")
        assert score == 85
        assert "85%" in note
        assert "14 reports" in note
        assert "CN" in note
        mock_urlopen.assert_called_once()


def test_reputation_lookup_is_cached():
    """Subsequent lookups for the same IP return from cache without re-querying the API."""
    payload = {
        "data": {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 92,
            "totalReports": 50,
            "countryCode": "US",
        }
    }

    with patch("urllib.request.urlopen", return_value=_mock_http_response(payload)) as mock_urlopen:
        score1, note1 = check_ip_reputation("118.25.6.39", api_key="valid_test_key", cache_hours=24)
        score2, note2 = check_ip_reputation("118.25.6.39", api_key="valid_test_key", cache_hours=24)
        assert score1 == score2 == 92
        assert note1 == note2
        # Only called once due to caching
        assert mock_urlopen.call_count == 1


# ---------------------------------------------------------------------------
# Error handling (Quota exceeded, invalid key, network timeout)
# ---------------------------------------------------------------------------

def test_quota_exceeded_error_handling():
    """HTTP 429 quota exceeded logs a warning and returns (None, None)."""
    http_err = urllib.error.HTTPError(
        url="https://api.abuseipdb.com",
        code=429,
        msg="Too Many Requests",
        hdrs={},
        fp=io.BytesIO(b"Daily quota exceeded"),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        score, note = check_ip_reputation("118.25.6.39", api_key="valid_test_key")
        assert score is None
        assert note is None


def test_unauthorized_key_error_handling():
    """HTTP 401 unauthorized logs a warning and returns (None, None)."""
    http_err = urllib.error.HTTPError(
        url="https://api.abuseipdb.com",
        code=401,
        msg="Unauthorized",
        hdrs={},
        fp=io.BytesIO(b"Invalid API Key"),
    )

    with patch("urllib.request.urlopen", side_effect=http_err):
        score, note = check_ip_reputation("118.25.6.39", api_key="bad_test_key")
        assert score is None
        assert note is None


def test_network_failure_never_crashes():
    """Network connection timeout/refusal gracefully returns (None, None)."""
    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        score, note = check_ip_reputation("118.25.6.39", api_key="valid_test_key")
        assert score is None
        assert note is None


# ---------------------------------------------------------------------------
# Database and Dispatch Integration
# ---------------------------------------------------------------------------

def test_check_abuseipdb_alerts_stores_reputation_in_database(test_db: Path, monkeypatch):
    """Pipeline processes alerts, marks internal IP and scores public IP in the database."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "mock_key_12345")

    cfg = Config(
        integrations=IntegrationsSettings(
            abuseipdb=AbuseIPDBSettings(enabled=True, max_age_days=90, cache_hours=24)
        )
    )

    # Insert two alerts: one internal source, one public source
    aid_internal = insert_alert(
        rule="syn_burst",
        severity="high",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        packet_time=1700000000.0,
        description="Internal burst",
        db_path=test_db,
    )
    aid_public = insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="118.25.6.39",
        dst_ip="192.168.1.1",
        packet_time=1700000001.0,
        description="External port scan",
        db_path=test_db,
    )

    alerts = [
        {"id": aid_internal, "src_ip": "192.168.1.10", "rule": "syn_burst"},
        {"id": aid_public, "src_ip": "118.25.6.39", "rule": "port_scan"},
    ]

    payload = {
        "data": {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 99,
            "totalReports": 120,
            "countryCode": "CN",
        }
    }

    with patch("urllib.request.urlopen", return_value=_mock_http_response(payload)):
        count = check_abuseipdb_alerts(alerts, cfg=cfg)
        assert count == 2

    # Verify internal alert record in DB
    rec_internal = get_alert_by_id(aid_internal, db_path=test_db)
    assert rec_internal["reputation_score"] is None
    assert rec_internal["reputation_note"] == "Internal address"

    # Verify public alert record in DB
    rec_public = get_alert_by_id(aid_public, db_path=test_db)
    assert rec_public["reputation_score"] == 99
    assert "99%" in rec_public["reputation_note"]
    assert "120 reports" in rec_public["reputation_note"]


def test_dispatch_pipeline_with_abuseipdb_enabled(test_db: Path, monkeypatch):
    """Calling store_alerts with notify=True invokes dispatch and updates public IP reputation."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "mock_key")
    cfg = Config(
        integrations=IntegrationsSettings(
            abuseipdb=AbuseIPDBSettings(enabled=True)
        )
    )

    payload = {
        "data": {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 77,
            "totalReports": 23,
            "countryCode": "KR",
        }
    }

    alert = Alert(
        rule="port_scan",
        severity="high",
        src="118.25.6.39",
        dst="192.168.1.1",
        first_ts=1700000000.0,
        last_ts=1700000002.0,
        packet_count=55,
        summary="Public scan",
        protocol="TCP",
    )

    with patch("src.config.load_config", return_value=cfg), \
         patch("urllib.request.urlopen", return_value=_mock_http_response(payload)):
        inserted = store_alerts([alert], "test.pcap", notify=True)
        assert len(inserted) == 1
        aid = inserted[0]

        row = get_alert_by_id(aid, db_path=test_db)
        assert row["reputation_score"] == 77
        assert "77%" in row["reputation_note"]


# ---------------------------------------------------------------------------
# Dashboard Presentation and Escaping
# ---------------------------------------------------------------------------

def test_dashboard_renders_reputation_badges_and_escapes(test_db: Path, monkeypatch):
    """Verify reputation score and badge render in dashboard, and HTML special chars are escaped."""
    from dashboard.app import app

    monkeypatch.setattr("dashboard.app.PROJECT_ROOT", test_db.parent)

    aid = insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="118.25.6.39",
        dst_ip="10.0.0.1",
        packet_time=1700000000.0,
        description="Public scanner",
        reputation_score=88,
        reputation_note="Score: 88% <script>alert('xss')</script>",
        db_path=test_db,
    )

    app.config["TESTING"] = True
    with app.test_client() as client:
        # 1. Alert list view (index)
        res = client.get("/")
        assert res.status_code == 200
        html = res.data.decode("utf-8")
        assert "Reputation" in html
        assert "88% Abuse" in html
        assert "<script>alert('xss')</script>" not in html
        assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "&lt;script&gt;alert('xss')&lt;/script&gt;" in html

        # 2. Alert detail view
        res_detail = client.get(f"/alert/{aid}")
        assert res_detail.status_code == 200
        detail_html = res_detail.data.decode("utf-8")
        assert "IP Reputation" in detail_html
        assert "88% Confidence (Malicious)" in detail_html
        assert "<script>alert('xss')</script>" not in detail_html
        assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in detail_html or "&lt;script&gt;alert('xss')&lt;/script&gt;" in detail_html


