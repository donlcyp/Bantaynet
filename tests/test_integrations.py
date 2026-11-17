"""Unit tests for integrations dispatcher and store notify wiring (T2 & T6)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.alerts import Alert
from src.config import Config, NotificationSettings
import src.db as db_mod
from src.db import get_alerts, init_db
from src.integrations import dispatch, dispatch_email
from src.store import store_alerts


@pytest.fixture
def test_db(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_store_notify.db"
    monkeypatch.setattr(db_mod, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db_mod, "DEFAULT_SQLITE_PATH", db_file)
    monkeypatch.setattr(db_mod, "DB_PATH", db_file)
    init_db(db_file)
    yield db_file


def _make_alert(rule="syn_burst", severity="high", src="192.168.1.50", dst="192.168.1.1"):
    return Alert(
        rule=rule,
        severity=severity,
        src=src,
        dst=dst,
        first_ts=1700000000.0,
        last_ts=1700000002.0,
        packet_count=150,
        summary=f"{rule} test incident",
        protocol="TCP",
        dst_port="80",
    )


# ---------------------------------------------------------------------------
# T2: Wire alert email in store_alerts
# ---------------------------------------------------------------------------

def test_store_alerts_with_notify_enabled(test_db: Path):
    """When notify=True, store_alerts calls dispatch with the alerts."""
    alert = _make_alert()
    with patch("src.integrations.dispatch") as mock_dispatch:
        inserted = store_alerts([alert], "test.pcap", client_name="LabClient", notify=True)
        assert len(inserted) == 1
        mock_dispatch.assert_called_once()
        call_alerts, call_client = mock_dispatch.call_args[0][0], mock_dispatch.call_args[1].get("client_name")
        assert len(call_alerts) == 1
        assert call_client == "LabClient"

    # Verify alert was stored in DB
    db_alerts = get_alerts(db_path=test_db)
    assert len(db_alerts) == 1
    assert db_alerts[0]["rule"] == "syn_burst"


def test_store_alerts_with_notify_disabled(test_db: Path):
    """When notify=False, dispatch is not invoked."""
    alert = _make_alert()
    with patch("src.integrations.dispatch") as mock_dispatch:
        inserted = store_alerts([alert], "test.pcap", notify=False)
        assert len(inserted) == 1
        mock_dispatch.assert_not_called()

    db_alerts = get_alerts(db_path=test_db)
    assert len(db_alerts) == 1


def test_store_alerts_dispatch_failure_never_breaks_storage(test_db: Path):
    """If the integrations dispatcher raises an unexpected exception, storage still succeeds."""
    alert = _make_alert()
    with patch("src.integrations.dispatch", side_effect=RuntimeError("Network/dispatcher crashed")):
        inserted = store_alerts([alert], "test.pcap", notify=True)
        assert len(inserted) == 1

    db_alerts = get_alerts(db_path=test_db)
    assert len(db_alerts) == 1
    assert db_alerts[0]["rule"] == "syn_burst"


def test_email_dispatch_when_enabled():
    """With email enabled and a mocked sender, one high alert sends one email."""
    cfg = Config(
        notifications=NotificationSettings(
            enabled=True,
            min_severity="high",
            sender="alerts@test.local",
            recipient="oncall@test.local",
        )
    )
    alerts = [_make_alert(rule="syn_burst", severity="high")]

    with patch("src.integrations.send_alert_email", return_value=True) as mock_send:
        results = dispatch(alerts, client_name="HQ", cfg=cfg)
        assert results["email"] == 1
        mock_send.assert_called_once()
        call_alert = mock_send.call_args[0][0]
        assert call_alert["rule"] == "syn_burst"
        assert call_alert["src_ip"] == "192.168.1.50"
        assert call_alert["client_name"] == "HQ"


def test_email_dispatch_when_disabled():
    """When notifications are disabled in config, zero emails are dispatched."""
    cfg = Config(notifications=NotificationSettings(enabled=False))
    alerts = [_make_alert(severity="high")]

    with patch("src.integrations.send_alert_email") as mock_send:
        results = dispatch(alerts, client_name="HQ", cfg=cfg)
        assert results["email"] == 0
        mock_send.assert_not_called()


def test_email_dispatch_min_severity_filtering():
    """Alerts below configured min_severity are not emailed."""
    cfg = Config(
        notifications=NotificationSettings(
            enabled=True,
            min_severity="high",
        )
    )
    # Low and medium alerts
    alerts = [
        _make_alert(rule="cleartext", severity="low"),
        _make_alert(rule="host_sweep", severity="medium"),
    ]

    with patch("src.integrations.send_alert_email", return_value=False) as mock_send:
        results = dispatch(alerts, client_name="HQ", cfg=cfg)
        assert results["email"] == 0


def test_email_dispatch_failure_handled_gracefully():
    """If send_alert_email raises an error, dispatch_email catches it and returns 0."""
    cfg = Config(notifications=NotificationSettings(enabled=True, min_severity="low"))
    alerts = [_make_alert()]

    with patch("src.integrations.send_alert_email", side_effect=OSError("SMTP down")):
        results = dispatch(alerts, client_name="HQ", cfg=cfg)
        assert results["email"] == 0


# ---------------------------------------------------------------------------
# T6: Dispatcher isolation
# ---------------------------------------------------------------------------

def test_dispatcher_isolation_one_failure_does_not_stop_others():
    """If one integration fails completely, the other integrations still execute."""
    cfg = Config(
        notifications=NotificationSettings(enabled=True, min_severity="low")
    )
    alerts = [_make_alert(severity="high")]

    # Mock email to raise an unhandled exception, while telegram succeeds
    with patch("src.integrations.dispatch_email", side_effect=Exception("Email module fatal crash")), \
         patch("src.integrations.dispatch_telegram", return_value=1) as mock_tg, \
         patch("src.integrations.dispatch_syslog", return_value=1) as mock_syslog:
        
        results = dispatch(alerts, client_name="Branch-1", cfg=cfg)
        
        # Email failed and reported 0
        assert results["email"] == 0
        # But telegram and syslog were still called and completed!
        assert results["telegram"] == 1
        assert results["syslog"] == 1
        mock_tg.assert_called_once()
        mock_syslog.assert_called_once()

