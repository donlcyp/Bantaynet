"""Unit tests for Syslog / SIEM export integration (T5)."""

from __future__ import annotations

import json
import socket
import threading
from typing import Any
from unittest.mock import patch
import pytest

from src.alerts import Alert
from src.config import Config, IntegrationsSettings, SyslogSettings
from src.integrations import dispatch
from src.integrations.syslog_out import (
    escape_cef_extension,
    escape_cef_header,
    format_cef_alert,
    format_json_alert,
    send_syslog_alerts,
)


def _make_alert_dict(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "rule": "port_scan",
        "name": "Network Service Discovery",
        "severity": "high",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "first_ts": 1700000000.5,
        "summary": "Port scan detected from 192.168.1.100",
        "client_name": "TestClient",
    }
    base.update(kwargs)
    return base


def test_escape_cef_header():
    """Header fields must escape pipe and backslash characters."""
    assert escape_cef_header("Port|Scan\\Test") == "Port\\|Scan\\\\Test"
    assert escape_cef_header("Normal Text") == "Normal Text"
    assert escape_cef_header(None) == ""


def test_escape_cef_extension():
    """Extension value fields must escape equals and backslash characters."""
    assert escape_cef_extension("val=1\\2") == "val\\=1\\\\2"
    assert escape_cef_extension("Simple_Val") == "Simple_Val"
    assert escape_cef_extension(None) == ""


def test_format_cef_alert():
    """Alert correctly formats as ArcSight CEF with required header and extension fields."""
    alert = _make_alert_dict(rule="syn_burst", severity="high")
    cef_msg = format_cef_alert(alert)

    assert cef_msg.startswith("CEF:0|BantayNet|BantayNet|1.0|syn_burst|")
    assert "|high|" in cef_msg
    assert "src=192.168.1.100" in cef_msg
    assert "dst=10.0.0.1" in cef_msg
    assert "proto=TCP" in cef_msg
    assert "cs1=T1498" in cef_msg
    assert "cs1Label=mitre" in cef_msg
    assert "rt=1700000000500" in cef_msg


def test_format_cef_escaping_applied():
    """Special characters in rule, name, and values are escaped in CEF."""
    alert = _make_alert_dict(
        rule="weird|rule\\name",
        name="Event|With|Pipes\\And\\Backslashes",
        src_ip="192.168.1.1\\=test",
    )
    cef_msg = format_cef_alert(alert)

    # Header pipe escaped
    assert "weird\\|rule\\\\name" in cef_msg
    assert "Event\\|With\\|Pipes\\\\And\\\\Backslashes" in cef_msg
    # Extension equals and backslash escaped
    assert "src=192.168.1.1\\\\\\=test" in cef_msg


def test_format_json_alert():
    """Alert correctly formats as a single valid JSON object with the expected fields."""
    alert = _make_alert_dict(rule="icmp_flood", severity="medium")
    raw_json = format_json_alert(alert)

    parsed = json.loads(raw_json)
    assert parsed["device_vendor"] == "BantayNet"
    assert parsed["device_product"] == "BantayNet"
    assert parsed["rule"] == "icmp_flood"
    assert parsed["severity"] == "medium"
    assert parsed["src_ip"] == "192.168.1.100"
    assert parsed["dst_ip"] == "10.0.0.1"
    assert parsed["proto"] == "TCP"
    assert parsed["mitre_id"] == "T1498"
    assert parsed["rt"] == 1700000000500


def test_syslog_disabled_by_default():
    """When syslog is disabled, send_syslog_alerts immediately returns 0."""
    cfg = Config()  # Default: integrations.syslog.enabled = False
    alerts = [_make_alert_dict()]

    with patch("socket.socket") as mock_socket:
        count = send_syslog_alerts(alerts, cfg=cfg)
        assert count == 0
        mock_socket.assert_not_called()


def test_syslog_min_severity_filter():
    """Alerts below configured min_severity are ignored."""
    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=514,
                min_severity="high",
            )
        )
    )
    alerts = [
        _make_alert_dict(rule="cleartext", severity="low"),
        _make_alert_dict(rule="host_sweep", severity="medium"),
    ]

    with patch("src.integrations.syslog_out._send_udp_messages") as mock_send:
        count = send_syslog_alerts(alerts, cfg=cfg)
        assert count == 0
        mock_send.assert_not_called()


def test_syslog_udp_transmission_to_local_listener():
    """Start a real local UDP listener on a dynamic port and verify message transmission."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.settimeout(3.0)

    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=port,
                protocol="udp",
                format="cef",
                min_severity="low",
            )
        )
    )

    alert = _make_alert_dict(rule="port_scan", severity="high")
    try:
        count = send_syslog_alerts([alert], cfg=cfg)
        assert count == 1

        data, _ = listener.recvfrom(4096)
        msg = data.decode("utf-8")
        assert msg.startswith("CEF:0|BantayNet|BantayNet|1.0|port_scan|")
        assert "src=192.168.1.100" in msg
    finally:
        listener.close()


def test_syslog_udp_json_format_to_local_listener():
    """Verify JSON formatted message transmission over UDP."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.settimeout(3.0)

    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=port,
                protocol="udp",
                format="json",
                min_severity="low",
            )
        )
    )

    alert = _make_alert_dict(rule="syn_burst", severity="high")
    try:
        count = send_syslog_alerts([alert], cfg=cfg)
        assert count == 1

        data, _ = listener.recvfrom(4096)
        parsed = json.loads(data.decode("utf-8"))
        assert parsed["rule"] == "syn_burst"
        assert parsed["severity"] == "high"
        assert parsed["device_vendor"] == "BantayNet"
    finally:
        listener.close()


def test_syslog_tcp_transmission_to_local_listener():
    """Verify TCP transmission with newline framing to a local TCP listener."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    server.settimeout(3.0)

    received_lines: list[str] = []

    def server_thread():
        try:
            conn, _ = server.accept()
            conn.settimeout(3.0)
            data = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            conn.close()
            for line in data.decode("utf-8").splitlines():
                if line.strip():
                    received_lines.append(line.strip())
        except Exception:
            pass

    t = threading.Thread(target=server_thread, daemon=True)
    t.start()

    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=port,
                protocol="tcp",
                format="cef",
                min_severity="low",
            )
        )
    )

    alerts = [
        _make_alert_dict(rule="port_scan", severity="high"),
        _make_alert_dict(rule="syn_burst", severity="medium"),
    ]

    try:
        count = send_syslog_alerts(alerts, cfg=cfg)
        assert count == 2
        t.join(timeout=3.0)
        assert len(received_lines) == 2
        assert "port_scan" in received_lines[0]
        assert "syn_burst" in received_lines[1]
    finally:
        server.close()


def test_syslog_unreachable_host_never_crashes():
    """An unreachable host or connection error logs a warning and returns 0 without raising."""
    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=1,  # Port 1 TCP is not listening
                protocol="tcp",
                format="cef",
                min_severity="low",
            )
        )
    )
    alerts = [_make_alert_dict()]

    # Transmission must catch connection refused, log warning, and return 0
    count = send_syslog_alerts(alerts, cfg=cfg)
    assert count == 0


def test_dispatch_syslog_integration():
    """Test full dispatch pipeline triggering syslog export."""
    cfg = Config(
        integrations=IntegrationsSettings(
            syslog=SyslogSettings(
                enabled=True,
                host="127.0.0.1",
                port=514,
                protocol="udp",
                format="cef",
            )
        )
    )
    alert = Alert(
        rule="port_scan",
        severity="high",
        src="10.0.0.99",
        dst="10.0.0.1",
        first_ts=1700000000.0,
        last_ts=1700000001.0,
        packet_count=60,
        summary="Port scan detected",
        protocol="TCP",
    )

    with patch("src.integrations.syslog_out._send_udp_messages", return_value=1) as mock_send:
        results = dispatch([alert], client_name="HQ", cfg=cfg)
        assert results["syslog"] == 1
        mock_send.assert_called_once()

