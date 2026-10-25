"""Unit and integration tests for Phase B features:
- Feature 5: MITRE ATT&CK mapping and tags
- Feature 3: Visual Analytics Charts (Chart.js dataset aggregation and rendering)
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from src.db import (
    clear_alerts,
    get_alert_by_id,
    get_alerts,
    get_chart_data,
    init_db,
    insert_alert,
)
from src.export import write_alerts_csv
from src.mitre import DEFAULT_MITRE, attach_mitre_info, get_mitre_info


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "test_phase_b.db"
    init_db(db_file)
    yield db_file


def test_mitre_mappings():
    """Verify all 7 rules map to the expected MITRE ATT&CK techniques."""
    assert get_mitre_info("port_scan")["id"] == "T1046"
    assert get_mitre_info("slow_scan")["id"] == "T1046"
    assert get_mitre_info("suspicious_flags")["id"] == "T1046"
    assert get_mitre_info("host_sweep")["id"] == "T1018"
    assert get_mitre_info("syn_burst")["id"] == "T1498"
    assert get_mitre_info("icmp_flood")["id"] == "T1498"
    assert get_mitre_info("cleartext")["id"] == "POLICY"
    assert get_mitre_info("unknown_rule") == DEFAULT_MITRE


def test_attach_mitre_info():
    """Verify attach_mitre_info enriches an alert dict."""
    alert = {"rule": "port_scan", "src_ip": "192.168.1.50"}
    enriched = attach_mitre_info(alert)
    assert enriched["mitre_id"] == "T1046"
    assert enriched["mitre_name"] == "Network Service Discovery"
    assert "https://attack.mitre.org" in enriched["mitre_url"]
    assert "T1046: Network Service Discovery" in enriched["mitre_tag"]


def test_db_alerts_include_mitre(test_db: Path):
    """Verify get_alerts and get_alert_by_id return MITRE fields."""
    aid = insert_alert(
        rule="host_sweep",
        severity="medium",
        src_ip="10.0.0.99",
        dst_ip="10.0.0.1",
        packet_time="2026-10-23T12:00:00",
        description="Host sweep detected across subnet",
        db_path=test_db,
    )
    alert = get_alert_by_id(aid, db_path=test_db)
    assert alert is not None
    assert alert["mitre_id"] == "T1018"
    assert alert["mitre_name"] == "Remote System Discovery"

    alerts = get_alerts(db_path=test_db)
    assert len(alerts) == 1
    assert alerts[0]["mitre_id"] == "T1018"


def test_chart_data_aggregation(test_db: Path):
    """Verify get_chart_data aggregates timeline, top sources, rules, severity, and status."""
    insert_alert(rule="port_scan", severity="high", src_ip="10.0.0.1", dst_ip="10.0.0.50", packet_time="2026-10-23T10:15:00", description="Port scan", detected_at="2026-10-23T10:15:00", db_path=test_db)
    insert_alert(rule="port_scan", severity="high", src_ip="10.0.0.1", dst_ip="10.0.0.50", packet_time="2026-10-23T10:45:00", description="Port scan 2", detected_at="2026-10-23T10:45:00", db_path=test_db)
    insert_alert(rule="syn_burst", severity="medium", src_ip="10.0.0.2", dst_ip="10.0.0.50", packet_time="2026-10-23T11:00:00", description="SYN flood", detected_at="2026-10-23T11:00:00", db_path=test_db)
    insert_alert(rule="host_sweep", severity="low", src_ip="10.0.0.3", dst_ip="10.0.0.255", packet_time="2026-10-23T12:00:00", description="Host sweep", detected_at="2026-10-23T12:00:00", db_path=test_db)

    charts = get_chart_data(db_path=test_db)
    assert charts["total"] == 4

    # Top sources
    assert "10.0.0.1" in charts["top_sources"]["labels"]
    top_ip_idx = charts["top_sources"]["labels"].index("10.0.0.1")
    assert charts["top_sources"]["counts"][top_ip_idx] == 2

    # By rule
    assert "port_scan" in charts["by_rule"]["labels"]
    port_idx = charts["by_rule"]["labels"].index("port_scan")
    assert charts["by_rule"]["counts"][port_idx] == 2

    # By severity
    assert charts["by_severity"]["counts"] == [2, 1, 1]  # High=2, Medium=1, Low=1

    # Timeline buckets
    assert len(charts["timeline"]["labels"]) >= 3


def test_export_csv_includes_mitre(test_db: Path):
    """Verify CSV export includes MITRE ATT&CK column."""
    insert_alert(rule="syn_burst", severity="high", src_ip="172.16.0.4", dst_ip="10.0.0.1", packet_time="2026-10-23T12:00:00", description="SYN burst test", db_path=test_db)
    alerts = get_alerts(db_path=test_db)

    buf = io.StringIO()
    write_alerts_csv(buf, alerts)
    content = buf.getvalue()

    assert "MITRE ATT&CK" in content
    assert "T1498: Network Denial of Service" in content


def test_dashboard_renders_charts_and_mitre(test_db: Path, monkeypatch):
    """Verify Flask dashboard index and alert detail pages render charts and MITRE tags."""
    from dashboard.app import app
    import src.db as db_mod

    # Redirect app to use test_db
    monkeypatch.setattr(db_mod, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db_mod, "DEFAULT_SQLITE_PATH", test_db)
    monkeypatch.setattr(db_mod, "DB_PATH", test_db)

    aid = insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        packet_time="2026-10-23T12:00:00",
        description="Port scan test",
        db_path=test_db,
    )

    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Check chart elements and local script
    assert "timelineChart" in html
    assert "topSourcesChart" in html
    assert "byRuleChart" in html
    assert "severityChart" in html
    assert "chart.umd.min.js" in html

    # Check MITRE tag in table
    assert "T1046" in html
    assert "Rule &amp; ATT&amp;CK" in html or "Rule & ATT&CK" in html

    # Check alert detail page
    resp_detail = client.get(f"/alert/{aid}")
    assert resp_detail.status_code == 200
    detail_html = resp_detail.get_data(as_text=True)
    assert "MITRE ATT&CK Mapping" in detail_html
    assert "T1046" in detail_html
    assert "https://attack.mitre.org/techniques/T1046/" in detail_html
