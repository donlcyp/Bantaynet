"""Unit tests for the SQLite storage layer and CLI export."""

from __future__ import annotations

import pytest

from src.db import clear_alerts, get_alert_by_id, get_alerts, get_summary_stats, init_db, insert_alert


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_bantaynet.db"
    init_db(db_file)
    return db_file


def test_insert_and_get_alerts(test_db):
    alert_id = insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="10.0.0.66",
        dst_ip="10.0.0.10",
        packet_time=1760000000.0,
        description="10.0.0.66 probed 200 ports",
        packet_count=200,
        db_path=test_db,
    )
    assert alert_id > 0

    alerts = get_alerts(db_path=test_db)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "port_scan"
    assert alerts[0]["severity"] == "high"

    fetched = get_alert_by_id(alert_id, db_path=test_db)
    assert fetched is not None
    assert fetched["src_ip"] == "10.0.0.66"


def test_filtering_and_stats(test_db):
    insert_alert("port_scan", "high", "10.0.0.66", "10.0.0.10", 1760000000.0, "Scan 1", db_path=test_db)
    insert_alert("syn_burst", "high", "10.0.0.66", "10.0.0.10", 1760000010.0, "Burst 1", db_path=test_db)
    insert_alert("cleartext", "low", "10.0.0.21", "10.0.0.10", 1760000020.0, "Telnet", db_path=test_db)

    stats = get_summary_stats(db_path=test_db)
    assert stats["total"] == 3
    assert stats["high"] == 2
    assert stats["low"] == 1

    high_only = get_alerts(severity="high", db_path=test_db)
    assert len(high_only) == 2

    cleartext_only = get_alerts(rule="cleartext", db_path=test_db)
    assert len(cleartext_only) == 1

    search_res = get_alerts(search="Telnet", db_path=test_db)
    assert len(search_res) == 1


def test_clear_alerts(test_db):
    insert_alert("port_scan", "high", "10.0.0.66", "10.0.0.10", 1760000000.0, "Scan", db_path=test_db)
    assert len(get_alerts(db_path=test_db)) == 1

    clear_alerts(db_path=test_db)
    assert len(get_alerts(db_path=test_db)) == 0
