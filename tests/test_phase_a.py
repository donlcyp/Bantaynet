"""Unit and integration tests for Phase A features:
1. Alert status and analyst notes
2. Allowlist (trusted IPs & CIDR ranges)
3. Client / site labels
"""

from __future__ import annotations

import io
from dataclasses import replace
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from dashboard.app import app
from src import db
from src.analyze import analyze
from src.config import Config, load_config
from src.detector import Detector
from src.export import write_alerts_csv
from src.main import main
from src.parser import SYN, PacketRecord

T0 = 1_760_000_000.0


def _syn_pkt(src, dst, dport, t):
    p = Ether(src="02:00:00:00:00:66", dst="02:00:00:00:00:10") / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    p.time = t
    return p


# --- Feature 1: Alert status and notes ---------------------------------------

def test_alert_status_and_notes_persistence(tmp_path, monkeypatch):
    test_db = tmp_path / "test_status.db"
    monkeypatch.setattr(db, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setattr(db, "DEFAULT_SQLITE_PATH", test_db)

    db.init_db(test_db)
    aid = db.insert_alert(
        rule="port_scan",
        severity="high",
        src_ip="10.0.0.66",
        dst_ip="10.0.0.10",
        packet_time=T0,
        description="Test port scan",
        db_path=test_db,
    )

    alert = db.get_alert_by_id(aid, db_path=test_db)
    assert alert["status"] == "new"
    assert alert["analyst_note"] == ""

    # Update status to resolved with note
    ok = db.update_alert_status_and_note(aid, "resolved", "False alarm - scheduled Nessus scan", db_path=test_db)
    assert ok is True

    updated = db.get_alert_by_id(aid, db_path=test_db)
    assert updated["status"] == "resolved"
    assert "Nessus scan" in updated["analyst_note"]
    assert updated["updated_at"] is not None

    # Filter by status
    resolved_alerts = db.get_alerts(status="resolved", db_path=test_db)
    assert len(resolved_alerts) == 1
    new_alerts = db.get_alerts(status="new", db_path=test_db)
    assert len(new_alerts) == 0


def test_status_update_route(tmp_path, monkeypatch):
    test_db = tmp_path / "test_route.db"
    monkeypatch.setattr(db, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setattr(db, "DEFAULT_SQLITE_PATH", test_db)
    monkeypatch.setattr("dashboard.app.PROJECT_ROOT", tmp_path)

    db.init_db(test_db)
    aid = db.insert_alert(
        rule="syn_burst",
        severity="high",
        src_ip="10.0.0.99",
        dst_ip="10.0.0.10",
        packet_time=T0,
        description="SYN burst test",
        db_path=test_db,
    )

    app.config["TESTING"] = True
    with app.test_client() as client:
        res = client.post(
            f"/alert/{aid}/status",
            data={"status": "investigating", "analyst_note": "Assigned to Security Analyst 1"},
            follow_redirects=True,
        )
        assert res.status_code == 200
        assert b"Investigating" in res.data

    updated = db.get_alert_by_id(aid, db_path=test_db)
    assert updated["status"] == "investigating"
    assert updated["analyst_note"] == "Assigned to Security Analyst 1"


# --- Feature 2: Allowlist (trusted IPs & CIDR ranges) ------------------------

def test_allowlist_suppresses_alerts(tmp_path):
    base_cfg = load_config()
    # Configure allowlist with both single IP and CIDR range
    cfg = replace(
        base_cfg,
        allowlist=replace(base_cfg.allowlist, enabled=True, ips=["10.0.0.5", "192.168.100.0/24"]),
        port_scan=replace(base_cfg.port_scan, distinct_ports=10, window_seconds=5.0),
    )

    # 1. Traffic from allowlisted IP 10.0.0.5 should be skipped
    det_allow = Detector(cfg)
    for i in range(20):
        rec = PacketRecord(index=i, ts=T0 + i * 0.1, src="10.0.0.5", dst="10.0.0.10",
                           proto="TCP", length=60, sport=40000 + i, dport=1000 + i, tcp_flags=SYN)
        det_allow.process(rec)
    alerts_allow = det_allow.finish()
    assert alerts_allow == []
    assert det_allow.skipped_allowlist == 20

    # 2. Traffic from allowlisted CIDR 192.168.100.55 should be skipped
    det_cidr = Detector(cfg)
    for i in range(20):
        rec = PacketRecord(index=i, ts=T0 + i * 0.1, src="192.168.100.55", dst="10.0.0.10",
                           proto="TCP", length=60, sport=40000 + i, dport=1000 + i, tcp_flags=SYN)
        det_cidr.process(rec)
    assert det_cidr.finish() == []
    assert det_cidr.skipped_allowlist == 20

    # 3. Traffic from non-allowlisted attacker 10.0.0.66 should still alert
    det_attack = Detector(cfg)
    for i in range(20):
        rec = PacketRecord(index=i, ts=T0 + i * 0.1, src="10.0.0.66", dst="10.0.0.10",
                           proto="TCP", length=60, sport=40000 + i, dport=1000 + i, tcp_flags=SYN)
        det_attack.process(rec)
    alerts_attack = det_attack.finish()
    assert len(alerts_attack) == 1
    assert alerts_attack[0].rule == "port_scan"
    assert det_attack.skipped_allowlist == 0


def test_allowlist_end_to_end_pcap(tmp_path):
    pcap_allow = tmp_path / "allow.pcap"
    pkts = [_syn_pkt("10.0.0.5", "10.0.0.10", 1000 + i, T0 + i * 0.05) for i in range(60)]
    wrpcap(str(pcap_allow), pkts)

    cfg = replace(load_config(), allowlist=replace(Config().allowlist, enabled=True, ips=["10.0.0.5"]))
    res = analyze(pcap_allow, cfg=cfg, evidence_dir=tmp_path)
    assert len(res.alerts) == 0
    assert res.stats.skipped_allowlist == 60


# --- Feature 4: Client / Site label -----------------------------------------

def test_client_label_cli_and_filtering(tmp_path, monkeypatch, capsys):
    test_db = tmp_path / "test_client.db"
    monkeypatch.setattr(db, "ACTIVE_ENGINE", "sqlite")
    monkeypatch.setattr(db, "DB_PATH", test_db)
    monkeypatch.setattr(db, "DEFAULT_SQLITE_PATH", test_db)

    pcap_path = tmp_path / "scan_client.pcap"
    pkts = [_syn_pkt("10.0.0.66", "10.0.0.10", 1000 + i, T0 + i * 0.05) for i in range(60)]
    wrpcap(str(pcap_path), pkts)

    import sys
    monkeypatch.setattr(
        sys,
        "argv",
        ["bantaynet", "--pcap", str(pcap_path), "--client", "Client A - Branch 2"],
    )
    assert main() == 0

    alerts_client_a = db.get_alerts(client_name="Client A - Branch 2", db_path=test_db)
    assert len(alerts_client_a) == 1
    assert alerts_client_a[0]["client_name"] == "Client A - Branch 2"

    alerts_other = db.get_alerts(client_name="Client B", db_path=test_db)
    assert len(alerts_other) == 0


def test_client_label_in_csv_export():
    buf = io.StringIO()
    row = {
        "id": 1,
        "rule": "port_scan",
        "severity": "high",
        "src_ip": "10.0.0.66",
        "dst_ip": "10.0.0.10",
        "client_name": "Client X - Site 1",
        "status": "investigating",
        "analyst_note": "Ticket #404",
    }
    write_alerts_csv(buf, [row])
    csv_text = buf.getvalue()
    assert "Client / Site" in csv_text
    assert "Status" in csv_text
    assert "Analyst Note" in csv_text
    assert "Client X - Site 1" in csv_text
    assert "investigating" in csv_text
    assert "Ticket #404" in csv_text
