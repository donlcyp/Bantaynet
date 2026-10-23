"""Tests for the detection engine and evidence extraction."""

from __future__ import annotations

from collections import Counter
from dataclasses import replace

import pytest
from scapy.layers.inet import IP
from scapy.utils import rdpcap

from src.analyze import analyze
from src.config import Config, load_config
from src.detector import Detector
from src.parser import ACK, FIN, RST, SYN, PacketRecord
from tests.make_synthetic_pcaps import ATTACKER, CLIENT_A, CLIENT_B, SERVER_WEB, generate


@pytest.fixture(scope="module")
def pcaps(tmp_path_factory):
    out = tmp_path_factory.mktemp("pcaps")
    generate(out)
    return out


@pytest.fixture(scope="module")
def results(pcaps, tmp_path_factory):
    ev = tmp_path_factory.mktemp("evidence")
    cfg = load_config()
    return {name: analyze(pcaps / f"{name}.pcap", cfg, evidence_dir=ev)
            for name in ("normal", "portscan", "burst", "suspicious")}


def rules_of(result):
    return Counter(a.rule for a in result.alerts)


# --- end-to-end on synthetic captures ----------------------------------------

def test_normal_traffic_raises_no_alerts(results):
    assert results["normal"].alerts == []


def test_portscan_detected_once(results):
    assert rules_of(results["portscan"]) == {"port_scan": 1}
    a = results["portscan"].alerts[0]
    assert (a.src, a.dst, a.severity) == (ATTACKER, SERVER_WEB, "high")
    assert a.details["distinct_ports"] == 200
    assert a.packet_count == 200
    assert a.duration < 3


def test_burst_detected_once(results):
    assert rules_of(results["burst"]) == {"syn_burst": 1}
    a = results["burst"].alerts[0]
    assert (a.src, a.dst) == (ATTACKER, SERVER_WEB)
    assert a.details["dport"] == 80
    assert a.packet_count == 600


def test_suspicious_capture(results):
    alerts = results["suspicious"].alerts
    assert rules_of(results["suspicious"]) == {"suspicious_flags": 3, "cleartext": 2, "icmp_flood": 1}

    flags = {a.details["pattern"]: a for a in alerts if a.rule == "suspicious_flags"}
    assert set(flags) == {"NULL", "XMAS", "FIN"}
    assert all(a.packet_count == 6 and a.src == ATTACKER for a in flags.values())

    clear = {a.details["protocol"]: a for a in alerts if a.rule == "cleartext"}
    assert (clear["Telnet"].src, clear["Telnet"].dst) == (CLIENT_A, SERVER_WEB)
    assert (clear["FTP"].src, clear["FTP"].dst) == (CLIENT_B, SERVER_WEB)

    icmp = next(a for a in alerts if a.rule == "icmp_flood")
    assert icmp.packet_count == 300


def test_alerts_sorted_by_time(results):
    ts = [a.first_ts for a in results["suspicious"].alerts]
    assert ts == sorted(ts)


def test_evidence_files_match_alerts(results):
    for result in results.values():
        for a in result.alerts:
            assert a.evidence_path, a.summary
            pkts = rdpcap(a.evidence_path)
            assert len(pkts) == len(a.evidence_indexes) == min(a.packet_count, 500)
            # Every packet in the snippet involves the alert's two hosts.
            assert all({p[IP].src, p[IP].dst} == {a.src, a.dst} for p in pkts)


def test_evidence_preserves_original_timestamps(results):
    a = results["burst"].alerts[0]
    pkts = rdpcap(a.evidence_path)
    assert float(pkts[0].time) == pytest.approx(a.first_ts)


def test_evidence_disabled(pcaps, tmp_path):
    cfg = replace(load_config(), evidence=replace(Config().evidence, enabled=False))
    result = analyze(pcaps / "burst.pcap", cfg, evidence_dir=tmp_path)
    assert result.alerts and result.alerts[0].evidence_path is None
    assert list(tmp_path.iterdir()) == []


# --- unit tests on hand-built records ---------------------------------------

def syn(i, ts, src="10.9.9.9", dst="10.0.0.10", dport=80, flags=SYN):
    return PacketRecord(index=i, ts=ts, src=src, dst=dst, proto="TCP", length=60,
                        sport=40000, dport=dport, tcp_flags=flags)


def run(cfg, records):
    det = Detector(cfg)
    alerts = [a for r in records for a in det.process(r)]
    return alerts + det.finish()


def small_burst_cfg(**alerts_kw):
    base = Config()
    return replace(base, syn_burst=replace(base.syn_burst, syn_count=10, window_seconds=1.0),
                   alerts=replace(base.alerts, **alerts_kw))


def test_below_threshold_no_alert():
    assert run(small_burst_cfg(), [syn(i, i * 0.05) for i in range(9)]) == []


def test_threshold_window_is_sliding():
    # 10 SYNs spread over 2s never has 10 inside any 1s window.
    assert run(small_burst_cfg(), [syn(i, i * 0.2) for i in range(10)]) == []


def test_bursts_within_cooldown_merge():
    recs = [syn(i, i * 0.01) for i in range(10)] + [syn(100 + i, 5 + i * 0.01) for i in range(10)]
    alerts = run(small_burst_cfg(cooldown_seconds=30), recs)
    assert len(alerts) == 1 and alerts[0].packet_count == 20


def test_bursts_beyond_cooldown_split():
    recs = [syn(i, i * 0.01) for i in range(10)] + [syn(100 + i, 50 + i * 0.01) for i in range(10)]
    alerts = run(small_burst_cfg(cooldown_seconds=30), recs)
    assert [a.packet_count for a in alerts] == [10, 10]


def test_alert_includes_packets_before_threshold():
    alerts = run(small_burst_cfg(), [syn(i, i * 0.01) for i in range(10)])
    assert alerts[0].evidence_indexes == list(range(10))
    assert alerts[0].first_ts == 0.0


def test_evidence_cap_respected():
    base = small_burst_cfg()
    cfg = replace(base, evidence=replace(base.evidence, max_packets=5))
    alerts = run(cfg, [syn(i, i * 0.001) for i in range(50)])
    assert alerts[0].packet_count == 50 and len(alerts[0].evidence_indexes) == 5


def test_disabled_rule_is_silent():
    base = small_burst_cfg()
    cfg = replace(base, syn_burst=replace(base.syn_burst, enabled=False))
    assert run(cfg, [syn(i, i * 0.01) for i in range(50)]) == []


def test_syn_ack_and_rst_are_not_burst_or_scan():
    base = Config()
    cfg = replace(base,
                  syn_burst=replace(base.syn_burst, syn_count=5),
                  port_scan=replace(base.port_scan, distinct_ports=5))
    recs = [syn(i, i * 0.01, dport=1000 + i, flags=SYN | ACK) for i in range(20)]
    recs += [syn(100 + i, 1 + i * 0.01, dport=2000 + i, flags=RST) for i in range(20)]
    assert run(cfg, recs) == []


def test_normal_fin_ack_close_not_flagged():
    recs = [syn(i, i * 0.1, flags=FIN | ACK) for i in range(20)]
    assert run(Config(), recs) == []


def test_closed_cleartext_port_not_flagged():
    # Client tries Telnet, server refuses with RST/ACK: no cleartext session happened.
    recs = [
        syn(0, 0.0, src=CLIENT_A, dst=SERVER_WEB, dport=23),
        PacketRecord(index=1, ts=0.001, src=SERVER_WEB, dst=CLIENT_A, proto="TCP", length=60,
                     sport=23, dport=40000, tcp_flags=RST | ACK),
    ]
    assert run(Config(), recs) == []


def test_host_sweep_detected():
    base = Config()
    cfg = replace(base, host_sweep=replace(base.host_sweep, distinct_hosts=10, window_seconds=5.0))
    recs = [
        PacketRecord(index=i, ts=i * 0.1, src="10.0.0.66", dst=f"10.0.1.{i+1}", proto="TCP", length=60,
                     sport=50000, dport=445, tcp_flags=SYN)
        for i in range(12)
    ]
    alerts = run(cfg, recs)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule == "host_sweep"
    assert a.src == "10.0.0.66"
    assert a.details["distinct_hosts"] == 12
    assert a.details["dport"] == 445
    assert a.dst_port == "445"

