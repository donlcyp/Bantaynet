"""Regression tests for the fixes in the BantayNet problems-and-fixes list."""

from __future__ import annotations

import io
from collections import Counter

import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from src.analyze import analyze
from src.config import load_config
from src.export import write_alerts_csv
from tests.make_synthetic_pcaps import generate

T0 = 1_760_000_000.0


def _syn(src, dst, dport, t):
    p = Ether(src="02:00:00:00:00:66", dst="02:00:00:00:00:10") / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    p.time = t
    return p


def _write(path, pkts):
    wrpcap(str(path), pkts)
    return path


@pytest.fixture(scope="module")
def pcaps(tmp_path_factory):
    out = tmp_path_factory.mktemp("fixpcaps")
    generate(out)
    return out


@pytest.fixture
def cfg():
    return load_config()


# --- Fix 1: protocol comes from the rule, not from summary text --------------
def test_protocol_set_by_rule(pcaps, cfg, tmp_path):
    by_rule = {}
    for name in ("burst", "suspicious"):
        for a in analyze(pcaps / f"{name}.pcap", cfg, evidence_dir=tmp_path).alerts:
            by_rule[a.rule] = a.protocol
    assert by_rule["syn_burst"] == "TCP"
    assert by_rule["cleartext"] == "TCP"
    assert by_rule["icmp_flood"] == "ICMP"


# --- Fix 2: evidence path is project-relative --------------------------------
def test_evidence_path_is_relative(pcaps, cfg):
    res = analyze(pcaps / "portscan.pcap", cfg)  # default evidence dir inside the project
    path = res.alerts[0].evidence_path
    assert not path.startswith("/") and ":" not in path[:3]
    assert path.startswith("evidence/")


# --- Fix 5 + 6: slow and moderate scans --------------------------------------
def test_slow_scan_detected(tmp_path, cfg):
    pcap = _write(tmp_path / "slow.pcap", [_syn("10.0.0.66", "10.0.0.10", 1000 + i, T0 + i * 2) for i in range(100)])
    res = analyze(pcap, cfg, evidence_dir=tmp_path)
    assert Counter(a.rule for a in res.alerts) == {"slow_scan": 1}


def test_moderate_fast_scan_detected(tmp_path, cfg):
    pcap = _write(tmp_path / "mid.pcap", [_syn("10.0.0.66", "10.0.0.10", 1000 + i, T0 + i * 0.1) for i in range(30)])
    res = analyze(pcap, cfg, evidence_dir=tmp_path)
    assert Counter(a.rule for a in res.alerts) == {"slow_scan": 1}


def test_fast_scan_is_not_double_reported(pcaps, cfg, tmp_path):
    res = analyze(pcaps / "portscan.pcap", cfg, evidence_dir=tmp_path)
    assert Counter(a.rule for a in res.alerts) == {"port_scan": 1}


def test_few_ports_no_alert(tmp_path, cfg):
    pcap = _write(tmp_path / "few.pcap", [_syn("10.0.0.5", "10.0.0.10", 80 + i, T0 + i) for i in range(5)])
    assert analyze(pcap, cfg, evidence_dir=tmp_path).alerts == []


# --- Fix 8: ICMPv6 echo flood ------------------------------------------------
def test_icmpv6_flood_detected(tmp_path, cfg):
    pkts = []
    for i in range(150):
        p = Ether(src="02:00:00:00:00:66", dst="02:00:00:00:00:10") / IPv6(src="fd00::66", dst="fd00::10") / ICMPv6EchoRequest(seq=i)
        p.time = T0 + i * 0.005
        pkts.append(p)
    res = analyze(_write(tmp_path / "v6.pcap", pkts), cfg, evidence_dir=tmp_path)
    assert Counter(a.rule for a in res.alerts) == {"icmp_flood": 1}


# --- Fix 9: one CSV writer ---------------------------------------------------
def test_write_alerts_csv_handles_missing_values():
    buf = io.StringIO()
    n = write_alerts_csv(buf, [{"id": 1, "rule": "port_scan", "dst_port": None}])
    text = buf.getvalue()
    assert n == 1 and text.startswith("ID,Detected At") and "port_scan" in text
