"""Tests for src.parser using freshly generated synthetic PCAPs."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from src.parser import ACK, FIN, PSH, SYN, URG, PacketRecord, ParseStats, PcapError, iter_packets
from tests.make_synthetic_pcaps import ATTACKER, generate


@pytest.fixture(scope="module")
def pcaps(tmp_path_factory):
    out = tmp_path_factory.mktemp("pcaps")
    counts = generate(out)
    return out, counts


def test_reads_every_packet(pcaps):
    out, counts = pcaps
    for name, expected in counts.items():
        stats = ParseStats()
        records = list(iter_packets(out / name, stats))
        assert stats.total == expected
        assert stats.parsed == len(records) == expected  # synthetic files are all IP
        assert stats.skipped_non_ip == 0


def test_records_are_in_order_with_indexes(pcaps):
    out, _ = pcaps
    records = list(iter_packets(out / "normal.pcap"))
    assert [r.index for r in records] == list(range(len(records)))
    assert all(a.ts <= b.ts for a, b in zip(records, records[1:]))


def test_portscan_fields(pcaps):
    out, _ = pcaps
    probes = [r for r in iter_packets(out / "portscan.pcap") if r.src == ATTACKER]
    assert len(probes) == 200
    assert all(r.proto == "TCP" and r.flag_str == "S" for r in probes)
    assert len({r.dport for r in probes}) == 200


def test_suspicious_flag_patterns(pcaps):
    out, _ = pcaps
    atk = [r for r in iter_packets(out / "suspicious.pcap") if r.src == ATTACKER]
    tcp = [r for r in atk if r.proto == "TCP"]
    assert sum(r.tcp_flags == 0 for r in tcp) == 6                       # NULL
    assert sum(r.has_flags(set_=FIN | PSH | URG) for r in tcp) == 6      # XMAS
    assert sum(r.has_flags(set_=FIN, clear=ACK | PSH | URG) for r in tcp) == 6  # FIN-only
    icmp = [r for r in atk if r.proto == "ICMP"]
    assert len(icmp) == 300 and all(r.icmp_type == 8 for r in icmp)


def test_flag_helpers():
    rec = PacketRecord(index=0, ts=0.0, src="a", dst="b", proto="TCP", length=60, tcp_flags=SYN | ACK)
    assert rec.flag_str == "SA"
    assert rec.has_flags(set_=SYN, clear=FIN)
    assert not rec.has_flags(set_=SYN, clear=ACK)
    null = PacketRecord(index=0, ts=0.0, src="a", dst="b", proto="TCP", length=60, tcp_flags=0)
    assert null.flag_str == "NULL"
    udp = PacketRecord(index=0, ts=0.0, src="a", dst="b", proto="UDP", length=60)
    assert not udp.has_flags(set_=0)


def test_skips_non_ip(tmp_path):
    path = tmp_path / "mixed.pcap"
    wrpcap(str(path), [Ether() / ARP(), Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S")])
    stats = ParseStats()
    records = list(iter_packets(path, stats))
    assert stats.total == 2 and stats.skipped_non_ip == 1
    assert len(records) == 1 and records[0].index == 1  # index tracks file position, not record count


def test_missing_file(tmp_path):
    with pytest.raises(PcapError, match="not found"):
        list(iter_packets(tmp_path / "nope.pcap"))


def test_not_a_pcap(tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"this is not a capture file at all")
    with pytest.raises(PcapError, match="not a readable"):
        list(iter_packets(bad))
