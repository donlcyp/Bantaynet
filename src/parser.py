"""Stream packets from a PCAP/PCAPNG file as lightweight records.

Packets are read one at a time with Scapy's ``PcapReader`` instead of loading
the whole file with ``rdpcap``, so memory use stays flat for large captures.
Each packet is reduced to a small ``PacketRecord`` holding only the fields the
detectors need. Non-IP frames (ARP, STP, ...) are skipped and counted.

This module only reads files. It never sends packets or sniffs an interface.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


class PcapError(Exception):
    """Raised when a capture file is missing or unreadable."""


@dataclass(frozen=True, slots=True)
class PacketRecord:
    index: int               # 0-based position in the capture (used for evidence extraction)
    ts: float                # capture timestamp, epoch seconds
    src: str
    dst: str
    proto: str               # "TCP", "UDP", "ICMP", or "OTHER"
    length: int              # bytes on the wire
    sport: int | None = None
    dport: int | None = None
    tcp_flags: int | None = None   # raw flag bits; see FIN/SYN/... constants
    icmp_type: int | None = None

    def has_flags(self, *, set_: int = 0, clear: int = 0) -> bool:
        """True if TCP and all ``set_`` bits are on and all ``clear`` bits are off."""
        if self.tcp_flags is None:
            return False
        return (self.tcp_flags & set_) == set_ and (self.tcp_flags & clear) == 0

    @property
    def flag_str(self) -> str:
        if self.tcp_flags is None:
            return ""
        names = ((FIN, "F"), (SYN, "S"), (RST, "R"), (PSH, "P"), (ACK, "A"), (URG, "U"))
        return "".join(ch for bit, ch in names if self.tcp_flags & bit) or "NULL"


@dataclass
class ParseStats:
    total: int = 0
    parsed: int = 0
    skipped_non_ip: int = 0
    protocols: Counter = field(default_factory=Counter)
    first_ts: float | None = None
    last_ts: float | None = None

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts


def _to_record(index: int, pkt) -> PacketRecord | None:
    if IP in pkt:
        l3 = pkt[IP]
    elif IPv6 in pkt:
        l3 = pkt[IPv6]
    else:
        return None

    common = dict(index=index, ts=float(pkt.time), src=l3.src, dst=l3.dst, length=len(pkt))
    if TCP in pkt:
        t = pkt[TCP]
        return PacketRecord(proto="TCP", sport=t.sport, dport=t.dport, tcp_flags=int(t.flags), **common)
    if UDP in pkt:
        u = pkt[UDP]
        return PacketRecord(proto="UDP", sport=u.sport, dport=u.dport, **common)
    if ICMP in pkt:
        return PacketRecord(proto="ICMP", icmp_type=int(pkt[ICMP].type), **common)
    return PacketRecord(proto="OTHER", **common)


def iter_packets(path: str | Path, stats: ParseStats | None = None) -> Iterator[PacketRecord]:
    """Yield a ``PacketRecord`` for each IP packet in ``path``.

    Pass a ``ParseStats`` to have it filled in as the file is read.
    """
    path = Path(path)
    if not path.is_file():
        raise PcapError(f"capture file not found: {path}")
    stats = stats if stats is not None else ParseStats()

    try:
        reader = PcapReader(str(path))  # auto-detects pcap vs pcapng
    except (Scapy_Exception, OSError, EOFError) as exc:
        raise PcapError(f"not a readable pcap/pcapng file: {path} ({exc})") from exc

    with reader:
        for index, pkt in enumerate(reader):
            stats.total += 1
            rec = _to_record(index, pkt)
            if rec is None:
                stats.skipped_non_ip += 1
                continue
            stats.parsed += 1
            stats.protocols[rec.proto] += 1
            if stats.first_ts is None:
                stats.first_ts = rec.ts
            stats.last_ts = rec.ts
            yield rec


def main(argv: list[str] | None = None) -> int:
    """Quick inspection: ``python -m src.parser <file.pcap>``."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m src.parser <file.pcap>", file=sys.stderr)
        return 2
    stats = ParseStats()
    try:
        for _ in iter_packets(argv[0], stats):
            pass
    except PcapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    protos = ", ".join(f"{k}={v}" for k, v in sorted(stats.protocols.items()))
    print(
        f"{Path(argv[0]).name}: {stats.total} packets, {stats.parsed} IP, "
        f"{stats.skipped_non_ip} skipped, {stats.duration:.1f}s  [{protos}]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
