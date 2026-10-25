"""Generate synthetic PCAP files for BantayNet testing.

SAFETY: This script only builds packets in memory and writes them to disk
with ``wrpcap``. It never sends packets, opens sockets, or touches a network
interface. All addresses are private (RFC 1918) lab addresses.

Usage:
    python tests/make_synthetic_pcaps.py [--out pcaps]

Outputs:
    normal.pcap      - benign background traffic (TCP handshakes, DNS, a few pings)
    portscan.pcap    - one host SYN-probing many ports on a target in a short window
    burst.pcap       - high-rate SYN burst to a single service (SYN-flood pattern)
    suspicious.pcap  - NULL/XMAS/FIN-only probes, cleartext Telnet/FTP, ICMP flood
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

# Fixed seed + fixed base time => byte-identical output on every run,
# so tests and detection results are reproducible.
SEED = 1337
BASE_TIME = 1_760_000_000.0  # fixed epoch timestamp

# Lab hosts (private addresses only)
CLIENT_A = "10.0.0.21"
CLIENT_B = "10.0.0.22"
SERVER_WEB = "10.0.0.10"
SERVER_DNS = "10.0.0.53"
ATTACKER = "10.0.0.66"

MAC_A = "02:00:00:00:00:21"
MAC_B = "02:00:00:00:00:22"
MAC_WEB = "02:00:00:00:00:10"
MAC_DNS = "02:00:00:00:00:53"
MAC_ATK = "02:00:00:00:00:66"

MACS = {
    CLIENT_A: MAC_A,
    CLIENT_B: MAC_B,
    SERVER_WEB: MAC_WEB,
    SERVER_DNS: MAC_DNS,
    ATTACKER: MAC_ATK,
}


def _mac(ip: str) -> str:
    return MACS.get(ip, "02:00:00:00:00:ff")


def stamp(pkt: Packet, t: float) -> Packet:
    """Assign a capture timestamp to a packet."""
    pkt.time = BASE_TIME + t
    return pkt


def eth_ip(src: str, dst: str) -> Packet:
    return Ether(src=_mac(src), dst=_mac(dst)) / IP(src=src, dst=dst)


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------

def tcp_session(
    t: float,
    client: str,
    server: str,
    dport: int,
    payload_req: bytes,
    payload_resp: bytes,
    rng: random.Random,
) -> tuple[list[Packet], float]:
    """A complete, well-formed TCP session: handshake, request/response, FIN close."""
    sport = rng.randint(49152, 65535)
    cseq = rng.randint(1_000, 1_000_000)
    sseq = rng.randint(1_000, 1_000_000)
    c2s = lambda: eth_ip(client, server)  # noqa: E731
    s2c = lambda: eth_ip(server, client)  # noqa: E731
    pkts: list[Packet] = []

    def add(p: Packet, dt: float) -> None:
        nonlocal t
        t += dt
        pkts.append(stamp(p, t))

    add(c2s() / TCP(sport=sport, dport=dport, flags="S", seq=cseq), 0.0)
    add(s2c() / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1), 0.002)
    add(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1), 0.001)
    cseq += 1
    sseq += 1

    add(c2s() / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(payload_req), 0.005)
    cseq += len(payload_req)
    add(s2c() / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq), 0.002)
    add(s2c() / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(payload_resp), 0.010)
    sseq += len(payload_resp)
    add(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq), 0.001)

    add(c2s() / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq), 0.050)
    add(s2c() / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1), 0.002)
    add(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1), 0.001)
    return pkts, t


def dns_exchange(t: float, client: str, name: str, answer: str, rng: random.Random) -> tuple[list[Packet], float]:
    sport = rng.randint(49152, 65535)
    qid = rng.randint(0, 0xFFFF)
    q = eth_ip(client, SERVER_DNS) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name))
    r = (
        eth_ip(SERVER_DNS, client)
        / UDP(sport=53, dport=sport)
        / DNS(id=qid, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=answer))
    )
    return [stamp(q, t), stamp(r, t + 0.015)], t + 0.015


def ping(t: float, src: str, dst: str, seq: int) -> tuple[list[Packet], float]:
    req = eth_ip(src, dst) / ICMP(type=8, id=0x4242, seq=seq) / Raw(b"bantaynet-ping")
    rep = eth_ip(dst, src) / ICMP(type=0, id=0x4242, seq=seq) / Raw(b"bantaynet-ping")
    return [stamp(req, t), stamp(rep, t + 0.001)], t + 0.001


def background(rng: random.Random, start: float, duration: float) -> list[Packet]:
    """Low-rate benign traffic spread across [start, start+duration)."""
    pkts: list[Packet] = []
    t = start
    end = start + duration
    sites = [("intranet.lab", "10.0.0.10"), ("files.lab", "10.0.0.11"), ("wiki.lab", "10.0.0.12")]
    ping_seq = 1
    while t < end:
        client = rng.choice([CLIENT_A, CLIENT_B])
        kind = rng.random()
        if kind < 0.5:
            name, ip = rng.choice(sites)
            p, t = dns_exchange(t, client, name, ip, rng)
            pkts += p
            p, t = tcp_session(
                t + 0.01, client, SERVER_WEB, 443,
                b"\x16\x03\x01\x00\x50" + bytes(rng.getrandbits(8) for _ in range(40)),
                b"\x16\x03\x03\x00\x60" + bytes(rng.getrandbits(8) for _ in range(60)),
                rng,
            )
            pkts += p
        elif kind < 0.8:
            p, t = tcp_session(
                t, client, SERVER_WEB, 80,
                b"GET /status HTTP/1.1\r\nHost: intranet.lab\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
                rng,
            )
            pkts += p
        else:
            p, t = ping(t, client, SERVER_WEB, ping_seq)
            ping_seq += 1
            pkts += p
        t += rng.uniform(0.3, 1.5)  # think time between activities
    return pkts


# ---------------------------------------------------------------------------
# Scenario builders
# ---------------------------------------------------------------------------

def build_normal(rng: random.Random) -> list[Packet]:
    return background(rng, 0.0, 60.0)


def build_portscan(rng: random.Random) -> list[Packet]:
    pkts = background(rng, 0.0, 30.0)
    open_ports = {22, 80, 443}
    t = 10.0
    ports = list(range(1, 1025))
    rng.shuffle(ports)
    for dport in ports[:200]:  # 200 distinct ports in ~2 s
        sport = rng.randint(40000, 60000)
        seq = rng.randint(1, 2**31)
        pkts.append(stamp(eth_ip(ATTACKER, SERVER_WEB) / TCP(sport=sport, dport=dport, flags="S", seq=seq), t))
        if dport in open_ports:
            reply = TCP(sport=dport, dport=sport, flags="SA", seq=rng.randint(1, 2**31), ack=seq + 1)
        else:
            reply = TCP(sport=dport, dport=sport, flags="RA", seq=0, ack=seq + 1)
        pkts.append(stamp(eth_ip(SERVER_WEB, ATTACKER) / reply, t + 0.0005))
        t += 0.01
    return pkts


def build_burst(rng: random.Random) -> list[Packet]:
    pkts = background(rng, 0.0, 30.0)
    t = 12.0
    for _ in range(600):  # 600 SYNs to port 80 in ~1.2 s, never completed
        sport = rng.randint(1024, 65535)
        pkts.append(
            stamp(
                eth_ip(ATTACKER, SERVER_WEB) / TCP(sport=sport, dport=80, flags="S", seq=rng.randint(1, 2**31)),
                t,
            )
        )
        t += 0.002
    return pkts


def build_suspicious(rng: random.Random) -> list[Packet]:
    pkts = background(rng, 0.0, 40.0)

    # Abnormal TCP flag probes
    t = 5.0
    probes = [("NULL", ""), ("XMAS", "FPU"), ("FIN", "F")]
    for i, (_, flags) in enumerate(probes):
        for dport in (21, 22, 23, 80, 443, 3389):
            pkts.append(
                stamp(
                    eth_ip(ATTACKER, SERVER_WEB)
                    / TCP(sport=50000 + i, dport=dport, flags=flags, seq=rng.randint(1, 2**31)),
                    t,
                )
            )
            t += 0.05

    # Cleartext protocol sessions (Telnet, FTP)
    p, _ = tcp_session(15.0, CLIENT_A, SERVER_WEB, 23, b"login: admin\r\n", b"Password: ", rng)
    pkts += p
    p, _ = tcp_session(18.0, CLIENT_B, SERVER_WEB, 21, b"USER anonymous\r\n", b"331 Please specify the password.\r\n", rng)
    pkts += p

    # ICMP echo flood: 300 requests in ~1.5 s
    t = 25.0
    for seq in range(300):
        pkts.append(
            stamp(eth_ip(ATTACKER, SERVER_WEB) / ICMP(type=8, id=0x6666, seq=seq) / Raw(b"X" * 56), t)
        )
        t += 0.005
    return pkts


def build_hostsweep(rng: random.Random) -> list[Packet]:
    pkts = background(rng, 0.0, 10.0)
    t = 2.0
    for i in range(1, 65):  # 64 different hosts probed on port 445
        target_ip = f"10.0.1.{i}"
        sport = rng.randint(40000, 60000)
        pkts.append(
            stamp(
                eth_ip(ATTACKER, target_ip) / TCP(sport=sport, dport=445, flags="S", seq=rng.randint(1, 2**31)),
                t,
            )
        )
        t += 0.05
    return pkts


def build_slowscan(rng: random.Random) -> list[Packet]:
    pkts = background(rng, 0.0, 250.0)
    t = 5.0
    for i, port in enumerate(range(1000, 1025)):  # 25 distinct ports probed over 192s
        sport = rng.randint(40000, 60000)
        pkts.append(
            stamp(
                eth_ip(ATTACKER, SERVER_WEB) / TCP(sport=sport, dport=port, flags="S", seq=rng.randint(1, 2**31)),
                t,
            )
        )
        t += 8.0
    return pkts


SCENARIOS = {
    "normal.pcap": build_normal,
    "portscan.pcap": build_portscan,
    "slowscan.pcap": build_slowscan,
    "hostsweep.pcap": build_hostsweep,
    "burst.pcap": build_burst,
    "suspicious.pcap": build_suspicious,
}


def generate(out_dir: Path) -> dict[str, int]:
    """Write all scenario PCAPs to ``out_dir``. Returns {filename: packet_count}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for name, builder in SCENARIOS.items():
        rng = random.Random(f"{SEED}-{name}")
        pkts = sorted(builder(rng), key=lambda p: float(p.time))
        wrpcap(str(out_dir / name), pkts)
        counts[name] = len(pkts)
    return counts


def main() -> None:
    default_out = Path(__file__).resolve().parent.parent / "pcaps"
    parser = argparse.ArgumentParser(description="Generate synthetic BantayNet test PCAPs (offline, no sending).")
    parser.add_argument("--out", type=Path, default=default_out, help="output directory (default: pcaps/)")
    args = parser.parse_args()

    for name, count in generate(args.out).items():
        print(f"  wrote {args.out / name}  ({count} packets)")


if __name__ == "__main__":
    main()
