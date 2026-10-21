"""Rule-based detection engine.

Design
------
* **Sliding windows** keyed by (rule, src, dst[, port]) hold recent matching
  packets. Windows are measured in capture time, so results don't depend on how
  fast the file is read.
* When a window crosses its threshold, an **incident** opens. The packets already
  in the window become its first evidence, so the alert covers the start of the
  attack, not just the packet that tipped it over.
* While an incident is open, further matching packets for the same key extend
  it instead of raising new alerts. It closes once no matching packet has been
  seen for ``alerts.cooldown_seconds``, or when the capture ends. Result: one
  sustained attack produces one alert with a full packet count.

Usage::

    det = Detector(cfg)
    for rec in iter_packets(path):
        for alert in det.process(rec):   # alerts whose incident just closed
            ...
    remaining = det.finish()             # close everything still open
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Hashable

from src.alerts import Alert
from src.config import Config
from src.parser import ACK, FIN, PSH, RST, SYN, URG, PacketRecord

SWEEP_INTERVAL = 1.0  # seconds of capture time between checks for idle incidents / stale windows


class SlidingWindow:
    """Packets seen in the last ``seconds`` for one key, with per-value counts."""

    __slots__ = ("seconds", "items", "counts")

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.items: deque[tuple[float, Hashable, int]] = deque()  # (ts, value, packet index)
        self.counts: Counter = Counter()

    def add(self, ts: float, value: Hashable, index: int) -> None:
        self.items.append((ts, value, index))
        self.counts[value] += 1
        self.evict(ts)

    def evict(self, now: float) -> None:
        while self.items and now - self.items[0][0] > self.seconds:
            _, value, _ = self.items.popleft()
            self.counts[value] -= 1
            if not self.counts[value]:
                del self.counts[value]

    def __len__(self) -> int:
        return len(self.items)

    @property
    def distinct(self) -> int:
        return len(self.counts)


@dataclass
class _Incident:
    rule: str
    severity: str
    src: str
    dst: str
    first_ts: float
    last_ts: float
    count: int
    indexes: list[int]
    ports: set[int] = field(default_factory=set)
    extra: dict[str, Any] = field(default_factory=dict)


class Detector:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._windows: dict[tuple, SlidingWindow] = {}
        self._open: dict[tuple, _Incident] = {}
        self._next_sweep: float | None = None
        self._max_evidence = cfg.evidence.max_packets

    # -- public API ---------------------------------------------------------

    def process(self, rec: PacketRecord) -> list[Alert]:
        closed = self._sweep(rec.ts)
        c = self.cfg
        if rec.proto == "TCP":
            if c.port_scan.enabled:
                self._port_scan(rec)
            if c.syn_burst.enabled:
                self._syn_burst(rec)
            if c.suspicious_flags.enabled:
                self._suspicious_flags(rec)
            if c.cleartext_protocols.enabled:
                self._cleartext(rec)
        elif rec.proto == "ICMP" and c.icmp_flood.enabled:
            self._icmp_flood(rec)
        return closed

    def finish(self) -> list[Alert]:
        alerts = [self._to_alert(inc) for inc in self._open.values()]
        self._open.clear()
        self._windows.clear()
        return alerts

    # -- incident bookkeeping ----------------------------------------------

    def _sweep(self, now: float) -> list[Alert]:
        if self._next_sweep is not None and now < self._next_sweep:
            return []
        self._next_sweep = now + SWEEP_INTERVAL

        cooldown = self.cfg.alerts.cooldown_seconds
        idle = [k for k, inc in self._open.items() if now - inc.last_ts > cooldown]
        closed = [self._to_alert(self._open.pop(k)) for k in idle]

        # Drop windows with nothing left in them so memory stays bounded on long captures.
        stale = []
        for key, w in self._windows.items():
            w.evict(now)
            if not w:
                stale.append(key)
        for key in stale:
            del self._windows[key]
        return closed

    def _window(self, key: tuple, seconds: float) -> SlidingWindow:
        w = self._windows.get(key)
        if w is None:
            w = self._windows[key] = SlidingWindow(seconds)
        return w

    def _open_incident(
        self, key: tuple, rule: str, severity: str, src: str, dst: str,
        rec: PacketRecord, window: SlidingWindow | None = None,
    ) -> _Incident:
        if window is not None:
            items = window.items
            inc = _Incident(rule, severity, src, dst, items[0][0], rec.ts, len(items),
                            [i for _, _, i in items][: self._max_evidence])
            self._windows.pop(key, None)  # window's job is done; the incident tracks from here
        else:
            inc = _Incident(rule, severity, src, dst, rec.ts, rec.ts, 1, [rec.index])
        self._open[key] = inc
        return inc

    def _extend(self, inc: _Incident, rec: PacketRecord) -> None:
        inc.last_ts = rec.ts
        inc.count += 1
        if len(inc.indexes) < self._max_evidence:
            inc.indexes.append(rec.index)

    # -- rules ---------------------------------------------------------------

    def _port_scan(self, rec: PacketRecord) -> None:
        # Probes are connection attempts / stealth probes: no ACK, no RST.
        if not rec.has_flags(clear=ACK | RST):
            return
        key = ("port_scan", rec.src, rec.dst)
        if inc := self._open.get(key):
            self._extend(inc, rec)
            inc.ports.add(rec.dport)
            return
        r = self.cfg.port_scan
        w = self._window(key, r.window_seconds)
        w.add(rec.ts, rec.dport, rec.index)
        if w.distinct >= r.distinct_ports:
            ports = set(w.counts)
            inc = self._open_incident(key, "port_scan", r.severity, rec.src, rec.dst, rec, w)
            inc.ports = ports

    def _syn_burst(self, rec: PacketRecord) -> None:
        if not rec.has_flags(set_=SYN, clear=ACK | RST):
            return
        key = ("syn_burst", rec.src, rec.dst, rec.dport)
        if inc := self._open.get(key):
            self._extend(inc, rec)
            return
        r = self.cfg.syn_burst
        w = self._window(key, r.window_seconds)
        w.add(rec.ts, None, rec.index)
        if len(w) >= r.syn_count:
            inc = self._open_incident(key, "syn_burst", r.severity, rec.src, rec.dst, rec, w)
            inc.ports = {rec.dport}

    def _icmp_flood(self, rec: PacketRecord) -> None:
        if rec.icmp_type != 8:  # echo request
            return
        key = ("icmp_flood", rec.src, rec.dst)
        if inc := self._open.get(key):
            self._extend(inc, rec)
            return
        r = self.cfg.icmp_flood
        w = self._window(key, r.window_seconds)
        w.add(rec.ts, None, rec.index)
        if len(w) >= r.echo_requests:
            self._open_incident(key, "icmp_flood", r.severity, rec.src, rec.dst, rec, w)

    def _suspicious_flags(self, rec: PacketRecord) -> None:
        r = self.cfg.suspicious_flags
        flags = rec.tcp_flags
        if flags == 0 and r.null_scan:
            pattern = "NULL"
        elif flags & (FIN | PSH | URG) == (FIN | PSH | URG) and r.xmas_scan:
            pattern = "XMAS"
        elif flags == FIN and r.fin_only:
            pattern = "FIN"
        else:
            return
        key = ("suspicious_flags", rec.src, rec.dst, pattern)
        if inc := self._open.get(key):
            self._extend(inc, rec)
        else:
            inc = self._open_incident(key, "suspicious_flags", r.severity, rec.src, rec.dst, rec)
            inc.extra["pattern"] = pattern
        inc.ports.add(rec.dport)

    def _cleartext(self, rec: PacketRecord) -> None:
        r = self.cfg.cleartext_protocols
        # Client -> server: only extends a session already confirmed live.
        if rec.dport in r.ports:
            if inc := self._open.get(("cleartext", rec.src, rec.dst, rec.dport)):
                self._extend(inc, rec)
                return
        # Server -> client: an ACK without RST proves a real service answered.
        # This keeps port scans that merely touch port 21/23 from raising cleartext alerts.
        if rec.sport in r.ports:
            key = ("cleartext", rec.dst, rec.src, rec.sport)
            if inc := self._open.get(key):
                self._extend(inc, rec)
            elif rec.has_flags(set_=ACK, clear=RST):
                inc = self._open_incident(key, "cleartext", r.severity, rec.dst, rec.src, rec)
                inc.ports = {rec.sport}
                inc.extra["protocol"] = r.ports[rec.sport]

    # -- alert construction --------------------------------------------------

    def _to_alert(self, inc: _Incident) -> Alert:
        dur = inc.last_ts - inc.first_ts
        ports = sorted(inc.ports)
        details: dict[str, Any] = {}

        if inc.rule == "port_scan":
            details = {"distinct_ports": len(ports), "sample_ports": ports[:20]}
            summary = f"{inc.src} probed {len(ports)} distinct TCP ports on {inc.dst} in {dur:.1f}s"
        elif inc.rule == "syn_burst":
            rate = inc.count / dur if dur > 0 else float(inc.count)
            details = {"dport": ports[0], "syn_count": inc.count, "rate_per_sec": round(rate, 1)}
            summary = (f"{inc.count} SYN packets from {inc.src} to {inc.dst}:{ports[0]} "
                       f"in {dur:.1f}s ({rate:.0f}/s), handshakes not completed")
        elif inc.rule == "icmp_flood":
            rate = inc.count / dur if dur > 0 else float(inc.count)
            details = {"echo_requests": inc.count, "rate_per_sec": round(rate, 1)}
            summary = f"{inc.count} ICMP echo requests from {inc.src} to {inc.dst} in {dur:.1f}s ({rate:.0f}/s)"
        elif inc.rule == "suspicious_flags":
            pattern = inc.extra["pattern"]
            details = {"pattern": pattern, "ports": ports}
            summary = (f"{inc.count} TCP {pattern} probe(s) from {inc.src} to {inc.dst} "
                       f"on port(s) {', '.join(map(str, ports[:10]))}{'...' if len(ports) > 10 else ''}")
        elif inc.rule == "cleartext":
            proto = inc.extra["protocol"]
            details = {"protocol": proto, "port": ports[0]}
            summary = f"Cleartext {proto} session between {inc.src} and {inc.dst}:{ports[0]}"
        else:  # pragma: no cover - every rule above sets a summary
            summary = inc.rule

        dst_port_str: str | None = None
        if ports:
            if len(ports) == 1:
                dst_port_str = str(ports[0])
            elif len(ports) <= 3:
                dst_port_str = ", ".join(map(str, ports))
            else:
                dst_port_str = f"Multiple ({len(ports)} ports)"


        return Alert(
            rule=inc.rule, severity=inc.severity, src=inc.src, dst=inc.dst,
            first_ts=inc.first_ts, last_ts=inc.last_ts, packet_count=inc.count,
            summary=summary, details=details, evidence_indexes=inc.indexes,
            dst_port=dst_port_str,
        )

