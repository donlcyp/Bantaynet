"""Alert data model shared by the detector, evidence writer, storage, and dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Alert:
    rule: str                 # e.g. "port_scan", "syn_burst"
    severity: str             # "low" | "medium" | "high"
    src: str                  # source / client address
    dst: str                  # destination / server address
    first_ts: float           # capture time of the first packet in the incident
    last_ts: float            # capture time of the last packet in the incident
    packet_count: int         # all matching packets, including ones beyond the evidence cap
    summary: str              # one-line human-readable description
    details: dict[str, Any] = field(default_factory=dict)
    evidence_indexes: list[int] = field(default_factory=list, repr=False)
    evidence_path: str | None = None
    protocol: str = "TCP"     # "TCP" | "UDP" | "ICMP" (set by the rule, never guessed from text)
    dst_port: str | None = None   # display label, e.g. "80" or "Multiple (200 ports)"

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @staticmethod
    def fmt_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"

    def to_dict(self) -> dict[str, Any]:
        """Serializable form (evidence packet indexes omitted; they can be large)."""
        d = asdict(self)
        d.pop("evidence_indexes")
        d["duration"] = round(self.duration, 6)
        return d
