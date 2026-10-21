"""Single place that saves analysis results to the database."""

from __future__ import annotations

from src.alerts import Alert
from src.db import init_db, insert_alert


def store_alerts(alerts: list[Alert], source_pcap: str) -> None:
    """Persist every alert from one analysis run."""
    init_db()
    for a in alerts:
        insert_alert(
            rule=a.rule,
            severity=a.severity,
            src_ip=a.src,
            dst_ip=a.dst,
            packet_time=a.first_ts,
            description=a.summary,
            evidence_file=a.evidence_path,
            source_pcap=source_pcap,
            protocol=a.protocol,
            packet_count=a.packet_count,
            details=a.details,
            dst_port=a.dst_port,
        )
