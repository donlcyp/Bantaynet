"""Single place that saves analysis results to the database."""

from __future__ import annotations

import logging
from src.alerts import Alert
from src.db import init_db, insert_alert

logger = logging.getLogger("bantaynet.store")


def store_alerts(
    alerts: list[Alert],
    source_pcap: str,
    client_name: str = "Default",
    notify: bool = True,
) -> list[int]:
    """Persist every alert from one analysis run and optionally trigger integrations dispatch."""
    init_db()
    inserted_ids: list[int] = []
    for a in alerts:
        aid = insert_alert(
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
            client_name=client_name or "Default",
        )
        setattr(a, "id", aid)
        inserted_ids.append(aid)

    if notify and alerts:
        try:
            from src.integrations import dispatch
            dispatch(alerts, client_name=client_name)
        except Exception as exc:
            logger.warning("Alert notification dispatch failed: %s", exc)

    return inserted_ids
