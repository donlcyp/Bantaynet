"""One CSV writer shared by the CLI and the dashboard."""

from __future__ import annotations

import csv
from typing import Any, Iterable, TextIO

COLUMNS = [
    ("id", "ID"), ("detected_at", "Detected At"), ("packet_time", "Packet Time"),
    ("rule", "Rule"), ("severity", "Severity"), ("src_ip", "Source IP"),
    ("dst_ip", "Destination IP"), ("dst_port", "Target Port"), ("protocol", "Protocol"),
    ("description", "Description"), ("source_pcap", "Source PCAP"),
    ("packet_count", "Packet Count"), ("evidence_file", "Evidence File"),
]


def write_alerts_csv(fh: TextIO, rows: Iterable[dict[str, Any]]) -> int:
    """Write ``rows`` (dicts keyed like the DB columns) to ``fh``; return the row count."""
    writer = csv.writer(fh)
    writer.writerow([label for _, label in COLUMNS])
    n = 0
    for row in rows:
        writer.writerow([row.get(key, "") if row.get(key) is not None else "" for key, _ in COLUMNS])
        n += 1
    return n
