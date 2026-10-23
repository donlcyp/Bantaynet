"""One CSV writer shared by the CLI and the dashboard."""

from __future__ import annotations

import csv
from typing import Any, Iterable, TextIO

from src.mitre import attach_mitre_info

COLUMNS = [
    ("id", "ID"), ("detected_at", "Detected At"), ("packet_time", "Packet Time"),
    ("rule", "Rule"), ("mitre_tag", "MITRE ATT&CK"), ("severity", "Severity"),
    ("client_name", "Client / Site"), ("status", "Status"), ("src_ip", "Source IP"),
    ("dst_ip", "Destination IP"), ("dst_port", "Target Port"), ("protocol", "Protocol"),
    ("description", "Description"), ("analyst_note", "Analyst Note"),
    ("source_pcap", "Source PCAP"), ("packet_count", "Packet Count"),
    ("evidence_file", "Evidence File"),
]


def write_alerts_csv(fh: TextIO, rows: Iterable[dict[str, Any]]) -> int:
    """Write ``rows`` (dicts keyed like the DB columns) to ``fh``; return the row count."""
    writer = csv.writer(fh)
    writer.writerow([label for _, label in COLUMNS])
    n = 0
    for row in rows:
        r = dict(row)
        if "mitre_tag" not in r:
            attach_mitre_info(r)
        writer.writerow([r.get(key, "") if r.get(key) is not None else "" for key, _ in COLUMNS])
        n += 1
    return n
