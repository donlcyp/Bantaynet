"""Write a PCAP snippet of the packets behind each alert.

Detection only keeps packet *indexes*, not packets, so memory stays small.
This module makes a second streaming pass over the original capture and copies
the referenced packets, unmodified (original timestamps and bytes), into one
file per alert.
"""

from __future__ import annotations

import re
from pathlib import Path

from scapy.utils import PcapReader, PcapWriter

from src.alerts import Alert

# Keep the number of simultaneously open output files well under OS limits.
MAX_OPEN_WRITERS = 200


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)


def write_evidence(pcap_path: str | Path, alerts: list[Alert], out_dir: str | Path, run_tag: str) -> None:
    """Write ``<stem>_<run_tag>_<NNN>_<rule>.pcap`` for each alert and set ``alert.evidence_path``."""
    pcap_path, out_dir = Path(pcap_path), Path(out_dir)
    todo = [(n, a) for n, a in enumerate(alerts, 1) if a.evidence_indexes]
    if not todo:
        return
    out_dir.mkdir(parents=True, exist_ok=True)

    for start in range(0, len(todo), MAX_OPEN_WRITERS):
        batch = todo[start : start + MAX_OPEN_WRITERS]
        wanted: dict[int, list[int]] = {}
        for slot, (_, alert) in enumerate(batch):
            for idx in alert.evidence_indexes:
                wanted.setdefault(idx, []).append(slot)
        last_needed = max(wanted)

        paths = [out_dir / f"{_safe(pcap_path.stem)}_{run_tag}_{n:03d}_{a.rule}.pcap" for n, a in batch]
        writers = [PcapWriter(str(p), sync=False) for p in paths]
        try:
            with PcapReader(str(pcap_path)) as reader:
                for idx, pkt in enumerate(reader):
                    for slot in wanted.get(idx, ()):
                        writers[slot].write(pkt)
                    if idx >= last_needed:
                        break
        finally:
            for w in writers:
                w.close()

        for path, (_, alert) in zip(paths, batch):
            alert.evidence_path = str(path)
