"""Run the full detection pipeline on one capture file.

    parse (stream) -> detect -> sort alerts -> write evidence snippets

Quick check from the command line::

    python -m src.analyze pcaps/portscan.pcap
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from src.alerts import Alert
from src.config import Config, ConfigError, load_config
from src.detector import Detector
from src.evidence import write_evidence
from src.parser import ParseStats, PcapError, iter_packets

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class AnalysisResult:
    pcap: Path
    alerts: list[Alert]
    stats: ParseStats
    run_tag: str


def analyze(
    pcap: str | Path,
    cfg: Config | None = None,
    evidence_dir: str | Path | None = None,
) -> AnalysisResult:
    """Analyze ``pcap`` and return its alerts.

    ``evidence_dir`` overrides ``evidence.output_dir`` from the config; relative
    config paths are resolved against the project root.
    """
    pcap = Path(pcap)
    cfg = cfg if cfg is not None else load_config()
    run_tag = datetime.now().strftime("%Y%m%d-%H%M%S")

    detector = Detector(cfg)
    stats = ParseStats()
    alerts: list[Alert] = []
    for rec in iter_packets(pcap, stats):
        alerts.extend(detector.process(rec))
    alerts.extend(detector.finish())
    stats.skipped_allowlist = detector.skipped_allowlist
    alerts.sort(key=lambda a: (a.first_ts, a.rule, a.src, a.dst))

    if cfg.evidence.enabled and alerts:
        out = Path(evidence_dir) if evidence_dir is not None else Path(cfg.evidence.output_dir)
        if not out.is_absolute():
            out = PROJECT_ROOT / out
        write_evidence(pcap, alerts, out, run_tag)

    return AnalysisResult(pcap=pcap, alerts=alerts, stats=stats, run_tag=run_tag)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m src.analyze <file.pcap>", file=sys.stderr)
        return 2
    try:
        result = analyze(argv[0])
    except (PcapError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    s = result.stats
    print(f"{result.pcap.name}: {s.parsed} IP packets over {s.duration:.1f}s -> {len(result.alerts)} alert(s)")
    for a in result.alerts:
        print(f"  [{a.severity.upper():6}] {a.rule:16} {a.summary}")
        if a.evidence_path:
            print(f"           evidence: {Path(a.evidence_path).name} ({len(a.evidence_indexes)} packets)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
