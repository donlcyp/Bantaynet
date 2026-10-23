"""CLI entry point for BantayNet PCAP analysis and alert management."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from src.analyze import analyze
from src.config import load_config
from src.db import clear_alerts, get_alerts
from src.export import write_alerts_csv
from src.store import store_alerts


def _export_all(path: Path) -> int:
    """Write every stored alert to ``path`` as CSV; return the row count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        return write_alerts_csv(fh, get_alerts(limit=100_000))


def run_pipeline(
    pcap_path: Path,
    rules_path: Path | None,
    export_path: Path | None,
    client_name: str = "Default",
) -> int:
    cfg = load_config(rules_path) if rules_path else load_config()
    start_time = time.perf_counter()

    print(f"\n[*] Analyzing: {pcap_path}")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")

    result = analyze(pcap_path, cfg=cfg)
    elapsed = time.perf_counter() - start_time

    store_alerts(result.alerts, pcap_path.name, client_name=client_name)

    # Print summary table
    print("\n" + "=" * 65)
    print("                     BANTAYNET ANALYSIS SUMMARY")
    print("=" * 65)
    print(f" Source File      : {pcap_path.name}")
    print(f" Client / Site    : {client_name}")
    print(f" Total Packets    : {result.stats.total}")
    print(f" IP Packets       : {result.stats.parsed}")
    print(f" Skipped Non-IP   : {result.stats.skipped_non_ip}")
    if result.stats.skipped_allowlist > 0:
        print(f" Skipped (Allow)  : {result.stats.skipped_allowlist} (allowlisted IPs)")
    print(f" Capture Duration : {result.stats.duration:.2f}s")
    print(f" Processing Time  : {elapsed:.3f}s")
    print(f" Total Alerts     : {len(result.alerts)}")
    print("-" * 65)

    by_rule: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for a in result.alerts:
        by_rule[a.rule] = by_rule.get(a.rule, 0) + 1
        by_sev[a.severity] = by_sev.get(a.severity, 0) + 1

    print(" Alerts by Rule:")
    if by_rule:
        for r, count in sorted(by_rule.items()):
            print(f"   - {r:<20}: {count}")
    else:
        print("   - (none)")

    print(" Alerts by Severity:")
    if by_sev:
        for s, count in sorted(by_sev.items()):
            print(f"   - {s.upper():<20}: {count}")
    else:
        print("   - (none)")
    print("=" * 65 + "\n")

    if export_path:
        n = _export_all(export_path)
        print(f"[+] Exported {n} stored alert(s) (all runs) to: {export_path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BantayNet: Rule-based suspicious activity detection system."
    )
    parser.add_argument("--pcap", type=Path, help="Path to PCAP/PCAPNG file for offline analysis")
    parser.add_argument("--rules", type=Path, help="Optional path to custom rules.yaml")
    parser.add_argument("--client", type=str, default="Default", help="Client or site label for this capture")
    parser.add_argument("--export", type=Path, help="Export all stored alerts to CSV at specified path")
    parser.add_argument("--clear-db", action="store_true", help="Clear all stored alerts from database")

    args = parser.parse_args()

    if args.clear_db:
        clear_alerts()
        print("[+] Alert database cleared successfully.")
        return 0

    if not args.pcap:
        if args.export:
            n = _export_all(args.export)
            print(f"[+] Exported {n} stored alert(s) to: {args.export}")
            return 0
        parser.print_help()
        return 1

    return run_pipeline(args.pcap, args.rules, args.export, client_name=args.client)


if __name__ == "__main__":
    sys.exit(main())
