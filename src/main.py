"""CLI entry point for BantayNet PCAP analysis and alert management."""

from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from src.analyze import analyze
from src.config import load_config
from src.db import clear_alerts, get_alerts, init_db, insert_alert


def run_pipeline(pcap_path: Path, rules_path: Path | None, export_path: Path | None) -> int:
    cfg = load_config(rules_path) if rules_path else load_config()
    start_time = time.perf_counter()

    print(f"\n[*] Analyzing: {pcap_path}")
    print("[!] NOTICE: For authorized lab traffic and PCAP files only.")

    result = analyze(pcap_path, cfg=cfg)
    elapsed = time.perf_counter() - start_time

    # Store alerts to SQLite
    init_db()
    for alert in result.alerts:
        insert_alert(
            rule=alert.rule,
            severity=alert.severity,
            src_ip=alert.src,
            dst_ip=alert.dst,
            packet_time=alert.first_ts,
            description=alert.summary,
            evidence_file=alert.evidence_path,
            source_pcap=str(pcap_path.name),
            protocol="TCP" if "TCP" in alert.summary else ("ICMP" if "ICMP" in alert.summary else "OTHER"),
            packet_count=alert.packet_count,
            details=alert.details,
            dst_port=alert.dst_port,
        )


    # Print summary table
    print("\n" + "=" * 65)
    print("                     BANTAYNET ANALYSIS SUMMARY")
    print("=" * 65)
    print(f" Source File      : {pcap_path.name}")
    print(f" Total Packets    : {result.stats.total}")
    print(f" IP Packets       : {result.stats.parsed}")
    print(f" Skipped Non-IP   : {result.stats.skipped_non_ip}")
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
        export_path.parent.mkdir(parents=True, exist_ok=True)
        with open(export_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Detected At", "Packet Time", "Rule", "Severity",
                "Source IP", "Destination IP", "Protocol", "Description",
                "Evidence File", "Source PCAP"
            ])
            all_alerts = get_alerts(limit=1000)
            for row in all_alerts:
                writer.writerow([
                    row["id"], row["detected_at"], row["packet_time"],
                    row["rule"], row["severity"], row["src_ip"], row["dst_ip"],
                    row["protocol"], row["description"], row["evidence_file"],
                    row["source_pcap"]
                ])
        print(f"[+] Exported alerts to: {export_path}")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BantayNet: Rule-based suspicious activity detection system."
    )
    parser.add_argument("--pcap", type=Path, help="Path to PCAP/PCAPNG file for offline analysis")
    parser.add_argument("--rules", type=Path, help="Optional path to custom rules.yaml")
    parser.add_argument("--export", type=Path, help="Export all stored alerts to CSV at specified path")
    parser.add_argument("--clear-db", action="store_true", help="Clear all stored alerts from database")

    args = parser.parse_args()

    if args.clear_db:
        clear_alerts()
        print("[+] Alert database cleared successfully.")
        return 0

    if not args.pcap:
        if args.export:
            # Export without analyzing new pcap
            args.export.parent.mkdir(parents=True, exist_ok=True)
            with open(args.export, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "ID", "Detected At", "Packet Time", "Rule", "Severity",
                    "Source IP", "Destination IP", "Protocol", "Description",
                    "Evidence File", "Source PCAP"
                ])
                for row in get_alerts(limit=5000):
                    writer.writerow([
                        row["id"], row["detected_at"], row["packet_time"],
                        row["rule"], row["severity"], row["src_ip"], row["dst_ip"],
                        row["protocol"], row["description"], row["evidence_file"],
                        row["source_pcap"]
                    ])
            print(f"[+] Exported alerts to: {args.export}")
            return 0
        parser.print_help()
        return 1

    return run_pipeline(args.pcap, args.rules, args.export)


if __name__ == "__main__":
    sys.exit(main())
