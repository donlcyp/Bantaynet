# BantayNet

> **NOTICE:** For authorized lab traffic and PCAP files only. The system is strictly detect-and-alert only. It does not send packets, scan hosts, flood, exploit, block traffic, or modify network state.

A rule-based suspicious activity detection system using Scapy and PCAP analysis.

## Features
- **Port-Scan Detection:** Detects rapid probing across multiple destination ports within configurable sliding time windows.
- **Connection Burst Detection:** Identifies abnormal bursts of SYN packets (e.g., SYN flood patterns).
- **Suspicious Protocol Indicators:** Identifies abnormal TCP flags (NULL, XMAS, FIN-only scans), cleartext protocol usage, and ICMP floods.
- **Evidence Extraction:** Extracts PCAP snippets for triggered alerts for forensic analysis.
- **Storage & Dashboard:** Persists alerts in SQLite and provides a web dashboard and CSV exports.

## Project Structure
```text
BantayNet/
├── pcaps/              # Sample capture files (.pcap, .pcapng)
├── rules/              # Detection rule configurations (rules.yaml)
├── src/                # Core engine (parser, detector, alerts, db, config, main)
├── dashboard/          # Flask web dashboard (UI & alert viewer)
├── evidence/           # Generated .pcap snippets for each alert
├── reports/            # Exported CSV alert reports
└── tests/              # Unit & integration tests, synthetic PCAP generators
```

## Setup & Quickstart
```bash
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate # Linux/macOS
pip install -r requirements.txt
```
