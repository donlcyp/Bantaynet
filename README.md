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

## Usage

### Analyze a capture (CLI)
```bash
python -m tests.make_synthetic_pcaps        # create sample PCAPs in pcaps/
python -m src.main --pcap pcaps/portscan.pcap
python -m src.main --pcap pcaps/portscan.pcap --export reports/alerts.csv
python -m src.main --export reports/all.csv  # export everything stored
python -m src.main --clear-db               # wipe stored alerts
```

### Start the dashboard
```bash
python -m dashboard.app
```
Open http://127.0.0.1:5000. Upload a `.pcap` or `.pcapng`, filter alerts, open an alert for its evidence packets, or export CSV.

### Database
Default engine is MySQL (XAMPP, user `root`, database `bantaynet_db`). If MySQL is not running, BantayNet falls back to a local SQLite file (`bantaynet.db`). Change `database.engine` in `rules/rules.yaml` to `sqlite` to skip MySQL entirely.

### Tests
```bash
python -m pytest -q
```

### Rules
All thresholds are in `rules/rules.yaml`: `port_scan`, `slow_scan`, `syn_burst`, `suspicious_flags`, `cleartext_protocols`, `icmp_flood`.

