# BantayNet: A Rule-Based Suspicious Activity Detection System Using Scapy and PCAP Analysis

> **NOTICE:** For authorized lab traffic and PCAP files only. The system is strictly detect-and-alert only. It does not send packets, scan hosts, flood, exploit, block traffic, or modify network state.

---

### Project Proposal Metadata
- **Proponent / Author:** Donyl Cyprus R. Basio
- **Subject:** System Administration and Maintenance – IT23/L
- **Course Code:** 3493
- **Time / Schedule:** 7:30 - 9:30 PM
- **Project Name:** #4 IntrusionAlert: Suspicious Activity Detection System
- **Company / Institution:** IT Services

---

## Overview
**BantayNet** is a rule-based suspicious activity detection system designed for network administrators, IT security officers, and IT support teams (such as in managed service providers or BPOs). These teams often oversee multi-client networks with small staffs and require an automated, non-disruptive method to inspect authorized network traffic or recorded Wireshark captures (`.pcap` / `.pcapng` files) to immediately uncover signs of reconnaissance and malicious anomalies.

BantayNet turns thousands of raw packets into a prioritized, actionable list of security incidents with forensically extracted PCAP evidence snippets, exportable CSV reports, and a web dashboard.

---

## 7 Core Detection Techniques

1. **Port Scan Detection** (`port_scan`)
   - *Technique:* Detects a single source rapidly probing many distinct destination ports on a target host within a configurable sliding window (default: 50 distinct ports within 5 seconds).
2. **Slow Scan Detection** (`slow_scan`)
   - *Technique:* Catches low-and-slow reconnaissance probing 20 or more distinct ports across a longer window (default: 300 seconds) without triggering fast-scan thresholds.
3. **Host Sweep Detection** (`host_sweep`)
   - *Technique:* Detects horizontal scanning where one source probes the same destination port across 50 or more different target hosts within a sliding window.
4. **SYN Burst Detection** (`syn_burst`)
   - *Technique:* Identifies abnormal bursts of SYN packets without completed three-way handshakes (indicative of SYN floods or volumetric connection exhaustion).
5. **Suspicious TCP Flag Patterns** (`suspicious_flags`)
   - *Technique:* Flags stealth scan patterns including `NULL` (no flags set), `XMAS` (FIN+PSH+URG), and `FIN-only` packets.
6. **Cleartext Protocol Usage** (`cleartext`)
   - *Technique:* Detects unencrypted authentication and command traffic on sensitive protocols (Telnet on port 23, FTP on port 21, POP3 on port 110, IMAP on port 143).
7. **ICMP Flood Detection** (`icmp_flood`)
   - *Technique:* Flags excessive ICMP and ICMPv6 echo requests from a single source exceeding high-rate thresholds.

---

## User Roles & Capabilities

- **IT Administrator:**
  - Configures detection rules, thresholds, and sliding window timings in `rules/rules.yaml`.
  - Manages database engine (XAMPP MySQL or SQLite fallback) and stored evidence snippets.
  - Reviews complete system alerts, evidence, and audit logs.
- **Security Analyst:**
  - Uploads and analyzes PCAP / PCAPNG capture files.
  - Investigates incident alerts using forensically isolated `.pcap` evidence packets.
  - Filters alert histories by rule, severity, or source IP and exports CSV incident reports.
- **Viewer (Team Lead / Auditor):**
  - Monitors high-level dashboard summaries, risk distribution cards, and read-only alert details.

---

## System Flow
$$\text{Load PCAP} \longrightarrow \text{Parse Packets (Scapy)} \longrightarrow \text{Apply Detection Rules (rules.yaml)} \longrightarrow \text{Build Alert + Evidence} \longrightarrow \text{Store in Database} \longrightarrow \text{View on Dashboard / Export CSV}$$

---

## Technologies & Frameworks

| Component | Technology |
|---|---|
| **Languages** | Python 3, SQL, Vanilla JavaScript |
| **Network Analysis** | Scapy (Python packet parsing), PyYAML, Wireshark PCAP/PCAPNG |
| **Backend** | Flask (Python), PyMySQL |
| **Frontend** | HTML5, Modern CSS3, Jinja2 Templates |
| **Database** | MySQL (XAMPP MariaDB) with seamless automatic fallback to local SQLite (`bantaynet.db`) |
| **Testing** | pytest, synthetic PCAP generators |

---

## Project Structure
```text
BantayNet/
├── pcaps/              # Sample capture files (.pcap, .pcapng) & upload directory
├── rules/              # Detection rule configurations (rules.yaml)
├── src/                # Core detection engine
│   ├── alerts.py       # Alert data models & incident representations
│   ├── analyze.py      # End-to-end capture analysis pipeline
│   ├── config.py       # Configuration parser & validation
│   ├── db.py           # MySQL (XAMPP) & SQLite database adapter
│   ├── detector.py     # 7 sliding-window detection rules & incident builder
│   ├── evidence.py     # PCAP evidence snippet extractor
│   ├── export.py       # CSV report exporter
│   ├── main.py         # CLI analysis interface
│   ├── parser.py       # Streaming packet reader & record normalizer
│   └── store.py        # Database alert ingestion helper
├── dashboard/          # Flask web dashboard
│   ├── app.py          # Dashboard routes, upload handler, & CSV export
│   ├── templates/      # Jinja2 templates (index.html, alert.html, base.html)
│   └── static/         # Custom styling (style.css)
├── evidence/           # Forensic evidence .pcap snippets for each alert
├── reports/            # Exported CSV alert reports
└── tests/              # Unit & integration test suite with synthetic PCAP generators
```

---

## Setup & Quickstart

### 1. Create Virtual Environment & Install Dependencies
```bash
python -m venv venv
venv\Scripts\activate   # On Windows PowerShell / Command Prompt
# source venv/bin/activate # Linux / macOS
pip install -r requirements.txt
```

### 2. Generate Sample PCAPs
Generate reproducible synthetic PCAPs covering all detection scenarios:
```bash
python -m tests.make_synthetic_pcaps
```
This generates:
- `pcaps/normal.pcap` — benign background traffic (no alerts)
- `pcaps/portscan.pcap` — fast multi-port SYN sweep
- `pcaps/slowscan.pcap` — low-and-slow probing across 25 ports over 200s
- `pcaps/hostsweep.pcap` — horizontal sweep targeting 64 hosts on port 445
- `pcaps/burst.pcap` — high-rate SYN flood burst
- `pcaps/suspicious.pcap` — NULL/XMAS/FIN stealth scans, Telnet/FTP cleartext, and ICMP flood

---

## Usage

### Command Line Interface (CLI)
Analyze any capture file offline:
```bash
# Analyze a specific PCAP
python -m src.main --pcap pcaps/portscan.pcap

# Analyze and export alerts to a CSV report
python -m src.main --pcap pcaps/hostsweep.pcap --export reports/sweep_alerts.csv

# Export all stored database alerts to CSV
python -m src.main --export reports/all_alerts.csv

# Clear stored database alerts
python -m src.main --clear-db
```

### Web Dashboard
Start the web dashboard:
```bash
python -m dashboard.app
```
Then navigate to **http://127.0.0.1:5000** in your browser:
- **Interactive Metrics Cards:** Real-time counts of total, high, medium, and low severity alerts.
- **Upload Capture:** Drag and drop `.pcap` or `.pcapng` files up to 50 MB for instant analysis.
- **Evidence Extraction:** View individual alerts and download forensically isolated `.pcap` evidence files.
- **Search & Filtering:** Filter by rule (`port_scan`, `slow_scan`, `host_sweep`, `syn_burst`, `suspicious_flags`, `cleartext`, `icmp_flood`), severity, source IP, or keywords.
- **CSV Export:** Download CSV reports directly from the dashboard.

---

## Database Configuration
BantayNet defaults to connecting to **XAMPP MySQL** (host `127.0.0.1:3306`, user `root`, database `bantaynet_db`).
- If MySQL is running in XAMPP, BantayNet automatically creates the database and tables.
- If MySQL is not reachable, BantayNet **automatically and seamlessly falls back** to a local SQLite database (`bantaynet.db`), requiring zero setup or configuration change.
- You can change engine settings directly in `rules/rules.yaml`.

---

## Testing
Run the automated test suite:
```bash
python -m pytest -v
```
All tests verify rule triggers, threshold boundaries, sliding windows, database storage, evidence extraction, and CSV generation.
