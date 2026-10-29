# 🛡️ BantayNet: Rule-Based Suspicious Activity Detection & Forensic PCAP Analysis System

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Dashboard-Flask%203.x-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Packet Analysis](https://img.shields.io/badge/Engine-Scapy-red.svg?logo=wireshark&logoColor=white)](https://scapy.net/)
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Mapped-orange.svg)](https://attack.mitre.org/)
[![Database](https://img.shields.io/badge/Storage-MySQL%20%7C%20SQLite%20Fallback-00758F.svg?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Tests](https://img.shields.io/badge/Tests-pytest%20Passing-brightgreen.svg?logo=pytest&logoColor=white)](https://pytest.org/)
[![License](https://img.shields.io/badge/Usage-Authorized%20Lab%20Traffic%20Only-lightgrey.svg)](#security--usage-policy)

> **⚠️ AUTHORIZED USE ONLY:** BantayNet is designed strictly for offline PCAP/PCAPNG capture analysis and authorized lab network monitoring. The system operates on a **detect-and-alert only** architecture: it does not craft or inject packets, perform port scanning, flood targets, execute exploits, block traffic, or alter network host configurations.

---

## 📋 Academic Project Proposal & Proponent Metadata

| Field | Detail |
|---|---|
| **Proponent / Author** | **Donyl Cyprus R. Basio** |
| **Subject** | System Administration and Maintenance – IT23/L |
| **Course Code** | 3493 |
| **Schedule / Time** | 7:30 PM – 9:30 PM |
| **Project Title** | Project #4 — IntrusionAlert: Suspicious Activity Detection System |
| **Company / Institution** | IT Services |

---

## 📖 Executive Summary & Overview

Modern IT administrators, system maintenance engineers, and security analysts in Managed Service Providers (MSPs) and Business Process Outsourcing (BPO) environments are responsible for multi-tenant networks with limited personnel. When suspicious activity or performance degradation arises, teams often capture network traffic into Wireshark (`.pcap` / `.pcapng`) files containing tens or hundreds of thousands of raw packets. Manually combing through these captures is tedious, error-prone, and time-intensive.

**BantayNet** automates this triage pipeline. By pairing **Scapy's** low-level packet parsing engine with a configurable **sliding-window stateful rule engine**, BantayNet immediately flags reconnaissance, brute-force anomalies, stealth scans, denial-of-service indicators, and cleartext credential transmission.

### Key Capabilities
- 🔍 **7 Stateful Detection Rules:** Port scans, slow low-and-slow probes, host sweeps, SYN bursts, stealth flag anomalies (NULL/XMAS/FIN), cleartext protocols, and ICMP floods.
- 🎯 **MITRE ATT&CK Alignment:** Each detection technique is mapped directly to official MITRE ATT&CK technique IDs (e.g., T1046, T1018, T1498).
- 🧬 **Forensic Evidence Snippets:** Isolates and saves mini-PCAPs containing *only* the specific offending packets for each incident, enabling rapid peer verification in Wireshark.
- 📄 **Executive & Technical PDF Dossiers:** Generates presentation-ready executive summary reports and per-incident forensic PDF files using ReportLab.
- 👥 **Role-Based Access Control (RBAC):** Tiered roles (`admin`, `analyst`, `viewer`) with session protection, password hashing, and user management.
- 🗄️ **Zero-Friction Dual Database:** Out-of-the-box support for **XAMPP MySQL / MariaDB** with an automatic, zero-config fallback to **SQLite** (`bantaynet.db`) if MySQL is offline.
- 🚀 **Dual Interface:** Run comprehensive audits via the offline **Command Line Interface (CLI)** or interact with the responsive **Flask Web Dashboard**.
- 🔔 **Alert Notification System:** Optional SMTP email dispatch for high-severity alerts.

---

## 🎯 Detection Techniques & MITRE ATT&CK Matrix

BantayNet implements 7 stateful detection algorithms configured via [`rules/rules.yaml`](file:///home/donylcb/Documents/Code/Bantaynet/rules/rules.yaml):

| Rule Key | Technique Name | Detection Logic | Default Thresholds | MITRE ATT&CK ID & Tactic |
|---|---|---|---|---|
| `port_scan` | **Fast Port Scan** | Detects a single IP probing many distinct TCP/UDP destination ports on a single host. | $\ge 50$ ports in $\le 5$ s | **[T1046](https://attack.mitre.org/techniques/T1046/)** — Discovery |
| `slow_scan` | **Low & Slow Scan** | Catches stealthy, spaced-out reconnaissance designed to evade fast-scan thresholds. | $\ge 20$ ports across $300$ s | **[T1046](https://attack.mitre.org/techniques/T1046/)** — Discovery |
| `host_sweep` | **Horizontal Host Sweep** | Detects one source host probing the same service port across numerous target IPs. | $\ge 50$ distinct hosts in $\le 10$ s | **[T1018](https://attack.mitre.org/techniques/T1018/)** — Discovery |
| `syn_burst` | **SYN Flood / Burst** | Flags abnormal rates of TCP SYN packets lacking legitimate 3-way handshakes. | $\ge 100$ SYNs/sec | **[T1498](https://attack.mitre.org/techniques/T1498/)** — Impact (DoS) |
| `suspicious_flags`| **Stealth Flag Probes** | Identifies illegal or anomalous TCP flag combos: `NULL` (no flags), `XMAS` (FIN+PSH+URG), `FIN-only`. | Any matching packet | **[T1046](https://attack.mitre.org/techniques/T1046/)** — Discovery |
| `cleartext` | **Unencrypted Protocols**| Warns when sensitive credentials/sessions are transmitted unencrypted (Telnet:23, FTP:21, POP3:110, IMAP:143). | Any observed packet | **POLICY** — Credential Risk |
| `icmp_flood` | **ICMP Echo Flood** | Detects high-volume ICMP/ICMPv6 echo request bursts aimed at bandwidth or CPU exhaustion. | $\ge 80$ packets/sec | **[T1498](https://attack.mitre.org/techniques/T1498/)** — Impact (DoS) |

---

## 🏗️ Architecture & Data Flow

```text
  +-------------------------------------------------------------------------+
  |                   Traffic Capture (.pcap / .pcapng)                     |
  +-------------------------------------------------------------------------+
                                       │
                                       ▼
  +-------------------------------------------------------------------------+
  |              Streaming Packet Reader & Normalizer (Scapy)               |
  |             (Extracts Timestamps, IP Endpoints, TCP/UDP/ICMP)           |
  +-------------------------------------------------------------------------+
                                       │
                                       ▼
  +-------------------------------------------------------------------------+
  |               Stateful Sliding-Window Engine (rules.yaml)               |
  |     - Port / Host Window Trackers   - TCP Flag Analyzer                 |
  |     - Volumetric Rate Trackers      - Protocol Policy Filter            |
  +-------------------------------------------------------------------------+
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
  +-----------------------------------+ +-----------------------------------+
  |  Forensic PCAP Evidence Extractor | |      Database Ingestion Layer     |
  |  (Carves offending packets into   | |  (XAMPP MariaDB or SQLite auto-   |
  |   standalone .pcap snippets)      | |   fallback with RBAC & Audit Log) |
  +-----------------------------------+ +-----------------------------------+
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       ▼
  +-------------------------------------------------------------------------+
  |                           Presentation & Export                         |
  |   • Flask Web Dashboard (Triage, Stats, Filter, User Mgmt)              |
  |   • Executive & Technical PDF Reports (ReportLab)                       |
  |   • CSV Exports & Email Notifications (SMTP)                            |
  |   • Offline CLI Runner (sysadmin terminal workflow)                     |
  +-------------------------------------------------------------------------+
```

---

## 👥 Role-Based Access Control (RBAC)

BantayNet enforces tiered permissions across all web routes and management actions:

| Role | Access & Capabilities | Default Username | Default Password |
|---|---|---|---|
| **`admin`** | Full administrative rights: user management (add/role/delete), rule configuration adjustments, database maintenance, alert status triage, PDF/CSV exports, PCAP upload, and forensic downloads. | `admin` | `admin123!` |
| **`analyst`** | Operations and triage: PCAP upload and analysis, alert status updates (Under Review / Resolved / False Positive), forensic PCAP downloads, and CSV/PDF report exports. | `analyst` | `analyst123!` |
| **`viewer`** | Read-only executive access: view dashboard metric counters, read alert details, and view summary dashboards. | `viewer` | `viewer123!` |

> [!TIP]
> Initial passwords can be customized before first run via environment variables: `BANTAYNET_ADMIN_PASSWORD`, `BANTAYNET_ANALYST_PASSWORD`, and `BANTAYNET_VIEWER_PASSWORD`.

---

## 🚀 Installation & Quickstart

### Prerequisites
- **Python 3.10+** (Tested on Python 3.10, 3.11, 3.12, 3.14)
- **Git**
- *(Optional)* **XAMPP / MariaDB** (if utilizing MySQL; SQLite runs automatically if MySQL is omitted)

---

### Step 1: Clone Repository & Create Virtual Environment

#### On Linux / macOS:
```bash
git clone https://github.com/donylcb/Bantaynet.git
cd Bantaynet

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate
```

#### On Windows (PowerShell / Command Prompt):
```powershell
git clone https://github.com/donylcb/Bantaynet.git
cd Bantaynet

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate
```

---

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

---

### Step 3: Environment Configuration
Copy the sample environment file and configure your local settings:
```bash
cp .env.example .env
```
Key configuration items in [`.env`](file:///home/donylcb/Documents/Code/Bantaynet/.env.example):
- `BANTAYNET_SECRET_KEY`: Random 64-char hex key for session signing.
- `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`: XAMPP / MariaDB connection settings.
- `BANTAYNET_COOKIE_SECURE`: Set to `1` when terminating TLS behind reverse proxies (Nginx / Caddy).

---

### Step 4: Generate Synthetic Test PCAPs
BantayNet includes a synthetic traffic generator for offline verification and lab simulations:
```bash
python -m tests.make_synthetic_pcaps
```
This produces ready-to-analyze captures in `pcaps/`:
- `pcaps/normal.pcap` — Clean benign baseline traffic (0 alerts).
- `pcaps/portscan.pcap` — Fast multi-port TCP SYN scan.
- `pcaps/slowscan.pcap` — Low-and-slow reconnaissance over 200+ seconds.
- `pcaps/hostsweep.pcap` — Subnet sweep targeting SMB (Port 445) across 64 IPs.
- `pcaps/burst.pcap` — High-velocity volumetric SYN flood.
- `pcaps/suspicious.pcap` — Stealth scans (NULL/XMAS/FIN), unencrypted Telnet/FTP sessions, and ICMP ping floods.

---

## 💻 Usage Guide

### 1. Web Dashboard (Interactive Mode)

#### Development Server:
```bash
python -m dashboard.app
```

#### Production Deployment (Waitress WSGI):
```bash
python wsgi.py
```
Open **http://127.0.0.1:5000** in your web browser.

#### Dashboard Features:
1. **Login:** Log in with default credentials (`admin` / `admin123!`).
2. **Real-time Incident Counter:** Visual counters for Total, High, Medium, and Low severity threats.
3. **Drag & Drop Upload:** Upload captures (`.pcap`, `.pcapng` up to 50 MB) for instantaneous background parsing.
4. **Interactive Filters:** Query by Rule, Severity, Source IP, or text keywords.
5. **Incident Workflow:** Triage alerts through statuses: `Open`, `Under Review`, `Resolved`, `False Positive`.
6. **Forensic Snippet Download:** Download an isolated `.pcap` containing the exact packets triggering each alert.
7. **Export Reports:**
   - **CSV Export:** Download full incident spreadsheets with one click.
   - **Executive Summary PDF:** High-level executive presentation PDF with graphs and severity breakdown.
   - **Technical Dossier PDF:** In-depth per-incident forensic report with packet metadata, timestamps, and MITRE mapping.
8. **User Administration (`/users`):** Add operators, modify RBAC roles, and deactivate accounts.
9. **Audit Trail (`/audit`):** Log of all operator triage actions and logins.

---

### 2. Command Line Interface (CLI Mode)

Analyze captures directly from your terminal or scheduled cron jobs:

```bash
# 1. Analyze a specific capture file
python -m src.main --pcap pcaps/portscan.pcap

# 2. Analyze capture and export detected alerts to CSV
python -m src.main --pcap pcaps/hostsweep.pcap --export reports/sweep_alerts.csv

# 3. Export all historical alerts currently in database to CSV
python -m src.main --export reports/all_alerts.csv

# 4. Clear all stored alerts from database (Admin action)
python -m src.main --clear-db
```

---

## 🗄️ Database Architecture & Fallback Logic

BantayNet implements a fault-tolerant dual-database architecture:

```text
               ┌───────────────────────────────┐
               │    BantayNet DB Initializer    │
               └───────────────┬───────────────┘
                               │
               Is MySQL / MariaDB reachable?
                               │
                ┌──────────────┴──────────────┐
               YES                            NO
                ▼                             ▼
   ┌─────────────────────────┐   ┌─────────────────────────┐
   │ Connect to XAMPP MySQL  │   │ Fallback to SQLite      │
   │ (Auto-create Schema &   │   │ (Zero setup; creates    │
   │  Tables in MariaDB)     │   │  local 'bantaynet.db')  │
   └─────────────────────────┘   └─────────────────────────┘
```

You can toggle or force specific database engines directly in [`rules/rules.yaml`](file:///home/donylcb/Documents/Code/Bantaynet/rules/rules.yaml):
```yaml
database:
  engine: "mysql"    # Options: "mysql" or "sqlite"
  host: "127.0.0.1"
  port: 3306
  user: "root"
  password: ""
  name: "bantaynet_db"
  sqlite_path: "bantaynet.db"
```

---

## 🧪 Testing & Verification

BantayNet includes a comprehensive automated test suite with synthetic PCAP verification:

```bash
# Run complete test suite
pytest -v

# Run with test coverage report
pytest --tb=short
```

### Covered Test Dimensions:
- Sliding-window rule triggers and boundary thresholds.
- Low-and-slow time window aging.
- TCP flag parsing edge cases (illegal flag bit combinations).
- Database migration, schema validation, and automatic SQLite fallback.
- User authentication, session expiration, and RBAC permission guards.
- Forensic evidence snippet carving and byte validation.
- PDF and CSV export generation.

---

## 📁 Project Directory Structure

```text
BantayNet/
├── dashboard/               # Flask Web Interface
│   ├── app.py               # Route handlers, authentication, upload & triage logic
│   ├── static/              # CSS stylesheets, frontend assets & icons
│   └── templates/           # Jinja2 templates (dashboard, alerts, users, audit)
├── evidence/                # Generated forensic evidence snippets (.pcap) per alert
├── pcaps/                   # Sample and uploaded network capture files
├── reports/                 # Output directory for exported CSV & PDF reports
├── rules/
│   └── rules.yaml           # Central detection rules, thresholds & database configuration
├── src/                     # Core Detection & Forensics Engine
│   ├── alerts.py            # Alert dataclasses & incident representations
│   ├── analyze.py           # Pipeline coordinating parser, detector, and storage
│   ├── config.py            # YAML configuration parser & validation
│   ├── db.py                # Dual MySQL / SQLite persistence, RBAC & user management
│   ├── detector.py          # 7 stateful sliding-window detection algorithms
│   ├── evidence.py          # Mini-PCAP forensic snippet extraction
│   ├── export.py            # CSV incident report generator
│   ├── main.py              # CLI entrypoint for terminal triage
│   ├── mitre.py             # MITRE ATT&CK technique mapping & tactic metadata
│   ├── notifier.py          # Email/SMTP notification dispatcher
│   ├── parser.py            # Streaming Scapy packet reader & normalizer
│   ├── report_pdf.py        # Enterprise PDF report generator (ReportLab)
│   ├── security.py          # Password hashing, token validation & session security
│   └── store.py             # Alert persistence helper
├── tests/                   # Automated pytest suite & synthetic packet generators
│   └── make_synthetic_pcaps.py # Synthetic PCAP generator for reproducible testing
├── .env.example             # Template for production security & database credentials
├── pytest.ini               # Pytest configuration settings
├── requirements.txt         # Project dependencies
├── wsgi.py                  # Production WSGI entrypoint (Waitress / Gunicorn)
└── README.md                # Project documentation & reference manual
```

---

## 🔒 Security & Usage Policy

BantayNet is engineered strictly for defensive analysis and educational purposes:
1. **Passive Only:** Analyzes recorded packet captures (`.pcap`, `.pcapng`). Does not generate unsolicited network traffic.
2. **Detect & Alert:** Flags security anomalies for human review without executing active network responses or blocking actions.
3. **Data Privacy:** Sensitive payloads in forensic snippets are preserved strictly as isolated packet evidence for authorized investigator review.

---

## 👤 Author & Academic Attribution

- **Author / Proponent:** Donyl Cyprus R. Basio
- **Course / Subject:** System Administration and Maintenance – IT23/L (Course Code: 3493)
- **Schedule:** 7:30 PM – 9:30 PM
- **Institution:** IT Services / College of Information Technology
