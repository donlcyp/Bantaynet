# 🛡️ BantayNet: Suspicious Activity Detection & Forensic PCAP Analysis

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Dashboard](https://img.shields.io/badge/Dashboard-Flask%203.x-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Packet Engine](https://img.shields.io/badge/Engine-Scapy-red.svg?logo=wireshark&logoColor=white)](https://scapy.net/)
[![MITRE ATT&CK](https://img.shields.io/badge/Security-MITRE%20ATT%26CK%20Mapped-orange.svg)](https://attack.mitre.org/)
[![Database](https://img.shields.io/badge/Storage-MySQL%20%7C%20SQLite%20Fallback-00758F.svg?logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Tests](https://img.shields.io/badge/Tests-pytest%20Passing-brightgreen.svg?logo=pytest&logoColor=white)](https://pytest.org/)

> **⚠️ Lab Notice:** For authorized PCAP analysis and lab traffic only. BantayNet operates strictly as **detect-and-alert** — it does not inject packets, scan targets, block traffic, or alter network devices.

---

## 📋 Project Information

| Detail | Description |
|---|---|
| **Author / Proponent** | **Donyl Cyprus R. Basio** |
| **Subject** | System Administration and Maintenance – IT23/L |
| **Course Code** | 3493 |
| **Schedule** | 7:30 PM – 9:30 PM |
| **Project Title** | Project #4 — IntrusionAlert: Suspicious Activity Detection System |
| **Company / Institution** | IT Services |

---

## 📖 Overview

**BantayNet** is a rule-based network intrusion detection and forensics system built for IT administrators and security analysts. It parses Wireshark captures (`.pcap` / `.pcapng`), correlates anomalies across sliding time windows, and generates actionable security alerts mapped to MITRE ATT&CK techniques.

### Core Features:
- **7 Detection Techniques:** Fast scans, slow scans, host sweeps, SYN floods, stealth flags, cleartext traffic, and ICMP floods.
- **Forensic Evidence Snippets:** Automatically isolates and exports mini-PCAP snippets containing only the offending packets.
- **Executive & Technical PDF Reports:** One-click generation of audit-ready summary and incident dossiers.
- **Dual Database Engine:** Connects to XAMPP MySQL/MariaDB with automatic zero-configuration fallback to SQLite (`bantaynet.db`).
- **Web & CLI Interfaces:** Manage triage via a modern web dashboard or run offline scans directly from the terminal.

---

## 🔑 Default Login Credentials

BantayNet includes built-in role-based access control (RBAC):

| Role | Username | Password | Access Level |
|---|---|---|---|
| **Administrator** | `admin` | `admin123!` | Full control: user management, triage, exports, and rule configuration |
| **Security Analyst** | `analyst` | `analyst123!` | Incident triage, PCAP uploads, evidence downloads, and PDF/CSV exports |
| **Viewer** | `viewer` | `viewer123!` | Read-only access to metrics, alert summaries, and incident lists |

---

## 🎯 Detection Rules & MITRE ATT&CK Mapping

Configured via [`rules/rules.yaml`](file:///home/donylcb/Documents/Code/Bantaynet/rules/rules.yaml):

| Rule | Description | Trigger Threshold | MITRE ATT&CK |
|---|---|---|---|
| **Port Scan** (`port_scan`) | Rapid port probing on a single host | $\ge 50$ distinct ports in $\le 5$ s | **[T1046](https://attack.mitre.org/techniques/T1046/)** (Discovery) |
| **Slow Scan** (`slow_scan`) | Low-and-slow reconnaissance | $\ge 20$ ports across $300$ s | **[T1046](https://attack.mitre.org/techniques/T1046/)** (Discovery) |
| **Host Sweep** (`host_sweep`) | Horizontal probe across multiple hosts | $\ge 50$ target IPs in $\le 10$ s | **[T1018](https://attack.mitre.org/techniques/T1018/)** (Discovery) |
| **SYN Burst** (`syn_burst`) | SYN flood / connection exhaustion | $\ge 100$ SYNs/sec | **[T1498](https://attack.mitre.org/techniques/T1498/)** (DoS) |
| **Suspicious Flags** (`suspicious_flags`) | Stealth scans (`NULL`, `XMAS`, `FIN`) | Any illegal flag combination | **[T1046](https://attack.mitre.org/techniques/T1046/)** (Discovery) |
| **Cleartext Protocol** (`cleartext`) | Insecure services (Telnet:23, FTP:21, POP3:110) | Any observed packet | **Policy Violation** |
| **ICMP Flood** (`icmp_flood`) | Volumetric ping flood | $\ge 80$ packets/sec | **[T1498](https://attack.mitre.org/techniques/T1498/)** (DoS) |

---

## 🚀 Quickstart Guide

### 1. Setup Environment

#### Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Windows (PowerShell / Command Prompt):
```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Environment (Optional)
Copy the template configuration if you want to customize secret keys or database credentials:
```bash
cp .env.example .env
```
*(If MySQL is not installed, BantayNet automatically creates and uses `bantaynet.db` locally without any setup.)*

### 3. Generate Test PCAPs
Create synthetic PCAPs simulating each attack scenario:
```bash
python -m tests.make_synthetic_pcaps
```

---

## 💻 How to Run

### Web Dashboard
Start the dashboard server:
```bash
python -m dashboard.app
```
*Or run via the production WSGI server:*
```bash
python wsgi.py
```
Open **http://127.0.0.1:5000** in your browser and sign in using `admin` / `admin123!`.

#### Dashboard Capabilities:
- **Upload PCAPs:** Drag-and-drop `.pcap` or `.pcapng` files for instant analysis.
- **Incident Triage:** Update alert statuses (`Open`, `Under Review`, `Resolved`, `False Positive`).
- **Forensic Downloads:** Download isolated mini-PCAP evidence files for any alert.
- **Reports:** Generate executive PDF summaries, detailed technical PDF dossiers, or CSV spreadsheets.
- **User Management & Audit:** Manage accounts and review operator activity under `/users` and `/audit`.

---

### Command Line Interface (CLI)
Analyze captures and export alerts directly from the terminal:

```bash
# Analyze a specific PCAP file
python -m src.main --pcap pcaps/portscan.pcap

# Analyze and export results to CSV
python -m src.main --pcap pcaps/hostsweep.pcap --export reports/sweep_alerts.csv

# Export all alerts from the database to CSV
python -m src.main --export reports/all_alerts.csv

# Clear stored alerts (Admin)
python -m src.main --clear-db
```

---

## 🧪 Testing

Execute the automated test suite:
```bash
pytest -v
```
All 97 unit and integration tests verify rule algorithms, thresholds, database operations, RBAC permissions, and evidence carving.
