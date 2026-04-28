# ZeroGuardian XDR

> **AI-Driven Behavioral Detection Framework for Zero-Day Threat Indicators in Network Environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%20%7C%20Windows-orange.svg)]()

ZeroGuardian XDR is an open-source, AI-driven Extended Detection and Response platform that monitors network activity, detects behavioral anomalies using a trained autoencoder, and provides centralized threat visualization through a professional SOC-style dashboard.

---

## Screenshots

| Dashboard | MITRE ATT&CK | Threat Feeds |
|---|---|---|
| Real-time packet monitoring | 87% ATT&CK coverage | 22,161 live indicators |

---

## Key Features

- **AI Behavioral Detection** — Trained autoencoder detects zero-day threats without signatures
- **Live Threat Intelligence** — 9 feeds including AlienVault OTX, Abuse.ch, Feodo Tracker (22,000+ indicators, auto-updated every 6 hours)
- **MITRE ATT&CK Mapping** — 87% framework coverage across 691 techniques and 8 tactics
- **Vulnerability Scanner** — Nmap-powered CVE detection including EternalBlue, BlueKeep, Log4Shell
- **SOC Dashboard** — Professional multi-page interface with real-time data
- **PDF Reports** — Auto-generated professional reports in plain English
- **Telegram + Email Alerts** — Real-time threat notifications
- **Attack Simulator** — 5 zero-day attack scenarios for testing detection

---

## Quick Install (Linux)

```bash
curl -sSL https://raw.githubusercontent.com/Sanjay1911410125/Zeroguardian-XDR/main/install.sh | bash
```

Supports Ubuntu 22.04, 24.04 · Debian 11, 12

---

## Manual Install

```bash
# Clone the repository
git clone https://github.com/Sanjay1911410125/Zeroguardian-XDR.git
cd Zeroguardian-XDR

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask python-nmap scapy tensorflow-cpu requests reportlab numpy

# Setup database
python3 setup_attack_db.py

# Train AI model
python3 train_autoencoder.py

# Configure settings
cp .env.example .env
nano .env  # Add your Telegram token and Email credentials

# Run
sudo venv/bin/python3 -m dashboard.app
```

Open your browser at `http://localhost:5000`

---

## Architecture

```
Packet Capture (Scapy)
        ↓
Feature Extraction
        ↓
AI Anomaly Detection (Autoencoder)
        ↓
Threat Intelligence (9 Live Feeds)
        ↓
Risk Scoring Engine
        ↓
Alert Delivery (Telegram + Email + Dashboard)
```

---

## Threat Intelligence Feeds

| Feed | Indicators | Type |
|---|---|---|
| AlienVault OTX | 731 | IPs, domains, hashes |
| Abuse.ch MalwareBazaar | Live | Malware C2 servers |
| Feodo Tracker | 5 | Banking trojan IPs |
| URLhaus | 2,333 | Malware domains |
| Blocklist.de | 20,296 | Attacker IPs |
| ThreatFox | Live | IOCs |
| NVD CVEs | 100+ | Critical CVEs |
| MITRE ATT&CK | 691 | Techniques |
| EmergingThreats | 356 | Compromised hosts |

---

## Project Structure

```
ZeroGuardian-XDR/
├── core/                   # Core detection modules
│   ├── orchestrator.py     # Background worker
│   ├── ai_detector.py      # Autoencoder anomaly detection
│   ├── threat_feeds.py     # Live threat intelligence
│   ├── threat_intel.py     # Signature matching
│   ├── vuln_scanner.py     # Vulnerability scanner
│   ├── device_discovery.py # Network device discovery
│   └── alerts.py           # Telegram + Email alerts
├── dashboard/              # Flask web application
│   ├── app.py              # Main Flask app
│   ├── templates/          # HTML templates
│   └── static/             # CSS + JavaScript
├── simulator/              # Zero-day attack simulator
│   └── simulate.py         # 5 attack scenarios
├── models/                 # Trained AI models
├── data/                   # Training data
├── train_autoencoder.py    # AI model training script
└── setup_attack_db.py      # Database setup
```

---

## Requirements

- Ubuntu 22.04/24.04 or Windows 10/11
- Python 3.10+
- Nmap
- 2GB RAM minimum
- Root/Administrator privileges (for packet capture)

---

## Research

This project was developed as a final-year research project:

**Title:** ZeroGuardian XDR: An AI-Driven Behavioral Detection Framework for Zero-Day Threat Indicators in Network Environments

**Institution:** Department of Computer Science and Engineering

**Year:** 2025–2026

---

## License

MIT License — free to use, modify, and distribute.

---

## Contact

- **GitHub:** [Sanjay1911410125](https://github.com/Sanjay1911410125)
- **Email:** sanjaymaheswaran1911@gmail.com
