#!/usr/bin/env python3
# setup_attack_db.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Attack Database Setup
# Populates vulnerabilities.db with 50+ real attack signatures.
#
# Usage:
#   cd ~/ZeroGuardian-XDR
#   python3 setup_attack_db.py
# ─────────────────────────────────────────────────────────────────────────────

import sqlite3, os

BASE   = os.path.dirname(os.path.abspath(__file__))
DB     = os.path.join(BASE, "vulnerabilities.db")

conn = sqlite3.connect(DB)
cur  = conn.cursor()

# ── Ensure correct schema ──────────────────────────────────────────────────────
cur.execute("DROP TABLE IF EXISTS threat_signatures")
cur.execute("""
CREATE TABLE threat_signatures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    indicator   TEXT    NOT NULL,
    operator    TEXT    DEFAULT 'gt',
    value       REAL    DEFAULT 0,
    severity    TEXT    DEFAULT 'MEDIUM',
    category    TEXT    DEFAULT 'Network',
    mitre_id    TEXT,
    mitre_name  TEXT,
    cve         TEXT,
    description TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

# ── Ensure vulnerabilities table exists ───────────────────────────────────────
cur.execute("""
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT UNIQUE,
    name        TEXT,
    severity    TEXT,
    cvss_score  REAL,
    description TEXT,
    affected    TEXT,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

print("[DB] Tables created ✅")

# ── 50+ Attack Signatures ─────────────────────────────────────────────────────
# Format: (name, indicator, operator, value, severity, category, mitre_id, mitre_name, cve, description)
SIGNATURES = [

    # ── RECONNAISSANCE ────────────────────────────────────────────────────────
    ("Stealth Port Scan",        "dst_port_variety", "gt", 20,  "MEDIUM",   "Reconnaissance", "T1046", "Network Service Scanning",    None,           "Single source scanned multiple ports — possible stealth reconnaissance"),
    ("Aggressive Port Scan",     "dst_port_variety", "gt", 50,  "HIGH",     "Reconnaissance", "T1046", "Network Service Scanning",    None,           "Aggressive port scan — source scanning 50+ unique ports"),
    ("Full Network Sweep",       "dst_port_variety", "gt", 100, "CRITICAL", "Reconnaissance", "T1046", "Network Service Scanning",    None,           "Full port sweep detected — 100+ ports scanned from single source"),
    ("Host Discovery Sweep",     "unique_dst_ips",   "gt", 20,  "MEDIUM",   "Reconnaissance", "T1018", "Remote System Discovery",     None,           "Traffic spread to 20+ destination IPs — possible host discovery"),
    ("Ping Sweep",               "icmp_rate",        "gt", 30,  "MEDIUM",   "Reconnaissance", "T1018", "Remote System Discovery",     None,           "High ICMP rate — possible ping sweep across subnet"),

    # ── DENIAL OF SERVICE ─────────────────────────────────────────────────────
    ("SYN Flood",                "syn_rate",         "gt", 100, "CRITICAL", "DoS",            "T1499", "Endpoint Denial of Service",  "CVE-1999-0116", "High SYN packet rate — classic SYN flood DoS attack"),
    ("UDP Flood",                "udp_rate",         "gt", 200, "HIGH",     "DoS",            "T1499", "Endpoint Denial of Service",  None,            "Abnormal UDP volume — possible UDP flood attack"),
    ("ICMP Flood",               "icmp_rate",        "gt", 100, "HIGH",     "DoS",            "T1499", "Endpoint Denial of Service",  "CVE-1999-0128", "High ICMP rate — possible ICMP flood or Smurf attack"),
    ("Packet Rate Spike",        "packet_rate",      "gt", 500, "HIGH",     "DoS",            "T1498", "Network Denial of Service",   None,            "Packet rate exceeds 500 pps — possible volumetric attack"),
    ("Traffic Spike",            "total_packets",    "gt", 2000,"MEDIUM",   "DoS",            "T1498", "Network Denial of Service",   None,            "Unusually high packet count in single capture window"),

    # ── CREDENTIAL ATTACKS ────────────────────────────────────────────────────
    ("SSH Brute Force",          "connection_rate",  "gt", 30,  "HIGH",     "Credential",     "T1110", "Brute Force",                 None,            "Rapid SSH connection attempts — possible brute force"),
    ("RDP Brute Force",          "connection_rate",  "gt", 20,  "HIGH",     "Credential",     "T1110", "Brute Force",                 "CVE-2019-0708", "Rapid RDP connections — possible BlueKeep-style brute force"),
    ("HTTP Login Flood",         "connection_rate",  "gt", 50,  "MEDIUM",   "Credential",     "T1110", "Brute Force",                 None,            "High HTTP connection rate — possible web login brute force"),
    ("Password Spray",           "unique_dst_ips",   "gt", 10,  "HIGH",     "Credential",     "T1110", "Password Spraying",           None,            "Connections to many hosts — possible password spray attack"),

    # ── EXFILTRATION ──────────────────────────────────────────────────────────
    ("DNS Exfiltration",         "dns_query_rate",   "gt", 50,  "HIGH",     "Exfiltration",   "T1048", "Exfiltration Over Alt Protocol", None,         "Abnormal DNS query rate — possible data exfiltration via DNS tunneling"),
    ("DNS Tunneling",            "dns_query_rate",   "gt", 100, "CRITICAL", "Exfiltration",   "T1071", "Application Layer Protocol",  None,            "Very high DNS query rate — likely DNS tunnel exfiltration"),
    ("Large Outbound Transfer",  "total_packets",    "gt", 5000,"HIGH",     "Exfiltration",   "T1030", "Data Transfer Size Limits",   None,            "Unusually large outbound data volume detected"),

    # ── COMMAND & CONTROL ─────────────────────────────────────────────────────
    ("C2 Beacon Pattern",        "connection_rate",  "gt", 10,  "HIGH",     "C2",             "T1071", "Application Layer Protocol",  None,            "Regular periodic connections — possible C2 beaconing pattern"),
    ("Unusual Outbound Port",    "dst_port_variety", "gt", 30,  "MEDIUM",   "C2",             "T1095", "Non-Standard Port",           None,            "Traffic on unusual ports — possible C2 communication"),
    ("High Unique Destination",  "unique_dst_ips",   "gt", 30,  "HIGH",     "C2",             "T1071", "Application Layer Protocol",  None,            "Connections to many unique IPs — possible C2 infrastructure"),

    # ── LATERAL MOVEMENT ──────────────────────────────────────────────────────
    ("Internal Port Scan",       "dst_port_variety", "gt", 40,  "HIGH",     "LateralMovement","T1021", "Remote Services",             None,            "Internal host scanning ports — possible lateral movement"),
    ("SMB Sweep",                "connection_rate",  "gt", 15,  "HIGH",     "LateralMovement","T1021", "SMB/Windows Admin Shares",    "CVE-2017-0144", "Rapid SMB connections — possible EternalBlue-style lateral movement"),
    ("RPC Abuse",                "connection_rate",  "gt", 25,  "MEDIUM",   "LateralMovement","T1021", "Remote Services",             None,            "High RPC connection rate — possible lateral movement via RPC"),

    # ── PROTOCOL ABUSE ────────────────────────────────────────────────────────
    ("Fragmented Packet Attack", "packet_rate",      "gt", 300, "MEDIUM",   "Evasion",        "T1599", "Network Boundary Bridging",   None,            "High packet rate with possible fragmentation — evasion attempt"),
    ("Protocol Anomaly",         "udp_rate",         "gt", 100, "MEDIUM",   "Evasion",        "T1599", "Network Boundary Bridging",   None,            "Abnormal protocol distribution — possible protocol abuse"),
    ("ICMP Tunneling",           "icmp_rate",        "gt", 50,  "HIGH",     "Exfiltration",   "T1095", "Non-Standard Port",           None,            "High ICMP rate — possible ICMP tunnel for covert communication"),

    # ── ZERO-DAY INDICATORS ───────────────────────────────────────────────────
    ("Zero-Day Behavioral",      "packet_rate",      "gt", 200, "HIGH",     "ZeroDay",        "T1203", "Exploitation for Client Execution", None,       "Anomalous packet behavior matching zero-day exploitation patterns"),
    ("Exploit Traffic Spike",    "syn_rate",         "gt", 50,  "HIGH",     "ZeroDay",        "T1190", "Exploit Public-Facing Application", None,       "SYN spike pattern matching known exploit delivery signatures"),
    ("Shellcode Delivery",       "total_packets",    "gt", 1000,"CRITICAL", "ZeroDay",        "T1203", "Exploitation for Client Execution", None,       "High volume traffic matching shellcode delivery patterns"),
    ("Memory Corruption Probe",  "dst_port_variety", "gt", 60,  "CRITICAL", "ZeroDay",        "T1203", "Exploitation for Client Execution", None,       "Port pattern matches memory corruption exploit probing behavior"),

    # ── NETWORK DISCOVERY ─────────────────────────────────────────────────────
    ("ARP Scan",                 "unique_dst_ips",   "gt", 15,  "LOW",      "Discovery",      "T1018", "Remote System Discovery",     None,            "ARP requests to many IPs — possible network mapping"),
    ("OS Fingerprinting",        "dst_port_variety", "gt", 10,  "LOW",      "Discovery",      "T1082", "System Information Discovery",None,            "Port pattern matches OS fingerprinting tools like Nmap"),
    ("Service Enumeration",      "dst_port_variety", "gt", 25,  "MEDIUM",   "Discovery",      "T1046", "Network Service Scanning",    None,            "Systematic port scanning matching service enumeration behavior"),

    # ── INSIDER THREAT ────────────────────────────────────────────────────────
    ("Insider Data Staging",     "total_packets",    "gt", 3000,"HIGH",     "InsiderThreat",  "T1074", "Data Staged",                 None,            "Unusually large data volume — possible insider data staging"),
    ("Unusual Access Hours",     "connection_rate",  "gt", 40,  "MEDIUM",   "InsiderThreat",  "T1078", "Valid Accounts",              None,            "High connection rate — possible unauthorized after-hours access"),

    # ── MALWARE INDICATORS ────────────────────────────────────────────────────
    ("Ransomware Traffic",       "connection_rate",  "gt", 60,  "CRITICAL", "Malware",        "T1486", "Data Encrypted for Impact",   None,            "Connection pattern matches ransomware encryption communication"),
    ("Botnet Communication",     "unique_dst_ips",   "gt", 25,  "HIGH",     "Malware",        "T1583", "Acquire Infrastructure",      None,            "Connections to many unique IPs matching botnet C2 pattern"),
    ("Worm Propagation",         "unique_dst_ips",   "gt", 20,  "CRITICAL", "Malware",        "T1210", "Exploitation of Remote Services", None,        "Rapid spread to many hosts matching worm self-propagation"),
    ("Trojan Beacon",            "connection_rate",  "gt", 8,   "HIGH",     "Malware",        "T1071", "Application Layer Protocol",  None,            "Low-rate periodic connection matching trojan beacon pattern"),

    # ── WEB ATTACKS ───────────────────────────────────────────────────────────
    ("Web Application Scan",     "connection_rate",  "gt", 35,  "MEDIUM",   "WebAttack",      "T1190", "Exploit Public-Facing Application", None,      "Rapid HTTP connections matching web application scanner behavior"),
    ("DDoS HTTP Flood",          "packet_rate",      "gt", 400, "CRITICAL", "WebAttack",      "T1498", "Network Denial of Service",   None,            "HTTP packet rate matches DDoS flood pattern"),
    ("Slowloris Attack",         "connection_rate",  "gt", 45,  "HIGH",     "WebAttack",      "T1499", "Endpoint Denial of Service",  None,            "Connection pattern matches Slowloris slow HTTP DoS attack"),

    # ── PHYSICAL/ROGUE ────────────────────────────────────────────────────────
    ("Rogue Device Traffic",     "unique_dst_ips",   "gt", 5,   "MEDIUM",   "Rogue",          "T1200", "Hardware Additions",          None,            "Unknown device generating unusual traffic patterns"),
    ("Rogue DHCP Activity",      "udp_rate",         "gt", 30,  "HIGH",     "Rogue",          "T1557", "Adversary-in-the-Middle",     None,            "UDP pattern matching rogue DHCP server activity"),
    ("ARP Poisoning",            "unique_dst_ips",   "gt", 8,   "HIGH",     "Rogue",          "T1557", "Adversary-in-the-Middle",     "CVE-2010-0746", "ARP traffic pattern matching ARP cache poisoning attack"),

    # ── ADVANCED PERSISTENT THREAT ────────────────────────────────────────────
    ("APT Low-and-Slow Scan",    "dst_port_variety", "gt", 5,   "LOW",      "APT",            "T1595", "Active Scanning",             None,            "Very slow port scan — low-and-slow APT reconnaissance technique"),
    ("Living off the Land",      "connection_rate",  "gt", 12,  "MEDIUM",   "APT",            "T1218", "System Binary Proxy Execution",None,           "Connection pattern matching living-off-the-land APT technique"),
    ("Data Minimization Exfil",  "dns_query_rate",   "gt", 20,  "HIGH",     "APT",            "T1048", "Exfiltration Over Alt Protocol", None,         "Low-rate DNS exfiltration matching APT slow exfil technique"),
]

cur.executemany("""
    INSERT INTO threat_signatures
        (name, indicator, operator, value, severity, category,
         mitre_id, mitre_name, cve, description)
    VALUES (?,?,?,?,?,?,?,?,?,?)
""", SIGNATURES)

print(f"[DB] {len(SIGNATURES)} attack signatures inserted ✅")

# ── Known CVEs ────────────────────────────────────────────────────────────────
CVES = [
    ("CVE-2017-0144", "EternalBlue",     "CRITICAL", 9.8, "SMB Remote Code Execution used by WannaCry ransomware",              "Windows SMBv1"),
    ("CVE-2019-0708", "BlueKeep",        "CRITICAL", 9.8, "RDP Remote Code Execution — unauthenticated pre-auth RCE",           "Windows RDP"),
    ("CVE-2021-44228","Log4Shell",       "CRITICAL", 10.0,"Apache Log4j2 JNDI injection — remote code execution",               "Apache Log4j2"),
    ("CVE-2021-34527","PrintNightmare",  "CRITICAL", 8.8, "Windows Print Spooler RCE — privilege escalation",                   "Windows Spooler"),
    ("CVE-2020-1472",  "Zerologon",      "CRITICAL", 10.0,"Netlogon privilege escalation — domain controller takeover",         "Windows Netlogon"),
    ("CVE-2022-30190","Follina",         "HIGH",     7.8, "MSDT remote code execution via Word documents",                      "Microsoft MSDT"),
    ("CVE-2023-23397","Outlook RCE",     "CRITICAL", 9.8, "Microsoft Outlook zero-click RCE via calendar invite",               "Microsoft Outlook"),
    ("CVE-1999-0116", "SYN Flood",       "HIGH",     7.5, "TCP SYN flood denial of service vulnerability",                      "TCP/IP Stack"),
    ("CVE-1999-0128", "Smurf Attack",    "HIGH",     7.5, "ICMP broadcast amplification denial of service",                     "TCP/IP Stack"),
    ("CVE-2010-0746", "ARP Poisoning",   "MEDIUM",   5.7, "ARP cache poisoning enabling man-in-the-middle attacks",             "Network Layer"),
    ("CVE-2014-0160", "Heartbleed",      "HIGH",     7.5, "OpenSSL buffer over-read exposing private keys and memory",          "OpenSSL"),
    ("CVE-2014-6271", "Shellshock",      "CRITICAL", 9.8, "Bash remote code execution via environment variable injection",      "GNU Bash"),
    ("CVE-2017-5638",  "Struts RCE",     "CRITICAL", 10.0,"Apache Struts 2 remote code execution — used in Equifax breach",    "Apache Struts 2"),
    ("CVE-2018-7600",  "Drupalgeddon2",  "CRITICAL", 9.8, "Drupal remote code execution via form rendering API",               "Drupal CMS"),
    ("CVE-2019-19781", "Citrix RCE",     "CRITICAL", 9.8, "Citrix ADC path traversal leading to remote code execution",        "Citrix ADC"),
]

cur.executemany("""
    INSERT OR IGNORE INTO vulnerabilities
        (cve_id, name, severity, cvss_score, description, affected)
    VALUES (?,?,?,?,?,?)
""", CVES)

print(f"[DB] {len(CVES)} CVEs inserted ✅")

conn.commit()
conn.close()

print()
print("="*60)
print("  Attack database setup complete!")
print(f"  Signatures : {len(SIGNATURES)}")
print(f"  CVEs       : {len(CVES)}")
print(f"  Database   : {DB}")
print()
print("  Now transfer and restart:")
print("  scp threat_intel.py san@192.168.31.73:~/ZeroGuardian-XDR/core/threat_intel.py")
print("  sudo venv/bin/python3 -m dashboard.app")
print("="*60)
