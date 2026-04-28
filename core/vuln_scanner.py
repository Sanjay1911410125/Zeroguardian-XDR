# core/vuln_scanner.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Network Vulnerability Scanner
# Scans discovered devices for open ports, weak services, and known CVEs.
# Uses Nmap scripts to identify vulnerable software versions.
# Results stored in vulnerabilities.db and shown on dashboard.
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import sqlite3
import json
import os
import re
import time
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "vulnerabilities.db")

# ── CVE knowledge base — port → known vulnerabilities ─────────────────────────
PORT_CVE_MAP = {
    21:   [{"cve": "CVE-2011-2523", "name": "FTP Backdoor",         "severity": "CRITICAL", "cvss": 10.0, "desc": "vsftpd 2.3.4 backdoor allows remote code execution via smiley face username"}],
    22:   [{"cve": "CVE-2023-38408","name": "OpenSSH RCE",          "severity": "CRITICAL", "cvss": 9.8,  "desc": "OpenSSH ssh-agent remote code execution via PKCS#11 provider"}],
    23:   [{"cve": "CVE-2020-15778","name": "Telnet Plaintext",     "severity": "HIGH",     "cvss": 7.8,  "desc": "Telnet transmits credentials in plaintext — trivial to intercept"}],
    25:   [{"cve": "CVE-2020-7247", "name": "SMTP RCE",             "severity": "CRITICAL", "cvss": 10.0, "desc": "OpenSMTPD remote code execution via malformed sender address"}],
    80:   [{"cve": "CVE-2021-41773","name": "Apache Path Traversal","severity": "CRITICAL", "cvss": 9.8,  "desc": "Apache HTTP Server path traversal and remote code execution"}],
    110:  [{"cve": "CVE-2019-10149","name": "Exim RCE",             "severity": "CRITICAL", "cvss": 9.8,  "desc": "Exim mail server remote code execution via malformed recipient address"}],
    135:  [{"cve": "CVE-2003-0352", "name": "MS RPC DCOM",          "severity": "CRITICAL", "cvss": 9.8,  "desc": "Microsoft RPC DCOM buffer overflow — exploited by Blaster worm"}],
    139:  [{"cve": "CVE-2017-0143", "name": "EternalBlue SMB",      "severity": "CRITICAL", "cvss": 9.8,  "desc": "SMBv1 remote code execution — used by WannaCry and NotPetya ransomware"}],
    443:  [{"cve": "CVE-2014-0160", "name": "Heartbleed",           "severity": "HIGH",     "cvss": 7.5,  "desc": "OpenSSL buffer over-read exposes private keys and session tokens"}],
    445:  [{"cve": "CVE-2017-0144", "name": "EternalBlue",          "severity": "CRITICAL", "cvss": 9.8,  "desc": "SMBv1 remote code execution — exploited by WannaCry ransomware worldwide"}],
    512:  [{"cve": "CVE-1999-0651", "name": "rexec Plaintext",      "severity": "HIGH",     "cvss": 7.5,  "desc": "rexec service transmits credentials in plaintext"}],
    513:  [{"cve": "CVE-1999-0651", "name": "rlogin No Auth",       "severity": "HIGH",     "cvss": 7.5,  "desc": "rlogin allows authentication bypass via .rhosts file"}],
    514:  [{"cve": "CVE-1999-0651", "name": "RSH No Auth",          "severity": "HIGH",     "cvss": 7.5,  "desc": "Remote shell service with no authentication requirement"}],
    1433: [{"cve": "CVE-2020-0618", "name": "MSSQL RCE",            "severity": "HIGH",     "cvss": 8.8,  "desc": "Microsoft SQL Server Reporting Services remote code execution"}],
    1723: [{"cve": "CVE-2012-0002", "name": "PPTP RCE",             "severity": "CRITICAL", "cvss": 9.3,  "desc": "Microsoft PPTP VPN server remote code execution via malformed packet"}],
    2049: [{"cve": "CVE-2019-3010", "name": "NFS Privilege Esc",    "severity": "HIGH",     "cvss": 7.8,  "desc": "NFS server local privilege escalation via symlink attack"}],
    3306: [{"cve": "CVE-2016-6662", "name": "MySQL RCE",            "severity": "CRITICAL", "cvss": 9.8,  "desc": "MySQL remote code execution via malicious configuration file injection"}],
    3389: [{"cve": "CVE-2019-0708", "name": "BlueKeep RDP",         "severity": "CRITICAL", "cvss": 9.8,  "desc": "RDP pre-authentication remote code execution — wormable vulnerability"}],
    4848: [{"cve": "CVE-2011-0807", "name": "GlassFish Auth Bypass","severity": "CRITICAL", "cvss": 10.0, "desc": "Oracle GlassFish Server admin console authentication bypass"}],
    5432: [{"cve": "CVE-2019-9193", "name": "PostgreSQL RCE",       "severity": "HIGH",     "cvss": 7.2,  "desc": "PostgreSQL COPY TO/FROM PROGRAM remote code execution as superuser"}],
    5900: [{"cve": "CVE-2015-5239", "name": "VNC Integer Overflow", "severity": "HIGH",     "cvss": 6.5,  "desc": "VNC server integer overflow allows remote denial of service"}],
    6379: [{"cve": "CVE-2022-0543", "name": "Redis RCE",            "severity": "CRITICAL", "cvss": 10.0, "desc": "Redis Lua sandbox escape allows remote code execution"}],
    8080: [{"cve": "CVE-2020-1938", "name": "Ghostcat Tomcat",      "severity": "CRITICAL", "cvss": 9.8,  "desc": "Apache Tomcat AJP connector file inclusion and remote code execution"}],
    8443: [{"cve": "CVE-2021-21985","name": "vCenter RCE",          "severity": "CRITICAL", "cvss": 9.8,  "desc": "VMware vCenter Server remote code execution via Virtual SAN plugin"}],
    9200: [{"cve": "CVE-2015-1427", "name": "Elasticsearch RCE",    "severity": "CRITICAL", "cvss": 9.8,  "desc": "Elasticsearch Groovy sandbox bypass allows remote code execution"}],
    27017:[{"cve": "CVE-2013-2132", "name": "MongoDB No Auth",      "severity": "HIGH",     "cvss": 7.1,  "desc": "MongoDB exposed without authentication — full database access"}],
}

# Dangerous services that should never be open
DANGEROUS_SERVICES = {
    23:   ("Telnet",    "CRITICAL", "Telnet transmits all data including passwords in plaintext"),
    512:  ("rexec",    "HIGH",     "Legacy remote execution service with no encryption"),
    513:  ("rlogin",   "HIGH",     "Legacy remote login with weak authentication"),
    514:  ("RSH",      "HIGH",     "Remote shell with no authentication by default"),
    2323: ("AltTelnet","HIGH",     "Alternative Telnet port — plaintext credentials"),
    69:   ("TFTP",     "MEDIUM",   "Trivial FTP — no authentication, often misconfigured"),
    161:  ("SNMP",     "MEDIUM",   "SNMP v1/v2 uses community strings instead of real auth"),
    6000: ("X11",      "HIGH",     "X11 display server exposed — allows GUI hijacking"),
}


def _ensure_scan_table():
    """Create scan results table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT NOT NULL,
            hostname     TEXT,
            port         INTEGER,
            service      TEXT,
            version      TEXT,
            state        TEXT,
            severity     TEXT,
            cve_id       TEXT,
            cve_name     TEXT,
            description  TEXT,
            cvss_score   REAL,
            scan_time    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_summary (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            devices_scanned INTEGER DEFAULT 0,
            total_vulns     INTEGER DEFAULT 0,
            critical_count  INTEGER DEFAULT 0,
            high_count      INTEGER DEFAULT 0,
            medium_count    INTEGER DEFAULT 0,
            low_count       INTEGER DEFAULT 0,
            status          TEXT DEFAULT 'running'
        )
    """)
    conn.commit()
    conn.close()


def _run_nmap(ip: str) -> dict:
    """
    Run Nmap service/version scan on a single IP.
    Returns dict of {port: {service, version, state}}.
    """
    result = {}
    try:
        cmd = [
            "nmap", "-sV", "-sS", "--open",
            "-p", "21,22,23,25,53,80,110,135,139,443,445,512,513,514,"
                  "1433,1723,2049,3306,3389,4848,5432,5900,6379,"
                  "8080,8443,9200,27017",
            "--host-timeout", "15s",
            "-T4", "--version-intensity", "5",
            ip
        ]
        out = subprocess.check_output(cmd, text=True,
                                      stderr=subprocess.DEVNULL,
                                      timeout=30)

        for line in out.splitlines():
            # Match lines like: 22/tcp   open  ssh     OpenSSH 8.9p1
            m = re.match(
                r"(\d+)/\w+\s+(open)\s+(\S+)\s*(.*)", line
            )
            if m:
                port    = int(m.group(1))
                state   = m.group(2)
                service = m.group(3)
                version = m.group(4).strip()
                result[port] = {
                    "service": service,
                    "version": version,
                    "state":   state,
                }
    except subprocess.TimeoutExpired:
        print(f"[VulnScan] Nmap timeout for {ip}")
    except Exception as e:
        print(f"[VulnScan] Nmap error for {ip}: {e}")
    return result


def _check_default_credentials(ip: str, port: int, service: str) -> list:
    """Check for common default credential usage."""
    issues = []
    service = service.lower()

    # SSH default credential check (connection attempt only — no actual login)
    if port == 22 and "ssh" in service:
        issues.append({
            "type":     "Default Credentials Risk",
            "severity": "MEDIUM",
            "details":  f"SSH port open on {ip} — verify no default credentials (root/root, admin/admin)",
        })

    # Telnet — always flag
    if port == 23:
        issues.append({
            "type":     "Insecure Protocol",
            "severity": "CRITICAL",
            "details":  f"Telnet open on {ip}:{port} — disable immediately and use SSH instead",
        })

    # FTP anonymous check
    if port == 21:
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=3)
            ftp.connect(ip, 21)
            ftp.login("anonymous", "anonymous@test.com")
            ftp.quit()
            issues.append({
                "type":     "Anonymous FTP Access",
                "severity": "HIGH",
                "details":  f"FTP on {ip}:21 allows anonymous login — data exposure risk",
            })
        except Exception:
            pass   # anonymous login failed — that's fine

    return issues


def scan_device(ip: str) -> list:
    """
    Scan a single device for vulnerabilities.
    Returns list of vulnerability dicts.
    """
    vulns = []
    print(f"[VulnScan] Scanning {ip} ...")

    open_ports = _run_nmap(ip)

    for port, info in open_ports.items():
        service = info.get("service", "unknown")
        version = info.get("version", "")

        # Check against CVE map
        if port in PORT_CVE_MAP:
            for cve in PORT_CVE_MAP[port]:
                vulns.append({
                    "ip":          ip,
                    "port":        port,
                    "service":     service,
                    "version":     version,
                    "severity":    cve["severity"],
                    "cve_id":      cve["cve"],
                    "cve_name":    cve["name"],
                    "description": cve["desc"],
                    "cvss_score":  cve["cvss"],
                    "type":        "CVE Match",
                })

        # Check dangerous services
        if port in DANGEROUS_SERVICES:
            svc_name, sev, desc = DANGEROUS_SERVICES[port]
            vulns.append({
                "ip":          ip,
                "port":        port,
                "service":     svc_name,
                "version":     version,
                "severity":    sev,
                "cve_id":      None,
                "cve_name":    f"Dangerous Service: {svc_name}",
                "description": desc,
                "cvss_score":  None,
                "type":        "Dangerous Service",
            })

        # Default credential checks
        cred_issues = _check_default_credentials(ip, port, service)
        for issue in cred_issues:
            vulns.append({
                "ip":          ip,
                "port":        port,
                "service":     service,
                "version":     version,
                "severity":    issue["severity"],
                "cve_id":      None,
                "cve_name":    issue["type"],
                "description": issue["details"],
                "cvss_score":  None,
                "type":        "Misconfiguration",
            })

    print(f"[VulnScan] {ip} — {len(open_ports)} open ports, {len(vulns)} vulnerabilities")
    return vulns


def save_results(vulns: list, summary_id: int):
    """Save scan results to database."""
    if not vulns:
        return
    conn = sqlite3.connect(DB_PATH)
    conn.executemany("""
        INSERT INTO scan_results
            (ip, port, service, version, severity,
             cve_id, cve_name, description, cvss_score)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, [
        (v["ip"], v["port"], v["service"], v["version"], v["severity"],
         v["cve_id"], v["cve_name"], v["description"], v.get("cvss_score"))
        for v in vulns
    ])
    conn.commit()
    conn.close()


def run_full_scan(devices: list) -> dict:
    """
    Run vulnerability scan across all discovered devices.
    Returns summary dict.
    """
    _ensure_scan_table()

    # Clear old results
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scan_results")

    # Create scan summary record
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scan_summary (devices_scanned, status)
        VALUES (?, 'running')
    """, (len(devices),))
    summary_id = cur.lastrowid
    conn.commit()
    conn.close()

    all_vulns   = []
    scan_ips    = [d["ip"] for d in devices
                   if not d["ip"].startswith("fe80")   # skip IPv6 link-local
                   and ":" not in d["ip"]]              # skip IPv6 entirely

    for ip in scan_ips:
        try:
            vulns = scan_device(ip)
            all_vulns.extend(vulns)
            save_results(vulns, summary_id)
        except Exception as e:
            print(f"[VulnScan] Error scanning {ip}: {e}")

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in all_vulns:
        sev = (v.get("severity") or "LOW").upper()
        counts[sev] = counts.get(sev, 0) + 1

    # Update summary
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        UPDATE scan_summary
        SET total_vulns=?, critical_count=?, high_count=?,
            medium_count=?, low_count=?, status='complete'
        WHERE id=?
    """, (len(all_vulns), counts["CRITICAL"], counts["HIGH"],
          counts["MEDIUM"], counts["LOW"], summary_id))
    conn.commit()
    conn.close()

    summary = {
        "devices_scanned": len(scan_ips),
        "total_vulns":     len(all_vulns),
        "critical":        counts["CRITICAL"],
        "high":            counts["HIGH"],
        "medium":          counts["MEDIUM"],
        "low":             counts["LOW"],
        "vulns":           all_vulns,
        "scan_time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Send Telegram alert if critical vulns found
    if counts["CRITICAL"] > 0:
        try:
            from core.alerts import send_threat_alert
            send_threat_alert(
                title=f"Vulnerability Scan — {counts['CRITICAL']} CRITICAL findings",
                details=(f"Scanned {len(scan_ips)} devices. "
                         f"Found {len(all_vulns)} vulnerabilities: "
                         f"{counts['CRITICAL']} Critical, {counts['HIGH']} High"),
                severity="CRITICAL",
                ip="network-wide",
            )
        except Exception as e:
            print(f"[VulnScan] Alert error: {e}")

    print(f"[VulnScan] Scan complete — {len(all_vulns)} vulnerabilities found across {len(scan_ips)} devices")
    return summary


def get_latest_results() -> list:
    """Get most recent scan results from database."""
    _ensure_scan_table()
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("""
            SELECT ip, port, service, version, severity,
                   cve_id, cve_name, description, cvss_score, scan_time
            FROM scan_results
            ORDER BY
                CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    ELSE 4
                END, cvss_score DESC
        """)
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "ip":          r[0],
                "port":        r[1],
                "service":     r[2],
                "version":     r[3],
                "severity":    r[4],
                "cve_id":      r[5],
                "cve_name":    r[6],
                "description": r[7],
                "cvss_score":  r[8],
                "scan_time":   r[9],
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[VulnScan] get_latest_results error: {e}")
        return []


def get_scan_summary() -> dict:
    """Get the latest scan summary."""
    _ensure_scan_table()
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("""
            SELECT devices_scanned, total_vulns, critical_count,
                   high_count, medium_count, low_count, status, scan_time
            FROM scan_summary
            ORDER BY id DESC LIMIT 1
        """)
        r = cur.fetchone()
        conn.close()
        if r:
            return {
                "devices_scanned": r[0],
                "total_vulns":     r[1],
                "critical":        r[2],
                "high":            r[3],
                "medium":          r[4],
                "low":             r[5],
                "status":          r[6],
                "scan_time":       r[7],
            }
    except Exception as e:
        print(f"[VulnScan] get_scan_summary error: {e}")
    return {}


# ── Background scan state ──────────────────────────────────────────────────────
_scan_running  = False
_scan_result   = {}


def start_background_scan(devices: list):
    """Start a vulnerability scan in a background thread."""
    global _scan_running, _scan_result
    if _scan_running:
        return {"error": "Scan already running"}
    _scan_running = True

    def _run():
        global _scan_running, _scan_result
        try:
            _scan_result = run_full_scan(devices)
        except Exception as e:
            _scan_result = {"error": str(e)}
        finally:
            _scan_running = False

    threading.Thread(target=_run, daemon=True, name="VulnScan").start()
    return {"started": True, "devices": len(devices)}


def get_scan_status() -> dict:
    return {
        "running": _scan_running,
        "result":  _scan_result,
    }
