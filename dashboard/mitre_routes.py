# dashboard/mitre_routes.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — MITRE ATT&CK Routes
# Maps live detections to MITRE ATT&CK techniques.
# Add to app.py:
#   from dashboard.mitre_routes import register_mitre_routes
#   register_mitre_routes(app)
# ─────────────────────────────────────────────────────────────────────────────

from flask import render_template, jsonify, session, redirect, url_for
from functools import wraps

# ── Full detection → MITRE ATT&CK mapping ────────────────────────────────────
DETECTION_MITRE_MAP = {
    # Threat intel signatures
    "Port Scan Detected":          {"id": "T1046", "name": "Network Service Scanning",      "tactic": "Reconnaissance"},
    "Stealth Port Scan":           {"id": "T1595", "name": "Active Scanning",                "tactic": "Reconnaissance"},
    "Aggressive Port Scan":        {"id": "T1046", "name": "Network Service Scanning",      "tactic": "Reconnaissance"},
    "Full Network Sweep":          {"id": "T1046", "name": "Network Service Scanning",      "tactic": "Reconnaissance"},
    "Host Discovery Sweep":        {"id": "T1018", "name": "Remote System Discovery",       "tactic": "Reconnaissance"},
    "Ping Sweep":                  {"id": "T1018", "name": "Remote System Discovery",       "tactic": "Reconnaissance"},
    "OS Fingerprinting":           {"id": "T1082", "name": "System Information Discovery",  "tactic": "Reconnaissance"},
    "Service Enumeration":         {"id": "T1046", "name": "Network Service Scanning",      "tactic": "Reconnaissance"},
    "ARP Scan":                    {"id": "T1018", "name": "Remote System Discovery",       "tactic": "Reconnaissance"},

    # DoS
    "SYN Flood":                   {"id": "T1499", "name": "Endpoint Denial of Service",    "tactic": "Impact"},
    "UDP Flood":                   {"id": "T1498", "name": "Network Denial of Service",     "tactic": "Impact"},
    "ICMP Flood":                  {"id": "T1499", "name": "Endpoint Denial of Service",    "tactic": "Impact"},
    "Packet Rate Spike":           {"id": "T1498", "name": "Network Denial of Service",     "tactic": "Impact"},
    "Traffic Spike":               {"id": "T1498", "name": "Network Denial of Service",     "tactic": "Impact"},
    "High Packet Rate":            {"id": "T1498", "name": "Network Denial of Service",     "tactic": "Impact"},
    "DDoS HTTP Flood":             {"id": "T1498", "name": "Network Denial of Service",     "tactic": "Impact"},
    "Slowloris Attack":            {"id": "T1499", "name": "Endpoint Denial of Service",    "tactic": "Impact"},

    # Credential
    "SSH Brute Force":             {"id": "T1110", "name": "Brute Force",                   "tactic": "Credential Access"},
    "RDP Brute Force":             {"id": "T1110", "name": "Brute Force",                   "tactic": "Credential Access"},
    "HTTP Login Flood":            {"id": "T1110", "name": "Brute Force",                   "tactic": "Credential Access"},
    "Password Spray":              {"id": "T1110", "name": "Password Spraying",             "tactic": "Credential Access"},
    "Brute Force Attempt":         {"id": "T1110", "name": "Brute Force",                   "tactic": "Credential Access"},

    # Exfiltration
    "DNS Exfiltration":            {"id": "T1048", "name": "Exfiltration Over Alt Protocol","tactic": "Exfiltration"},
    "DNS Tunneling":               {"id": "T1071", "name": "Application Layer Protocol",    "tactic": "Command & Control"},
    "Large Outbound Transfer":     {"id": "T1030", "name": "Data Transfer Size Limits",     "tactic": "Exfiltration"},
    "Data Minimization Exfil":     {"id": "T1048", "name": "Exfiltration Over Alt Protocol","tactic": "Exfiltration"},
    "ICMP Tunneling":              {"id": "T1095", "name": "Non-Standard Port",             "tactic": "Command & Control"},

    # C2
    "C2 Beacon Pattern":           {"id": "T1071", "name": "Application Layer Protocol",    "tactic": "Command & Control"},
    "Unusual Outbound Port":       {"id": "T1095", "name": "Non-Standard Port",             "tactic": "Command & Control"},
    "High Unique Destination":     {"id": "T1071", "name": "Application Layer Protocol",    "tactic": "Command & Control"},
    "Trojan Beacon":               {"id": "T1071", "name": "Application Layer Protocol",    "tactic": "Command & Control"},

    # Lateral movement
    "Internal Port Scan":          {"id": "T1021", "name": "Remote Services",               "tactic": "Lateral Movement"},
    "SMB Sweep":                   {"id": "T1021", "name": "SMB/Windows Admin Shares",      "tactic": "Lateral Movement"},
    "RPC Abuse":                   {"id": "T1021", "name": "Remote Services",               "tactic": "Lateral Movement"},
    "Worm Propagation":            {"id": "T1210", "name": "Exploitation of Remote Svc",    "tactic": "Lateral Movement"},

    # Malware
    "Ransomware Traffic":          {"id": "T1486", "name": "Data Encrypted for Impact",     "tactic": "Impact"},
    "Botnet Communication":        {"id": "T1583", "name": "Acquire Infrastructure",        "tactic": "Resource Development"},
    "Living off the Land":         {"id": "T1218", "name": "System Binary Proxy Exec",      "tactic": "Defense Evasion"},

    # Rogue / insider
    "Rogue Device Traffic":        {"id": "T1200", "name": "Hardware Additions",            "tactic": "Initial Access"},
    "Rogue DHCP Activity":         {"id": "T1557", "name": "Adversary-in-the-Middle",       "tactic": "Collection"},
    "ARP Poisoning":               {"id": "T1557", "name": "Adversary-in-the-Middle",       "tactic": "Collection"},
    "Insider Data Staging":        {"id": "T1074", "name": "Data Staged",                   "tactic": "Collection"},
    "Unusual Access Hours":        {"id": "T1078", "name": "Valid Accounts",                "tactic": "Defense Evasion"},

    # Web attacks
    "Web Application Scan":        {"id": "T1190", "name": "Exploit Public-Facing App",     "tactic": "Initial Access"},

    # Zero-day / APT
    "Zero-Day Behavioral":         {"id": "T1203", "name": "Exploitation for Exec",         "tactic": "Execution"},
    "Exploit Traffic Spike":       {"id": "T1190", "name": "Exploit Public-Facing App",     "tactic": "Initial Access"},
    "Shellcode Delivery":          {"id": "T1203", "name": "Exploitation for Exec",         "tactic": "Execution"},
    "Memory Corruption Probe":     {"id": "T1203", "name": "Exploitation for Exec",         "tactic": "Execution"},
    "APT Low-and-Slow Scan":       {"id": "T1595", "name": "Active Scanning",               "tactic": "Reconnaissance"},

    # AI detections
    "AI Behavioral Anomaly":       {"id": "T1071", "name": "Application Layer Protocol",    "tactic": "Command & Control"},
    "Port Scan (Many Destination Ports)": {"id": "T1046", "name": "Network Service Scanning", "tactic": "Reconnaissance"},
    "Known Threat":                {"id": "T1595", "name": "Active Scanning",               "tactic": "Reconnaissance"},
}


def enrich_with_mitre(detections: list) -> list:
    """
    Add MITRE ATT&CK fields to each detection dict.
    Works on anomalies list from orchestrator snapshot.
    """
    enriched = []
    for d in detections:
        d = dict(d)
        det_type = d.get("type", "")

        # Direct match
        mitre = DETECTION_MITRE_MAP.get(det_type)

        # Fuzzy match — check if any key is a substring of the detection type
        if not mitre:
            for key, val in DETECTION_MITRE_MAP.items():
                if key.lower() in det_type.lower() or det_type.lower() in key.lower():
                    mitre = val
                    break

        if mitre:
            d["mitre_id"]   = mitre["id"]
            d["mitre_name"] = mitre["name"]
            d["tactic"]     = mitre["tactic"]
            d["mitre_url"]  = f"https://attack.mitre.org/techniques/{mitre['id']}/"
        else:
            d["mitre_id"]   = None
            d["mitre_name"] = None
            d["tactic"]     = None
            d["mitre_url"]  = None

        enriched.append(d)
    return enriched


def _require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def register_mitre_routes(app):

    @app.route("/mitre")
    @_require_login
    def mitre():
        return render_template("mitre.html",
                               page="mitre",
                               title="MITRE ATT&CK — ZeroGuardian XDR")

    @app.route("/api/mitre/detections")
    @_require_login
    def api_mitre_detections():
        try:
            from core.orchestrator import get_snapshot
            snap       = get_snapshot()
            anomalies  = snap.get("anomalies", [])
            enriched   = enrich_with_mitre(anomalies)

            # Collect all detected MITRE technique IDs
            detected_ids = list({
                d["mitre_id"] for d in enriched
                if d.get("mitre_id")
            })

            return jsonify({
                "detections":   enriched,
                "detected_ids": detected_ids,
                "total":        len(enriched),
            })
        except Exception as e:
            return jsonify({"detections": [], "detected_ids": [], "error": str(e)})

    @app.route("/api/mitre/enrich")
    @_require_login
    def api_mitre_enrich():
        """Returns current anomalies enriched with MITRE data for other pages."""
        try:
            from core.orchestrator import get_snapshot
            snap      = get_snapshot()
            anomalies = snap.get("anomalies", [])
            return jsonify(enrich_with_mitre(anomalies))
        except Exception as e:
            return jsonify([])

    print("[MITRE] Routes registered ✅")
