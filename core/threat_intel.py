# core/threat_intel.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Threat Intelligence Engine
# Reads attack signatures from vulnerabilities.db and matches against
# live traffic metrics captured by the background worker.
# ─────────────────────────────────────────────────────────────────────────────

import sqlite3
import os

# ── Correct DB path — signatures live in vulnerabilities.db ──────────────────
BASE_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH   = os.path.join(BASE_DIR, "vulnerabilities.db")


def load_signatures():
    """Load all attack signatures from vulnerabilities.db."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()
        cur.execute("""
            SELECT name, indicator, operator, value, severity, description
            FROM threat_signatures
        """)
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "name":        r[0],
                "indicator":   r[1],
                "operator":    r[2] or "gt",
                "value":       r[3],
                "severity":    r[4] or "MEDIUM",
                "description": r[5] or "",
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[ThreatIntel] load_signatures error: {e}")
        return []


def _compare(actual, operator, threshold):
    """Compare actual metric value against threshold using operator."""
    try:
        actual    = float(actual)
        threshold = float(threshold)
    except (TypeError, ValueError):
        return False
    ops = {
        "gt":  actual >  threshold,
        "gte": actual >= threshold,
        "lt":  actual <  threshold,
        "lte": actual <= threshold,
        "eq":  actual == threshold,
    }
    return ops.get(operator, actual > threshold)


def detect_known_threats(traffic):
    """
    Match live traffic metrics against all signatures in the DB.
    Returns list of alert dicts.
    """
    signatures = load_signatures()
    alerts     = []
    seen       = set()   # dedup identical alerts in same cycle

    total_packets    = traffic.get("total_packets", 0)
    duration         = traffic.get("duration_sec", 30) or 30
    pps              = total_packets / duration if duration > 0 else 0
    entries          = traffic.get("entries", [])
    top_protocols    = traffic.get("top_protocols", [])
    syn_rate         = traffic.get("syn_rate", 0)
    udp_rate         = traffic.get("udp_rate", 0)
    icmp_rate        = traffic.get("icmp_rate", 0)
    dst_port_variety = traffic.get("dst_port_variety", 0)
    unique_dst_ips   = traffic.get("unique_dst_ips", 0)

    # Build protocol lookup
    proto_counts = {p["proto"].upper(): p["count"]
                    for p in top_protocols if isinstance(p, dict)}

    # Build per-IP port sets and connection counts for scan detection
    ports_by_ip = {}
    conn_by_ip  = {}
    for e in entries:
        src  = e.get("src")
        port = e.get("port") or e.get("dport")
        if src and port:
            ports_by_ip.setdefault(src, set()).add(str(port))
            conn_by_ip[src] = conn_by_ip.get(src, 0) + 1

    # ── Match signatures ──────────────────────────────────────────────────────
    for sig in signatures:
        ind  = sig["indicator"]
        op   = sig["operator"]
        val  = sig["value"]
        name = sig["name"]
        sev  = sig["severity"]
        desc = sig["description"]

        triggered = False
        detail    = desc

        # Packet rate indicators
        if ind == "packet_rate":
            if _compare(pps, op, val):
                triggered = True
                detail = f"{int(pps)} pps detected (threshold: {val}). {desc}"

        elif ind == "total_packets":
            if _compare(total_packets, op, val):
                triggered = True
                detail = f"{total_packets} packets in window. {desc}"

        # Protocol-specific indicators
        elif ind == "syn_rate":
            if _compare(syn_rate, op, val):
                triggered = True
                detail = f"{syn_rate} SYN packets detected (threshold: {val}). {desc}"

        elif ind == "udp_rate":
            count = proto_counts.get("UDP", udp_rate)
            if _compare(count, op, val):
                triggered = True
                detail = f"{count} UDP packets detected (threshold: {val}). {desc}"

        elif ind == "icmp_rate":
            count = proto_counts.get("ICMP", icmp_rate)
            if _compare(count, op, val):
                triggered = True
                detail = f"{count} ICMP packets detected (threshold: {val}). {desc}"

        elif ind == "dst_port_variety":
            if _compare(dst_port_variety, op, val):
                triggered = True
                detail = (f"Single source scanned {dst_port_variety} unique ports "
                          f"(threshold: {val}). {desc}")

        elif ind == "unique_dst_ips":
            if _compare(unique_dst_ips, op, val):
                triggered = True
                detail = (f"Traffic spread across {unique_dst_ips} destination IPs. {desc}")

        elif ind == "dns_query_rate":
            dns_count = proto_counts.get("DNS", 0)
            if _compare(dns_count, op, val):
                triggered = True
                detail = f"{dns_count} DNS queries in window (threshold: {val}). {desc}"

        elif ind == "connection_rate":
            max_conns = max(conn_by_ip.values(), default=0)
            if _compare(max_conns, op, val):
                triggered = True
                detail = f"Single IP made {max_conns} connections (threshold: {val}). {desc}"

        if triggered:
            key = f"{name}:{sev}"
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":     name,
                    "severity": sev,
                    "details":  detail.strip(),
                    "source":   "threat_intel",
                })

    # ── Per-IP port scan detection (always active) ────────────────────────────
    for ip, ports in ports_by_ip.items():
        count = len(ports)
        if count > 15:
            sev = "CRITICAL" if count > 100 else "HIGH" if count > 50 else "MEDIUM"
            key = f"portscan:{ip}"
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":     "Port Scan Detected",
                    "severity": sev,
                    "details":  f"Source {ip} scanned {count} unique ports in one window.",
                    "source":   "threat_intel",
                    "ip":       ip,
                })

    # ── Brute force detection — many connections from single IP ───────────────
    for ip, count in conn_by_ip.items():
        if count > 200:
            sev = "CRITICAL" if count > 200 else "HIGH"
            key = f"bruteforce:{ip}"
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":     "Brute Force Attempt",
                    "severity": sev,
                    "details":  f"Source {ip} made {count} rapid connections.",
                    "source":   "threat_intel",
                    "ip":       ip,
                })

    return alerts


# ── Compatibility alias ───────────────────────────────────────────────────────
def detect_known_threat(traffic):
    return detect_known_threats(traffic)
