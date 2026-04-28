import os
import sqlite3

DB_PATH = os.path.join("database", "zeroguardian.db")

SEED = [
  # --- Recon / Scanning ---
  ("Port Scan (Many Destination Ports)", "Network", "dst_port_variety", "gt", "20", "MEDIUM",
   "Same source IP hitting many destination ports within short time."),

  ("Ping Sweep / ICMP Burst", "Network", "icmp_rate", "gt", "50", "MEDIUM",
   "High ICMP packet rate may indicate scanning or probing."),

  # --- DoS / Flood ---
  ("Possible UDP Flood", "Network", "udp_rate", "gt", "300", "HIGH",
   "Very high UDP packet rate in a short window."),

  ("Possible TCP SYN Flood", "Network", "syn_rate", "gt", "200", "HIGH",
   "High SYN rate can indicate SYN flood attempt."),

  # --- Spoofing / LAN attacks ---
  ("ARP Spoofing Suspicion", "Network", "duplicate_mac", "eq", "true", "HIGH",
   "Same MAC seen for multiple IPs or rapid MAC change in ARP cache."),

  ("Gateway MAC Change", "Network", "gateway_mac_change", "eq", "true", "HIGH",
   "Default gateway MAC changed unexpectedly (MITM risk)."),

  # --- Exfil / Suspicious behavior ---
  ("DNS Tunneling Suspicion", "Network", "dns_query_len", "gt", "80", "HIGH",
   "Very long DNS queries can indicate data exfiltration via DNS."),

  ("Suspicious Outbound Connections", "Network", "unique_dst_ips", "gt", "40", "MEDIUM",
   "Large number of unique destination IPs in a short time."),

  # --- Remote access / common risky services ---
  ("SSH Brute Force Suspicion", "Auth", "ssh_failed_logins", "gt", "8", "HIGH",
   "Multiple failed SSH logins in a short time."),

  ("RDP Exposure / Activity", "Network", "dst_port", "eq", "3389", "MEDIUM",
   "RDP traffic detected. Verify exposure and access control."),

  ("SMB Traffic Detected", "Network", "dst_port", "eq", "445", "MEDIUM",
   "SMB traffic observed. Monitor for lateral movement."),

  # --- Web attacks (basic indicators) ---
  ("HTTP Suspicious User-Agent", "Web", "http_user_agent", "contains", "sqlmap", "HIGH",
   "Known scanning tool user-agent detected."),

  ("Possible SQL Injection Pattern", "Web", "http_query", "contains", "UNION SELECT", "HIGH",
   "Common SQLi string found in HTTP query."),

  ("Possible XSS Pattern", "Web", "http_query", "contains", "<script", "MEDIUM",
   "XSS-like payload found in HTTP query."),

  # --- Malware-ish indicators (basic) ---
  ("Outbound to Known Bad Port (6667 IRC)", "Network", "dst_port", "eq", "6667", "MEDIUM",
   "Legacy botnet/IRC C2 port observed."),

  ("Outbound to Tor (9001)", "Network", "dst_port", "eq", "9001", "MEDIUM",
   "Tor-related port observed; verify if expected.")
]

def seed():
  conn = sqlite3.connect(DB_PATH)
  cur = conn.cursor()

  # insert only if table empty
  cur.execute("SELECT COUNT(*) FROM threat_signatures")
  count = cur.fetchone()[0]
  if count > 0:
    print("[DB] threat_signatures already has data (count=%d). Skipping seed." % count)
    conn.close()
    return

  cur.executemany("""
    INSERT INTO threat_signatures (name, category, indicator, operator, value, severity, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  """, SEED)

  conn.commit()
  conn.close()
  print("[DB] Seeded threat_signatures with", len(SEED), "rules.")

if __name__ == "__main__":
  seed()
