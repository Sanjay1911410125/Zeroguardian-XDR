# core/threat_feeds.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Live Threat Intelligence Feed Integrator
# Pulls from 9 free threat intelligence sources automatically.
# Updates every 6 hours. Stores 50,000+ indicators in vulnerabilities.db.
#
# Feeds integrated:
#   1. AlienVault OTX      — 19M+ malicious IPs/domains/hashes
#   2. Abuse.ch            — 500K+ malware C2 servers
#   3. Feodo Tracker       — Banking trojan C2 IPs
#   4. URLhaus             — 1M+ malware download URLs
#   5. Blocklist.de        — Brute force attacker IPs
#   6. ThreatFox           — Malware IOCs and hashes
#   7. EmergingThreats     — Network attack rules
#   8. CVE NVD API         — Latest CVEs (200,000+)
#   9. MITRE ATT&CK STIX   — Full technique database
# ─────────────────────────────────────────────────────────────────────────────

import os
import sqlite3
import threading
import time
import json
import gzip
import csv
import io
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[ThreatFeeds] requests not installed — run: pip install requests")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH  = os.path.join(BASE_DIR, "vulnerabilities.db")
ENV_PATH = os.path.join(BASE_DIR, ".env")

UPDATE_INTERVAL_SEC = 6 * 3600   # 6 hours
_updater_started    = False
_last_update        = 0
_update_stats       = {}


# ── Env loader ────────────────────────────────────────────────────────────────
def _load_env():
    env = {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
    return env


# ── Database setup ────────────────────────────────────────────────────────────
def _setup_db():
    conn = sqlite3.connect(DB_PATH)

    # Main threat indicators table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_indicators (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator   TEXT NOT NULL,
            type        TEXT NOT NULL,
            source      TEXT NOT NULL,
            severity    TEXT DEFAULT 'HIGH',
            category    TEXT,
            description TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(indicator, source)
        )
    """)

    # Feed update log
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feed_updates (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_name   TEXT NOT NULL,
            records     INTEGER DEFAULT 0,
            status      TEXT DEFAULT 'success',
            error       TEXT,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Index for fast lookups during traffic analysis
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_indicator
        ON threat_indicators(indicator)
    """)

    conn.commit()
    conn.close()
    print("[ThreatFeeds] Database tables ready ✅")


def _log_feed_update(feed_name, records, status="success", error=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            INSERT INTO feed_updates (feed_name, records, status, error)
            VALUES (?,?,?,?)
        """, (feed_name, records, status, error))
        conn.commit()
        conn.close()
    except Exception:
        pass


def _bulk_insert(indicators: list):
    """Bulk insert indicators into DB. indicators = list of tuples."""
    if not indicators:
        return 0
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.executemany("""
            INSERT OR REPLACE INTO threat_indicators
                (indicator, type, source, severity, category, description,
                 first_seen, last_seen)
            VALUES (?,?,?,?,?,?,?,?)
        """, indicators)
        count = conn.total_changes
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        print(f"[ThreatFeeds] DB insert error: {e}")
        return 0


# ── FEED 1: AlienVault OTX ────────────────────────────────────────────────────
def fetch_otx(api_key: str) -> int:
    if not api_key or not HAS_REQUESTS:
        return 0

    print("[ThreatFeeds] Fetching AlienVault OTX ...")
    indicators = []
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        headers = {"X-OTX-API-KEY": api_key}

        # Fetch subscribed pulses
        url  = "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=20"
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            print(f"[OTX] Error {resp.status_code}")
            _log_feed_update("AlienVault OTX", 0, "error", str(resp.status_code))
            return 0

        data   = resp.json()
        pulses = data.get("results", [])

        for pulse in pulses:
            pulse_name = pulse.get("name", "OTX Pulse")
            for ioc in pulse.get("indicators", []):
                ind_type = ioc.get("type", "").lower()
                value    = ioc.get("indicator", "").strip()
                if not value:
                    continue

                # Map OTX types to our types
                if ind_type in ("ipv4", "ipv6"):
                    itype = "ip"
                elif ind_type in ("domain", "hostname"):
                    itype = "domain"
                elif ind_type in ("url",):
                    itype = "url"
                elif ind_type in ("filehash-md5", "filehash-sha1", "filehash-sha256"):
                    itype = "hash"
                else:
                    continue

                indicators.append((
                    value, itype, "AlienVault OTX",
                    "HIGH", pulse_name,
                    f"OTX Pulse: {pulse_name}",
                    today, today
                ))

        count = _bulk_insert(indicators)
        print(f"[OTX] {count} indicators inserted ✅")
        _log_feed_update("AlienVault OTX", count)
        return count

    except Exception as e:
        print(f"[OTX] Error: {e}")
        _log_feed_update("AlienVault OTX", 0, "error", str(e))
        return 0


# ── FEED 2: Abuse.ch MalwareBazaar ───────────────────────────────────────────
def fetch_abusech() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching Abuse.ch MalwareBazaar ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "100"},
            timeout=30
        )
        data = resp.json()
        if data.get("query_status") != "ok":
            return 0

        indicators = []
        for sample in data.get("data", []):
            sha256 = sample.get("sha256_hash", "")
            tags   = ", ".join(sample.get("tags") or [])
            if sha256:
                indicators.append((
                    sha256, "hash", "Abuse.ch MalwareBazaar",
                    "CRITICAL", "Malware",
                    f"Malware sample. Tags: {tags}",
                    today, today
                ))

            # Also add C2 if available
            c2_list = sample.get("vendor_intel", {})
            for vendor, info in c2_list.items():
                if isinstance(info, dict):
                    c2 = info.get("C2", "")
                    if c2:
                        indicators.append((
                            c2, "ip", "Abuse.ch MalwareBazaar",
                            "CRITICAL", "Malware C2",
                            f"Malware C2 server. Vendor: {vendor}",
                            today, today
                        ))

        count = _bulk_insert(indicators)
        print(f"[Abuse.ch] {count} indicators inserted ✅")
        _log_feed_update("Abuse.ch MalwareBazaar", count)
        return count

    except Exception as e:
        print(f"[Abuse.ch] Error: {e}")
        _log_feed_update("Abuse.ch MalwareBazaar", 0, "error", str(e))
        return 0


# ── FEED 3: Feodo Tracker ─────────────────────────────────────────────────────
def fetch_feodo() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching Feodo Tracker ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        resp = requests.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
            timeout=30
        )
        data = resp.json()
        indicators = []

        for entry in data:
            ip      = entry.get("ip_address", "").strip()
            malware = entry.get("malware", "Unknown")
            port    = entry.get("port", "")
            if ip:
                indicators.append((
                    ip, "ip", "Feodo Tracker",
                    "CRITICAL", "Banking Trojan C2",
                    f"{malware} C2 server on port {port}",
                    entry.get("first_seen", today),
                    entry.get("last_online", today)
                ))

        count = _bulk_insert(indicators)
        print(f"[Feodo] {count} C2 IPs inserted ✅")
        _log_feed_update("Feodo Tracker", count)
        return count

    except Exception as e:
        print(f"[Feodo] Error: {e}")
        _log_feed_update("Feodo Tracker", 0, "error", str(e))
        return 0


# ── FEED 4: URLhaus ───────────────────────────────────────────────────────────
def fetch_urlhaus() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching URLhaus ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        resp = requests.get(
            "https://urlhaus.abuse.ch/downloads/csv_recent/",
            timeout=30
        )
        indicators = []
        lines      = resp.text.splitlines()

        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            url      = parts[2].strip().strip('"')
            status   = parts[3].strip().strip('"')
            tags     = parts[5].strip().strip('"') if len(parts) > 5 else ""
            if url and status == "online":
                # Extract domain from URL
                try:
                    domain = url.split("/")[2]
                    indicators.append((
                        domain, "domain", "URLhaus",
                        "HIGH", "Malware Distribution",
                        f"Malware URL host. Tags: {tags}",
                        today, today
                    ))
                except Exception:
                    pass

        # Limit to 5000 most recent
        indicators = indicators[:5000]
        count = _bulk_insert(indicators)
        print(f"[URLhaus] {count} malware domains inserted ✅")
        _log_feed_update("URLhaus", count)
        return count

    except Exception as e:
        print(f"[URLhaus] Error: {e}")
        _log_feed_update("URLhaus", 0, "error", str(e))
        return 0


# ── FEED 5: Blocklist.de ─────────────────────────────────────────────────────
def fetch_blocklist_de() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching Blocklist.de ...")
    today = datetime.now().strftime("%Y-%m-%d")

    # Different attack type lists
    lists = {
        "ssh":   ("https://lists.blocklist.de/lists/ssh.txt",   "SSH Brute Force"),
        "mail":  ("https://lists.blocklist.de/lists/mail.txt",  "Mail Attack"),
        "apache":("https://lists.blocklist.de/lists/apache.txt","Web Attack"),
        "ftp":   ("https://lists.blocklist.de/lists/ftp.txt",   "FTP Attack"),
    }

    indicators = []
    for key, (url, category) in lists.items():
        try:
            resp = requests.get(url, timeout=20)
            for line in resp.text.splitlines():
                ip = line.strip()
                if ip and not ip.startswith("#") and "." in ip:
                    indicators.append((
                        ip, "ip", "Blocklist.de",
                        "HIGH", category,
                        f"Known {category} attacker IP",
                        today, today
                    ))
        except Exception as e:
            print(f"[Blocklist.de] {key} error: {e}")

    count = _bulk_insert(indicators)
    print(f"[Blocklist.de] {count} attacker IPs inserted ✅")
    _log_feed_update("Blocklist.de", count)
    return count


# ── FEED 6: ThreatFox ────────────────────────────────────────────────────────
def fetch_threatfox() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching ThreatFox IOCs ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 3},
            timeout=30
        )
        data = resp.json()
        if data.get("query_status") != "ok":
            return 0

        indicators = []
        for ioc in data.get("data", []):
            value    = ioc.get("ioc_value", "").strip()
            ioc_type = ioc.get("ioc_type", "").lower()
            malware  = ioc.get("malware", "Unknown")
            tags     = ", ".join(ioc.get("tags") or [])

            if not value:
                continue

            if "ip" in ioc_type:
                # Strip port if present (e.g. 1.2.3.4:8080)
                value = value.split(":")[0]
                itype = "ip"
            elif "domain" in ioc_type or "host" in ioc_type:
                itype = "domain"
            elif "url" in ioc_type:
                itype = "url"
            elif "hash" in ioc_type or "md5" in ioc_type or "sha" in ioc_type:
                itype = "hash"
            else:
                continue

            indicators.append((
                value, itype, "ThreatFox",
                "CRITICAL", malware,
                f"ThreatFox IOC: {malware}. Tags: {tags}",
                today, today
            ))

        count = _bulk_insert(indicators)
        print(f"[ThreatFox] {count} IOCs inserted ✅")
        _log_feed_update("ThreatFox", count)
        return count

    except Exception as e:
        print(f"[ThreatFox] Error: {e}")
        _log_feed_update("ThreatFox", 0, "error", str(e))
        return 0


# ── FEED 7: CVE NVD API ───────────────────────────────────────────────────────
def fetch_nvd_cves() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching NVD CVEs ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        # Fetch recent critical CVEs
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            "?cvssV3Severity=CRITICAL&resultsPerPage=100",
            timeout=30,
            headers={"User-Agent": "ZeroGuardian-XDR/1.0"}
        )
        data = resp.json()

        conn = sqlite3.connect(DB_PATH)

        # Ensure CVE columns exist
        try:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN name TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN severity TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE vulnerabilities ADD COLUMN affected TEXT")
        except Exception:
            pass

        count = 0
        for vuln in data.get("vulnerabilities", []):
            cve  = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc   = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:500]
                    break

            metrics  = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                if metrics.get("cvssMetricV31")
                else metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                if metrics.get("cvssMetricV30")
                else {}
            )
            score = cvss_data.get("baseScore", 0)
            sev   = cvss_data.get("baseSeverity", "HIGH")

            try:
                conn.execute("""
                    INSERT OR REPLACE INTO vulnerabilities
                        (cve_id, name, severity, cvss_score, description, affected)
                    VALUES (?,?,?,?,?,?)
                """, (cve_id, cve_id, sev, score, desc, "See NVD for details"))
                count += 1
            except Exception:
                pass

        conn.commit()
        conn.close()

        print(f"[NVD] {count} CVEs updated ✅")
        _log_feed_update("NVD CVEs", count)
        return count

    except Exception as e:
        print(f"[NVD] Error: {e}")
        _log_feed_update("NVD CVEs", 0, "error", str(e))
        return 0


# ── FEED 8: MITRE ATT&CK ─────────────────────────────────────────────────────
def fetch_mitre_attack() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching MITRE ATT&CK STIX data ...")

    try:
        resp = requests.get(
            "https://raw.githubusercontent.com/mitre/cti/master/"
            "enterprise-attack/enterprise-attack.json",
            timeout=60
        )
        data    = resp.json()
        objects = data.get("objects", [])

        conn = sqlite3.connect(DB_PATH)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id           TEXT PRIMARY KEY,
                name         TEXT,
                tactic       TEXT,
                description  TEXT,
                url          TEXT,
                updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        count = 0
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            ext_refs = obj.get("external_references", [])
            tech_id  = ""
            url      = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "")
                    url     = ref.get("url", "")
                    break

            if not tech_id or tech_id.startswith("T") is False:
                continue

            tactics = [
                p.get("phase_name", "")
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]

            desc = obj.get("description", "")[:500]
            name = obj.get("name", "")

            try:
                conn.execute("""
                    INSERT OR REPLACE INTO mitre_techniques
                        (id, name, tactic, description, url)
                    VALUES (?,?,?,?,?)
                """, (tech_id, name, ", ".join(tactics), desc, url))
                count += 1
            except Exception:
                pass

        conn.commit()
        conn.close()

        print(f"[MITRE] {count} ATT&CK techniques updated ✅")
        _log_feed_update("MITRE ATT&CK", count)
        return count

    except Exception as e:
        print(f"[MITRE] Error: {e}")
        _log_feed_update("MITRE ATT&CK", 0, "error", str(e))
        return 0


# ── FEED 9: EmergingThreats Rules ────────────────────────────────────────────
def fetch_emerging_threats() -> int:
    if not HAS_REQUESTS:
        return 0
    print("[ThreatFeeds] Fetching EmergingThreats compromised IPs ...")
    today = datetime.now().strftime("%Y-%m-%d")

    try:
        resp = requests.get(
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            timeout=30
        )
        indicators = []
        for line in resp.text.splitlines():
            ip = line.strip()
            if ip and not ip.startswith("#") and "." in ip:
                indicators.append((
                    ip, "ip", "EmergingThreats",
                    "HIGH", "Compromised Host",
                    "Known compromised host from EmergingThreats",
                    today, today
                ))

        count = _bulk_insert(indicators[:10000])
        print(f"[EmergingThreats] {count} compromised IPs inserted ✅")
        _log_feed_update("EmergingThreats", count)
        return count

    except Exception as e:
        print(f"[EmergingThreats] Error: {e}")
        _log_feed_update("EmergingThreats", 0, "error", str(e))
        return 0


# ── Live traffic checker ──────────────────────────────────────────────────────
def check_traffic_against_feeds(traffic: dict) -> list:
    """
    Check live traffic IPs and domains against threat indicator database.
    Returns list of matches — called by orchestrator every cycle.
    """
    alerts = []
    try:
        entries = traffic.get("entries", [])
        if not entries:
            return []

        # Collect all IPs from traffic
        ips = set()
        for e in entries:
            if e.get("src") and e.get("src") != "unknown":
                ips.add(e["src"].split(":")[0])   # strip port
            if e.get("dst") and e.get("dst") != "unknown":
                ips.add(e["dst"].split(":")[0])

        if not ips:
            return []

        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()

        placeholders = ",".join("?" * len(ips))
        cur.execute(f"""
            SELECT indicator, source, severity, category, description
            FROM threat_indicators
            WHERE indicator IN ({placeholders})
            AND type = 'ip'
        """, list(ips))

        rows = cur.fetchall()
        conn.close()

        seen = set()
        for row in rows:
            indicator, source, severity, category, desc = row
            key = f"{indicator}:{source}"
            if key not in seen:
                seen.add(key)
                alerts.append({
                    "type":     f"Threat Intel Match — {category or source}",
                    "severity": severity or "HIGH",
                    "ip":       indicator,
                    "details":  f"IP {indicator} matched {source}: {desc or category}",
                    "source":   "threat_intel_feed",
                    "feed":     source,
                })

    except Exception as e:
        print(f"[ThreatFeeds] Traffic check error: {e}")

    return alerts


# ── Full update run ───────────────────────────────────────────────────────────
def run_full_update() -> dict:
    """Run all feed updates. Returns summary dict."""
    global _last_update, _update_stats

    print("\n" + "="*60)
    print(f"[ThreatFeeds] Starting full update — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)

    _setup_db()
    env   = _load_env()
    total = 0
    stats = {}

    # Run all feeds
    feeds = [
        ("AlienVault OTX",     lambda: fetch_otx(env.get("OTX_API_KEY", ""))),
        ("Abuse.ch",           fetch_abusech),
        ("Feodo Tracker",      fetch_feodo),
        ("URLhaus",            fetch_urlhaus),
        ("Blocklist.de",       fetch_blocklist_de),
        ("ThreatFox",          fetch_threatfox),
        ("NVD CVEs",           fetch_nvd_cves),
        ("MITRE ATT&CK",       fetch_mitre_attack),
        ("EmergingThreats",    fetch_emerging_threats),
    ]

    for name, fn in feeds:
        try:
            count       = fn()
            stats[name] = count
            total      += count
        except Exception as e:
            print(f"[ThreatFeeds] {name} failed: {e}")
            stats[name] = 0

    # Count total in DB
    try:
        conn     = sqlite3.connect(DB_PATH)
        cur      = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM threat_indicators")
        db_total = cur.fetchone()[0]
        conn.close()
    except Exception:
        db_total = total

    _last_update  = time.time()
    _update_stats = {
        "feeds":       stats,
        "new_records": total,
        "db_total":    db_total,
        "updated_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    print("="*60)
    print(f"[ThreatFeeds] Update complete!")
    print(f"[ThreatFeeds] New records this run : {total:,}")
    print(f"[ThreatFeeds] Total in database    : {db_total:,}")
    print("="*60 + "\n")

    return _update_stats


# ── Background scheduler ──────────────────────────────────────────────────────
def start_feed_updater():
    """Start background thread that updates feeds every 6 hours."""
    global _updater_started
    if _updater_started:
        return
    _updater_started = True

    def _loop():
        # First run immediately
        try:
            run_full_update()
        except Exception as e:
            print(f"[ThreatFeeds] Initial update error: {e}")

        while True:
            time.sleep(UPDATE_INTERVAL_SEC)
            try:
                run_full_update()
            except Exception as e:
                print(f"[ThreatFeeds] Scheduled update error: {e}")

    t = threading.Thread(target=_loop, daemon=True, name="ThreatFeedUpdater")
    t.start()
    print("[ThreatFeeds] Feed updater started — updates every 6 hours ✅")


def get_feed_stats() -> dict:
    """Return current feed statistics for dashboard display."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur  = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM threat_indicators")
        total = cur.fetchone()[0]

        cur.execute("""
            SELECT source, COUNT(*) as cnt
            FROM threat_indicators
            GROUP BY source
            ORDER BY cnt DESC
        """)
        by_source = {r[0]: r[1] for r in cur.fetchall()}

        cur.execute("""
            SELECT feed_name, records, status, updated_at
            FROM feed_updates
            ORDER BY updated_at DESC LIMIT 20
        """)
        recent = [
            {"feed": r[0], "records": r[1],
             "status": r[2], "updated_at": r[3]}
            for r in cur.fetchall()
        ]

        conn.close()
        return {
            "total_indicators": total,
            "by_source":        by_source,
            "recent_updates":   recent,
            "last_update":      _update_stats.get("updated_at", "Never"),
            "next_update_in":   max(0, int(
                (_last_update + UPDATE_INTERVAL_SEC - time.time()) / 60
            )) if _last_update else 0,
        }
    except Exception as e:
        return {"error": str(e), "total_indicators": 0}


# ── Quick test ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Running manual feed update...")
    stats = run_full_update()
    print(json.dumps(stats, indent=2))
