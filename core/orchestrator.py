# core/orchestrator.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Background Worker Orchestrator
# Runs analysis every 30 seconds in background thread.
# Flask routes call get_snapshot() / collect_all() — returns instantly.
# Sends Telegram alerts automatically on every detected anomaly.
# ─────────────────────────────────────────────────────────────────────────────

import time
import threading
from collections import Counter

from core.device_discovery import discover_devices
from core.anomaly_detector import detect_anomalies
from core.ai_detector import SimpleAutoEncoderDetector
from core.threat_intel import detect_known_threats
from core.features import build_features

try:
    from core.risk_scoring import compute_risk
except Exception:
    compute_risk = None

# ── Singleton detector (loaded once at startup) ────────────────────────────────
detector = SimpleAutoEncoderDetector()

# ── Shared in-memory snapshot ─────────────────────────────────────────────────
_SNAPSHOT = {
    "devices":       [],
    "traffic":       {},
    "anomalies":     [],
    "known_alerts":  [],
    "risk_summary":  {
        "overall_score": 0, "overall_level": "LOW",
        "high_count": 0, "medium_count": 0, "low_count": 0, "top_risky": []
    },
    "risk_by_ip":    {},
    "last_updated":  0,
    "worker_status": "starting",
}
_LOCK = threading.Lock()

WORKER_INTERVAL_SEC  = 30
DEVICE_REFRESH_EVERY = 4   # re-scan devices every 4 cycles (~2 min)

_worker_started = False
_cycle_count    = 0


# ── Traffic reader — reads LiveLogStore instantly (no blocking) ───────────────
def _read_traffic_from_store():
    try:
        from core.live_logs import STORE
        snap = STORE.snapshot()

        raw_protos = snap.get("protocols", {})
        top_protocols = [
            {"proto": k, "count": v}
            for k, v in sorted(raw_protos.items(),
                               key=lambda x: x[1], reverse=True)[:5]
        ]

        entries = snap.get("entries", [])
        total   = snap.get("packets", 0)

        ip_counter   = Counter()
        ports_by_src = {}
        syn_rate = udp_rate = icmp_rate = 0

        for e in entries:
            src = e.get("src"); dst = e.get("dst")
            if src and src != "unknown": ip_counter[src] += 1
            if dst and dst != "unknown": ip_counter[dst] += 1
            proto = (e.get("proto") or "").upper()
            if proto == "UDP":  udp_rate  += 1
            if proto == "ICMP": icmp_rate += 1
            if "syn" in (e.get("note") or "").lower(): syn_rate += 1
            port = e.get("port")
            if src and port and str(port).isdigit():
                ports_by_src.setdefault(src, set()).add(int(port))

        top_talkers      = [{"ip": ip, "count": cnt}
                            for ip, cnt in ip_counter.most_common(5)]
        dst_port_variety = max((len(s) for s in ports_by_src.values()), default=0)
        unique_dst       = len(set(
            e.get("dst") for e in entries
            if e.get("dst") and e.get("dst") != "unknown"
        ))
        duration = snap.get("duration_sec", WORKER_INTERVAL_SEC)

        return {
            "duration_sec":     duration,
            "duration":         duration,
            "total_packets":    total,
            "packets":          total,
            "unique_ips":       snap.get("unique_ips", 0),
            "top_protocols":    top_protocols,
            "protocols":        raw_protos,
            "top_talkers":      top_talkers,
            "entries":          list(entries)[-300:],
            "udp_rate":         udp_rate,
            "icmp_rate":        icmp_rate,
            "syn_rate":         syn_rate,
            "dst_port_variety": dst_port_variety,
            "unique_dst_ips":   unique_dst,
            "source":           "live_store",
            "last_update_ts":   snap.get("last_update_ts", 0),
        }

    except Exception as e:
        print(f"[Worker] LiveStore read error: {e}")
        return {
            "duration_sec": WORKER_INTERVAL_SEC, "duration": WORKER_INTERVAL_SEC,
            "total_packets": 0, "packets": 0, "unique_ips": 0,
            "top_protocols": [], "protocols": {}, "top_talkers": [],
            "entries": [], "udp_rate": 0, "icmp_rate": 0,
            "syn_rate": 0, "dst_port_variety": 0, "unique_dst_ips": 0,
            "source": "error",
        }


# ── Send Telegram alert safely (never crashes the worker) ─────────────────────
def _send_alert(title, details, severity, ip="network"):
    if severity.upper() not in ("HIGH", "CRITICAL"):
        return
    try:
        from core.alerts import send_threat_alert
        send_threat_alert(
            title=title,
            details=details,
            severity=severity,
            ip=ip,
            async_send=True,   # non-blocking — runs in separate thread
        )
    except Exception as e:
        print(f"[Worker] Alert send error: {e}")


# ── One full analysis cycle ───────────────────────────────────────────────────
def _run_cycle(devices_cache):
    global _cycle_count
    _cycle_count += 1

    # Device scan — only every N cycles
    if _cycle_count % DEVICE_REFRESH_EVERY == 1 or not devices_cache:
        try:
            devices = discover_devices() or []
            print(f"[Worker] Devices: {len(devices)} found")
        except Exception as e:
            devices = devices_cache or []
            print(f"[Worker] Device scan error: {e}")
    else:
        devices = devices_cache

    # Read traffic instantly from Scapy background capture
    traffic = _read_traffic_from_store()

    anomalies    = []
    known_alerts = []

    # ── Known threat signatures ───────────────────────────────────────────────
    try:
        known_alerts = detect_known_threats(traffic) or []
        for k in known_alerts:
            sev     = (k.get("severity") or "MEDIUM")
            details = k.get("details", "Matched known attack signature")
            anomalies.append({
                "type":     k.get("type", "Known Threat"),
                "severity": sev.lower(),
                "details":  details,
                "source":   "threat_intel",
            })
            # 🔔 Telegram alert for known threats
            _send_alert(
                title=k.get("type", "Known Threat"),
                details=details,
                severity=sev,
                ip="network",
            )
    except Exception as e:
        print(f"[Worker] Threat intel error: {e}")

    # ── Rule-based anomaly detection ──────────────────────────────────────────
    try:
        anomalies += detect_anomalies(traffic, devices) or []
    except Exception as e:
        print(f"[Worker] Anomaly detector error: {e}")

    # ── AI autoencoder detection ──────────────────────────────────────────────
    try:
        features  = build_features(devices, traffic)
        ai_result = detector.predict(features)

        top       = traffic.get("top_talkers") or []
        target_ip = "unknown"
        if top:
            first     = top[0]
            target_ip = (first.get("ip") or "unknown") \
                        if isinstance(first, dict) else str(first)

        device_name = "Unknown Device"
        for d in devices:
            if d.get("ip") == target_ip:
                device_name = (d.get("name") or d.get("hostname")
                               or d.get("mac") or "Unknown Device")
                break

        if ai_result["anomaly"]:
            details = ai_result.get("details", "Behavioral anomaly detected")
            anomalies.append({
                "type":       "AI Behavioral Anomaly",
                "severity":   ai_result["severity"],
                "ip":         target_ip,
                "device":     device_name,
                "score":      ai_result["score"],
                "confidence": ai_result.get("confidence", 0),
                "details":    details,
                "features":   ai_result.get("features", []),
                "model":      ai_result.get("model", "AutoEncoder"),
                "source":     "ai",
            })
            # 🔔 Telegram alert for AI detections
            _send_alert(
                title=f"AI Behavioral Anomaly — {ai_result['severity']}",
                details=f"{details} | Device: {device_name}",
                severity=ai_result["severity"],
                ip=target_ip,
            )

    except Exception as e:
        print(f"[Worker] AI detector error: {e}")

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk_summary = {
        "overall_score": 0, "overall_level": "LOW",
        "high_count": 0, "medium_count": 0, "low_count": 0, "top_risky": []
    }
    risk_by_ip = {}
    try:
        if compute_risk:
            risk_summary, risk_by_ip = compute_risk(devices, traffic, anomalies)
    except Exception as e:
        print(f"[Worker] Risk scoring error: {e}")

    # Check live traffic against threat intelligence feeds
    try:
        from core.threat_feeds import check_traffic_against_feeds
        feed_hits = check_traffic_against_feeds(traffic)
        for hit in feed_hits:
            anomalies.append(hit)
            _send_alert(
                title=hit["type"],
                details=hit["details"],
                severity=hit["severity"],
                ip=hit.get("ip", "unknown"),
            )
    except Exception as e:
        print(f"[Worker] Feed check error: {e}")

    # Filter noisy alerts
    noisy     = {"Protocol Dominance", "Single Talker Dominance"}
    anomalies = [a for a in anomalies if a.get("type") not in noisy]

    snapshot = {
        "devices":       devices,
        "traffic":       traffic,
        "anomalies":     anomalies,
        "known_alerts":  known_alerts,
        "risk_summary":  risk_summary,
        "risk_by_ip":    risk_by_ip,
        "last_updated":  int(time.time()),
        "worker_status": "running",
    }
    return snapshot, devices


# ── Background worker loop ────────────────────────────────────────────────────
def _worker_loop():
    print("[Worker] Background worker started ✅")
    devices_cache = []

    # First cycle immediately
    try:
        snap, devices_cache = _run_cycle(devices_cache)
        with _LOCK:
            _SNAPSHOT.update(snap)
        print(f"[Worker] First cycle done — "
              f"{len(snap['devices'])} devices, "
              f"{snap['traffic'].get('total_packets', 0)} pkts, "
              f"{len(snap['anomalies'])} anomalies")
    except Exception as e:
        print(f"[Worker] First cycle error: {e}")

    while True:
        time.sleep(WORKER_INTERVAL_SEC)
        try:
            snap, devices_cache = _run_cycle(devices_cache)
            with _LOCK:
                _SNAPSHOT.update(snap)
            print(f"[Worker] Cycle {_cycle_count} — "
                  f"{snap['traffic'].get('total_packets', 0)} pkts, "
                  f"{len(snap['anomalies'])} anomalies, "
                  f"risk={snap['risk_summary'].get('overall_level', '?')}")
        except Exception as e:
            print(f"[Worker] Cycle error: {e}")
            with _LOCK:
                _SNAPSHOT["worker_status"] = f"error: {e}"


# ── Public API ────────────────────────────────────────────────────────────────
def start_worker():
    """Start background worker thread — call once at Flask startup."""
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    t = threading.Thread(target=_worker_loop, daemon=True, name="ZG-Worker")
    t.start()


def get_snapshot() -> dict:
    """Returns latest snapshot instantly — no blocking."""
    with _LOCK:
        return dict(_SNAPSHOT)


# ── Drop-in compatibility alias ───────────────────────────────────────────────
def collect_all(cache_seconds=30) -> dict:
    return get_snapshot()
