#!/usr/bin/env python3
# apply_patch.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Option B patch script
# Run this once from ~/ZeroGuardian-XDR/ to apply the background worker upgrade.
#
# Usage:
#   cd ~/ZeroGuardian-XDR
#   source venv/bin/activate
#   python3 apply_patch.py
# ─────────────────────────────────────────────────────────────────────────────

import os, shutil, sys

BASE    = os.path.dirname(os.path.abspath(__file__))
APP_PY  = os.path.join(BASE, "dashboard", "app.py")
ORCH_PY = os.path.join(BASE, "core", "orchestrator.py")

print("="*60)
print("  ZeroGuardian XDR — Background Worker Patch")
print("="*60)


# ── 1. Backup existing files ───────────────────────────────────────────────────
def backup(path):
    bak = path + ".bak2"
    shutil.copy2(path, bak)
    print(f"[Patch] Backed up → {bak}")

backup(APP_PY)
backup(ORCH_PY)


# ── 2. Write new orchestrator.py ──────────────────────────────────────────────
NEW_ORCHESTRATOR = '''# core/orchestrator.py
# Background Worker Orchestrator — ZeroGuardian XDR Option B
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

detector = SimpleAutoEncoderDetector()

_SNAPSHOT = {
    "devices": [], "traffic": {}, "anomalies": [],
    "known_alerts": [], "risk_summary": {
        "overall_score": 0, "overall_level": "LOW",
        "high_count": 0, "medium_count": 0, "low_count": 0, "top_risky": []
    },
    "risk_by_ip": {}, "last_updated": 0, "worker_status": "starting",
}
_LOCK = threading.Lock()
WORKER_INTERVAL_SEC = 30
DEVICE_REFRESH_EVERY = 4
_worker_started = False
_cycle_count = 0


def _read_traffic_from_store():
    try:
        from core.live_logs import STORE
        snap = STORE.snapshot()
        raw_protos = snap.get("protocols", {})
        top_protocols = [
            {"proto": k, "count": v}
            for k, v in sorted(raw_protos.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        entries = snap.get("entries", [])
        total = snap.get("packets", 0)
        ip_counter = Counter()
        ports_by_src = {}
        syn_rate = udp_rate = icmp_rate = 0

        for e in entries:
            src = e.get("src"); dst = e.get("dst")
            if src and src != "unknown": ip_counter[src] += 1
            if dst and dst != "unknown": ip_counter[dst] += 1
            proto = (e.get("proto") or "").upper()
            if proto == "UDP": udp_rate += 1
            if proto == "ICMP": icmp_rate += 1
            if "syn" in (e.get("note") or "").lower(): syn_rate += 1
            port = e.get("port")
            if src and port and str(port).isdigit():
                ports_by_src.setdefault(src, set()).add(int(port))

        top_talkers = [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(5)]
        dst_port_variety = max((len(s) for s in ports_by_src.values()), default=0)
        unique_dst = len(set(e.get("dst") for e in entries if e.get("dst") and e.get("dst") != "unknown"))
        duration = snap.get("duration_sec", WORKER_INTERVAL_SEC)

        return {
            "duration_sec": duration, "duration": duration,
            "total_packets": total, "packets": total,
            "unique_ips": snap.get("unique_ips", 0),
            "top_protocols": top_protocols, "protocols": raw_protos,
            "top_talkers": top_talkers, "entries": list(entries)[-300:],
            "udp_rate": udp_rate, "icmp_rate": icmp_rate,
            "syn_rate": syn_rate, "dst_port_variety": dst_port_variety,
            "unique_dst_ips": unique_dst, "source": "live_store",
            "last_update_ts": snap.get("last_update_ts", 0),
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


def _run_cycle(devices_cache):
    global _cycle_count
    _cycle_count += 1

    if _cycle_count % DEVICE_REFRESH_EVERY == 1 or not devices_cache:
        try:
            devices = discover_devices() or []
            print(f"[Worker] Devices: {len(devices)} found")
        except Exception as e:
            devices = devices_cache or []
    else:
        devices = devices_cache

    traffic = _read_traffic_from_store()
    anomalies = []
    known_alerts = []

    try:
        known_alerts = detect_known_threats(traffic) or []
        for k in known_alerts:
            anomalies.append({
                "type": k.get("type", "Known Threat"),
                "severity": (k.get("severity") or "MEDIUM").lower(),
                "details": k.get("details", "Matched known attack signature"),
                "source": "threat_intel",
            })
    except Exception as e:
        print(f"[Worker] Threat intel error: {e}")

    try:
        anomalies += detect_anomalies(traffic, devices) or []
    except Exception as e:
        print(f"[Worker] Anomaly detector error: {e}")

    try:
        features = build_features(devices, traffic)
        ai_result = detector.predict(features)
        top = traffic.get("top_talkers") or []
        target_ip = "unknown"
        if top:
            first = top[0]
            target_ip = (first.get("ip") or "unknown") if isinstance(first, dict) else str(first)
        device_name = "Unknown Device"
        for d in devices:
            if d.get("ip") == target_ip:
                device_name = d.get("name") or d.get("hostname") or "Unknown Device"
                break
        if ai_result["anomaly"]:
            anomalies.append({
                "type": "AI Behavioral Anomaly",
                "severity": ai_result["severity"],
                "ip": target_ip, "device": device_name,
                "score": ai_result["score"],
                "confidence": ai_result.get("confidence", 0),
                "details": ai_result.get("details", ""),
                "features": ai_result.get("features", []),
                "model": ai_result.get("model", "AutoEncoder"),
                "source": "ai",
            })
    except Exception as e:
        print(f"[Worker] AI error: {e}")

    risk_summary = {"overall_score": 0, "overall_level": "LOW",
                    "high_count": 0, "medium_count": 0, "low_count": 0, "top_risky": []}
    risk_by_ip = {}
    try:
        if compute_risk:
            risk_summary, risk_by_ip = compute_risk(devices, traffic, anomalies)
    except Exception as e:
        print(f"[Worker] Risk error: {e}")

    noisy = {"Protocol Dominance", "Single Talker Dominance"}
    anomalies = [a for a in anomalies if a.get("type") not in noisy]

    snapshot = {
        "devices": devices, "traffic": traffic, "anomalies": anomalies,
        "known_alerts": known_alerts, "risk_summary": risk_summary,
        "risk_by_ip": risk_by_ip, "last_updated": int(time.time()),
        "worker_status": "running",
    }
    return snapshot, devices


def _worker_loop():
    print("[Worker] Background worker started ✅")
    devices_cache = []
    try:
        snap, devices_cache = _run_cycle(devices_cache)
        with _LOCK:
            _SNAPSHOT.update(snap)
        print(f"[Worker] First cycle done — {len(snap[\'devices\'])} devices, "
              f"{snap[\'traffic\'].get(\'total_packets\', 0)} pkts, "
              f"{len(snap[\'anomalies\'])} anomalies")
    except Exception as e:
        print(f"[Worker] First cycle error: {e}")

    while True:
        time.sleep(WORKER_INTERVAL_SEC)
        try:
            snap, devices_cache = _run_cycle(devices_cache)
            with _LOCK:
                _SNAPSHOT.update(snap)
            print(f"[Worker] Cycle {_cycle_count} — "
                  f"{snap[\'traffic\'].get(\'total_packets\', 0)} pkts, "
                  f"{len(snap[\'anomalies\'])} anomalies")
        except Exception as e:
            print(f"[Worker] Cycle error: {e}")


def start_worker():
    global _worker_started
    if _worker_started:
        return
    _worker_started = True
    t = threading.Thread(target=_worker_loop, daemon=True, name="ZG-Worker")
    t.start()


def get_snapshot():
    with _LOCK:
        return dict(_SNAPSHOT)


def collect_all(cache_seconds=30):
    return get_snapshot()
'''

with open(ORCH_PY, "w") as f:
    f.write(NEW_ORCHESTRATOR)
print("[Patch] ✅ core/orchestrator.py rewritten")


# ── 3. Patch app.py ───────────────────────────────────────────────────────────
with open(APP_PY, "r") as f:
    content = f.read()

# Remove the old _capture_started block and replace with clean startup
OLD_BLOCK = "_capture_started = False"
NEW_BLOCK = """_systems_started = False

def start_background_systems():
    global _systems_started
    if _systems_started:
        return
    _systems_started = True
    try:
        from core.live_logs import start_live_capture
        start_live_capture(interface=CAPTURE_INTERFACE, window_sec=CAPTURE_WINDOW_SEC)
        print("[Startup] Scapy live capture started ✅")
    except Exception as e:
        print(f"[Startup] Scapy capture not started: {e}")
    try:
        from core.orchestrator import start_worker
        start_worker()
        print("[Startup] Background worker started ✅")
    except Exception as e:
        print(f"[Startup] Worker not started: {e}")"""

if OLD_BLOCK in content:
    content = content.replace(OLD_BLOCK, NEW_BLOCK, 1)
    print("[Patch] ✅ Replaced _capture_started block")
else:
    print("[Patch] ⚠️  Could not find _capture_started — please add start_background_systems() manually")

# Remove the old @app.before_request _ensure_capture_started function
import re
pattern = r"@app\.before_request\s*\ndef _ensure_capture_started\(\):.*?(?=\n@app|\nNOTIFS|\ndef |\nif )"
match = re.search(pattern, content, re.DOTALL)
if match:
    # Replace with call to our new function
    replacement = """@app.before_request
def _ensure_systems_started():
    start_background_systems()

"""
    content = content[:match.start()] + replacement + content[match.end():]
    print("[Patch] ✅ Replaced _ensure_capture_started with _ensure_systems_started")
else:
    print("[Patch] ⚠️  Could not auto-replace before_request hook — doing it safely")
    # Safe fallback: just add the call
    content = content.replace(
        "def _ensure_capture_started():",
        "def _ensure_capture_started():\n    start_background_systems()\n    return  # old logic replaced"
    )

with open(APP_PY, "w") as f:
    f.write(content)
print("[Patch] ✅ dashboard/app.py patched")


# ── 4. Done ───────────────────────────────────────────────────────────────────
print()
print("="*60)
print("  Patch complete! Now restart your app:")
print()
print("  python3 -m dashboard.app")
print()
print("  You should see:")
print("  [Startup] Scapy live capture started ✅")
print("  [Startup] Background worker started ✅")
print("  [Worker]  Background worker started ✅")
print("  [Worker]  First cycle done — X devices, Y pkts")
print("="*60)
