import time

# Risk bands
def risk_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


# Common risky ports (simple but effective)
RISKY_PORTS = {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900}


def _safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default


def _device_key(d):
    # supports both dict + object
    return getattr(d, "ip", None) or (d.get("ip") if isinstance(d, dict) else None)


def _device_state(d):
    return getattr(d, "state", None) or (d.get("state", "unknown") if isinstance(d, dict) else "unknown")


def compute_risk(devices, traffic: dict, anomalies: list, port_scan: dict | None = None):
    """
    devices: list of dicts like {"ip": "...", "state": "lan/observed/gateway/self"}
    traffic: dict like {"total_packets": 123, "top_talkers": [{"ip": "...", "count": 50}], "external_ip_count": 6}
    anomalies: list like [{"ip": "...", "severity": "low/med/high", "score": 0-100, "reason": "..."}]
    port_scan: optional dict {"ip": [22, 80, 445], ...}
    """

    port_scan = port_scan or {}

    # Build per-device structure
    per_ip = {}
    for d in (devices or []):
        ip = _device_key(d)
        if not ip:
            continue
        per_ip[ip] = {
            "ip": ip,
            "state": _device_state(d),
            "score": 0,
            "level": "LOW",
            "reasons": [],
            "updated_ts": int(time.time())
        }

    # If nothing discovered at all, return safe empty structure
    if not per_ip:
        summary = {
            "overall_score": 0,
            "overall_level": "LOW",
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "top_risky": []
        }
        return summary, {}

    # --- Weight components ---
    # 40% anomaly, 25% risky ports, 25% traffic behavior, 10% threat intel (future -> 0 now)

    # 1) ANOMALY contribution (per device)
    sev_weight = {"low": 10, "medium": 25, "med": 25, "high": 40, "critical": 50}

    for a in (anomalies or []):
        if not isinstance(a, dict):
            continue
        ip = a.get("ip")
        if not ip or ip not in per_ip:
            continue

        sev = (a.get("severity") or "low").lower()
        add = sev_weight.get(sev, 10)

        # if anomaly has numeric score, blend it a bit
        a_score = a.get("score")
        if a_score is not None:
            add = max(add, min(50, int(_safe_int(a_score) * 0.5)))

        per_ip[ip]["score"] += add
        per_ip[ip]["reasons"].append(f"Anomaly detected ({sev}) +{add}")

    # 2) PORT risk (optional)
    for ip, ports in (port_scan or {}).items():
        if ip not in per_ip:
            continue
        if not isinstance(ports, (list, tuple, set)):
            continue

        risky = [p for p in ports if _safe_int(p) in RISKY_PORTS]
        if risky:
            add = min(25, 5 + len(set(risky)) * 4)  # capped
            per_ip[ip]["score"] += add
            per_ip[ip]["reasons"].append(f"Risky services exposed {sorted(set(risky))} +{add}")

    # 3) TRAFFIC behavior (top talkers + external connections)
    top_talkers = traffic.get("top_talkers", []) if isinstance(traffic, dict) else []
    external_ip_count = _safe_int(traffic.get("external_ip_count", 0)) if isinstance(traffic, dict) else 0
    total_packets = _safe_int(traffic.get("total_packets", 0)) if isinstance(traffic, dict) else 0

    # mark heavy talkers
    if isinstance(top_talkers, list):
        for t in top_talkers[:10]:
            if not isinstance(t, dict):
                continue
            tip = t.get("ip")
            cnt = _safe_int(t.get("count", 0))
            if tip in per_ip and cnt > 0:
                add = min(20, max(3, cnt // 20))  # scaled but capped
                per_ip[tip]["score"] += add
                per_ip[tip]["reasons"].append(f"High traffic volume ({cnt} pkts) +{add}")

    # external connections affect overall risk; add small portion to all observed devices
    if external_ip_count > 0:
        add_all = min(10, 2 + external_ip_count // 3)
        for ip in per_ip:
            per_ip[ip]["score"] += add_all

    # 4) STATE influence (gateway/self lower baseline)
    for ip, info in per_ip.items():
        st = info.get("state", "unknown")
        if st == "gateway":
            info["score"] = max(0, info["score"] - 10)
            info["reasons"].append("Gateway device (lowered baseline) -10")
        if st == "self":
            info["score"] = max(0, info["score"] - 5)
            info["reasons"].append("Local host (lowered baseline) -5")

    # clamp 0..100 + add levels
    for ip, info in per_ip.items():
        info["score"] = max(0, min(100, int(info["score"])))
        info["level"] = risk_level(info["score"])

        if not info["reasons"]:
            # baseline reasons for explainability
            if total_packets == 0:
                info["reasons"].append("No traffic/anomaly evidence yet (baseline low risk)")
            else:
                info["reasons"].append("Normal behavior observed (baseline)")

    # summary metrics
    scores = [v["score"] for v in per_ip.values()]
    overall = int(sum(scores) / max(1, len(scores)))
    overall_level = risk_level(overall)

    high = sum(1 for v in per_ip.values() if v["level"] == "HIGH")
    med = sum(1 for v in per_ip.values() if v["level"] == "MEDIUM")
    low = sum(1 for v in per_ip.values() if v["level"] == "LOW")

    top_risky = sorted(per_ip.values(), key=lambda x: x["score"], reverse=True)[:5]
    if external_ip_count > 0:
        for item in top_risky:
            item["reasons"].append(f"External connections observed ({external_ip_count}) +shared")

    summary = {
        "overall_score": overall,
        "overall_level": overall_level,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "top_risky": top_risky
    }

    return summary, per_ip

def save_risk_snapshot(risk_summary, risk_by_ip):
    # demo mode: no DB yet
    return
