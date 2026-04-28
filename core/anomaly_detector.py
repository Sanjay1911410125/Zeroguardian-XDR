def detect_anomalies(traffic, devices=None):
    """
    traffic: dict returned by core.packet_sniffer.capture_traffic()
    devices: list of devices from device_discovery (can be empty on hotspot)

    Returns a list of anomalies:
    [
      {"type":"High Packet Rate", "severity":"High", "details":"..."},
      ...
    ]
    """

    anomalies = []
    devices = devices or []

    duration = int(traffic.get("duration_sec", 0) or 0)
    total = int(traffic.get("total_packets", 0) or 0)
    top_protocols = traffic.get("top_protocols", []) or []
    top_talkers = traffic.get("top_talkers", []) or []

    pps = (total / duration) if duration > 0 else 0  # packets per second

    # 1) High packet rate (possible scan/flood)
    if pps >= 60:
        anomalies.append({
            "type": "High Packet Rate",
            "severity": "High",
            "details": f"{total} packets in {duration}s (~{pps:.1f} pps). Possible scan/flood."
        })
    elif pps >= 25:
        anomalies.append({
            "type": "Elevated Packet Rate",
            "severity": "Medium",
            "details": f"{total} packets in {duration}s (~{pps:.1f} pps). Monitor traffic."
        })

    # 2) Protocol dominance (too much TCP/UDP can be odd depending on env)
    proto_map = {p.get("proto"): int(p.get("count", 0) or 0) for p in top_protocols}
    if total > 0:
        for proto, cnt in proto_map.items():
            share = cnt / total
            if share >= 0.90 and cnt >= 30:
                anomalies.append({
                    "type": "Protocol Dominance",
                    "severity": "Medium",
                    "details": f"{proto} is {share*100:.0f}% of captured traffic ({cnt}/{total})."
                })

    # 3) Top talker concentration (one IP dominates)
    if top_talkers:
        top = top_talkers[0]
        top_ip = top.get("ip", "unknown")
        top_cnt = int(top.get("count", 0) or 0)
        if total > 0:
            share = top_cnt / total
            if share >= 0.85 and top_cnt >= 25:
                anomalies.append({
                    "type": "Single Talker Dominance",
                    "severity": "High",
                    "details": f"IP {top_ip} appears in {top_cnt}/{total} packets ({share*100:.0f}%)."
                })
            elif share >= 0.65 and top_cnt >= 20:
                anomalies.append({
                    "type": "Talker Concentration",
                    "severity": "Medium",
                    "details": f"IP {top_ip} appears in {top_cnt}/{total} packets ({share*100:.0f}%)."
                })

    # 4) Device discovery mismatch (if discovery works)
    # If device discovery returns 0 devices repeatedly, on normal wifi it could be scan blocked
    if len(devices) == 0:
        anomalies.append({
            "type": "Device Discovery Limited",
            "severity": "Low",
            "details": "No devices discovered. On mobile hotspot/managed Wi-Fi, scanning is often blocked."
        })

    if not anomalies:
        anomalies.append({
            "type": "No Significant Anomaly",
            "severity": "Low",
            "details": f"Traffic looks normal ({total} packets / {duration}s)."
        })

    return anomalies


if __name__ == "__main__":
    # Quick local test (requires packet_sniffer to work)
    from core.packet_sniffer import capture_traffic
    traffic = capture_traffic(duration=5, iface=None, packet_count=200)
    result = detect_anomalies(traffic, devices=[])
    for a in result:
        print(a)
