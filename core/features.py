# core/features.py
def build_features(devices, traffic):
    """
    Returns a fixed-length numeric feature vector for AI model.
    Keep this stable once you start training.
    """
    devices = devices or []
    traffic = traffic or {}

    total_packets = int(traffic.get("total_packets", 0) or 0)
    duration_sec  = float(traffic.get("duration_sec", traffic.get("duration", 0)) or 0)
    top_talkers   = traffic.get("top_talkers", []) or []
    top_protocols = traffic.get("top_protocols", []) or []

    device_count = len(devices)
    talker_count = len(top_talkers)
    proto_count  = len(top_protocols)

    # a stable “rate” feature (avoid division by zero)
    pps = (total_packets / duration_sec) if duration_sec > 0 else 0.0

    # Feature vector (simple + stable)
    return [
        float(device_count),
        float(total_packets),
        float(talker_count),
        float(proto_count),
        float(pps),
    ]
