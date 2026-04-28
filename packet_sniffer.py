def extract_ips(packets):
    ips = set()
    for pkt in packets:
        if "src" in pkt:
            ips.add(pkt["src"])
        if "dst" in pkt:
            ips.add(pkt["dst"])
    return [{"ip": ip, "state": "observed"} for ip in ips]
