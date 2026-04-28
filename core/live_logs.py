# core/live_logs.py
from collections import deque, Counter
import threading, time

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False


class LiveLogStore:
    def __init__(self, max_entries=300):
        self.lock = threading.Lock()
        self.entries = deque(maxlen=max_entries)
        self.proto_counts = Counter()
        self.ip_set = set()
        self.last_window_sec = 6
        self.last_packets = 0
        self.last_update_ts = 0

    def add_entry(self, entry, proto=None, src=None, dst=None):
        with self.lock:
            self.entries.appendleft(entry)
            if proto:
                self.proto_counts[proto] += 1
            if src:
                self.ip_set.add(src)
            if dst:
                self.ip_set.add(dst)

    def snapshot(self):
        with self.lock:
            top_proto = self.proto_counts.most_common(1)[0][0] if self.proto_counts else None
            return {
                "duration_sec": self.last_window_sec,
                "packets": self.last_packets,
                "unique_ips": len([x for x in self.ip_set if x and x != "unknown"]),
                "top_protocol": top_proto,
                "protocols": dict(self.proto_counts),
                "entries": list(self.entries),
                "last_update_ts": self.last_update_ts
            }


STORE = LiveLogStore(max_entries=300)


def _proto_from_pkt(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IPv4"
    return "OTHER"


def _ip_src_dst(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return "unknown", "unknown"


def _port(pkt):
    if pkt.haslayer(TCP):
        return int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].dport)
    return None


def _len(pkt):
    try:
        return len(bytes(pkt))
    except Exception:
        return None


def start_live_capture(interface=None, window_sec=6):
    """
    Continuous capture in background.
    Requires permissions (sudo or CAP_NET_RAW).
    """
    if not SCAPY_OK:
        raise RuntimeError("Scapy not available. Install with: pip install scapy")

    def loop():
        while True:
            start = time.time()
            local_counts = Counter()
            local_ips = set()
            local_packets = 0

            def on_pkt(pkt):
                nonlocal local_packets
                local_packets += 1
                proto = _proto_from_pkt(pkt)
                src, dst = _ip_src_dst(pkt)
                port = _port(pkt)
                ln = _len(pkt)

                local_counts[proto] += 1
                if src: local_ips.add(src)
                if dst: local_ips.add(dst)

                STORE.add_entry(
                    {
                        "time": time.strftime("%H:%M:%S"),
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "port": port if port is not None else "-",
                        "len": ln if ln is not None else "-",
                        "note": ""
                    },
                    proto=proto,
                    src=src,
                    dst=dst
                )

            # capture for window_sec (doesn't block Flask because this is a thread)
            sniff(prn=on_pkt, iface=interface, store=False, timeout=window_sec)

            # update store counters for the window
            with STORE.lock:
                STORE.proto_counts = local_counts
                STORE.ip_set = local_ips
                STORE.last_packets = local_packets
                STORE.last_window_sec = window_sec
                STORE.last_update_ts = int(time.time())

            # tiny sleep so it doesn't loop too aggressively
            elapsed = time.time() - start
            if elapsed < 0.4:
                time.sleep(0.4 - elapsed)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
