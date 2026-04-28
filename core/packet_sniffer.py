import subprocess
import time
import re
from collections import Counter

def capture_traffic(duration=2, iface=None, packet_count=200):
    """
    Captures live traffic using tcpdump (requires sudo).
    Returns:
      {
        "duration_sec": int,
        "total_packets": int,
        "top_protocols": [{"proto":"TCP","count":..}, ...],
        "top_talkers": [{"ip":"x.x.x.x","count":..}, ...],
        "entries": [{"time":..,"src":..,"dst":..,"proto":..,"port":..,"len":..,"note":..}, ...]
      }
    """
    cmd = ["sudo", "tcpdump", "-n", "-l", "-q", "-c", str(packet_count)]
    if iface:
        cmd += ["-i", iface]

    start = time.time()
    out_lines = []

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # read for duration seconds or until process ends
        while True:
            if proc.poll() is not None:
                break
            if time.time() - start >= duration:
                proc.terminate()
                break
            line = proc.stdout.readline()
            if line:
                out_lines.append(line.strip())

        # ensure process exits
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()

    except Exception as e:
        return {
            "duration_sec": duration,
            "total_packets": 0,
            "top_protocols": [],
            "top_talkers": [],
            "entries": [],
            "error": str(e),
        }

    # Parse results
    proto_counter = Counter()
    ip_counter = Counter()
    entries = []

    for line in out_lines:
        # Protocol hints
        if "IP6" in line:
            proto_counter["IPv6"] += 1
        elif "IP " in line:
            proto_counter["IPv4"] += 1

        if " TCP" in line or "tcp" in line:
            proto_counter["TCP"] += 1
        elif " UDP" in line or "udp" in line:
            proto_counter["UDP"] += 1
        elif " ICMP" in line or "icmp" in line:
            proto_counter["ICMP"] += 1

        # Extract talker IPs (source -> destination)
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)', line)
        if m:
            src_ip = m.group(1)
            src_port = m.group(2)
            dst_ip = m.group(3)
            dst_port = m.group(4)

            ip_counter[src_ip] += 1
            ip_counter[dst_ip] += 1

            proto = "IPv4"
            if "IP6" in line:
                proto = "IPv6"
            if " TCP" in line or "tcp" in line:
                proto = "TCP"
            elif " UDP" in line or "udp" in line:
                proto = "UDP"
            elif " ICMP" in line or "icmp" in line:
                proto = "ICMP"

            # Packet length at end like "length 78"
            ln = None
            lm = re.search(r'length\s+(\d+)', line)
            if lm:
                try:
                    ln = int(lm.group(1))
                except Exception:
                    ln = None

            # note based on common ports
            note = ""
            try:
                p = int(dst_port)
                if p == 53:
                    note = "DNS"
                elif p == 80:
                    note = "HTTP"
                elif p == 443:
                    note = "HTTPS/TLS"
                elif p == 22:
                    note = "SSH"
                elif p == 123:
                    note = "NTP"
            except Exception:
                note = ""

            # best-effort SYN hint if tcpdump contains flags
            if "Flags [S" in line or "Flags [S]" in line:
                note = (note + " " if note else "") + "SYN"

            entries.append({
                "time": time.strftime("%H:%M:%S"),
                "src": src_ip,
                "dst": dst_ip,
                "proto": proto,
                "port": int(dst_port) if str(dst_port).isdigit() else dst_port,
                "dport": int(dst_port) if str(dst_port).isdigit() else dst_port,
                "len": ln if ln is not None else "",
                "note": note
            })

        else:
            # fallback when ports not present (ICMP etc.)
            m2 = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})', line)
            if m2:
                src_ip = m2.group(1)
                dst_ip = m2.group(2)

                ip_counter[src_ip] += 1
                ip_counter[dst_ip] += 1

                proto = "IPv4"
                if "IP6" in line:
                    proto = "IPv6"
                if " ICMP" in line or "icmp" in line:
                    proto = "ICMP"

                ln = None
                lm = re.search(r'length\s+(\d+)', line)
                if lm:
                    try:
                        ln = int(lm.group(1))
                    except Exception:
                        ln = None

                entries.append({
                    "time": time.strftime("%H:%M:%S"),
                    "src": src_ip,
                    "dst": dst_ip,
                    "proto": proto,
                    "port": "",
                    "dport": "",
                    "len": ln if ln is not None else "",
                    "note": ""
                })

    total_packets = len(out_lines)

    top_protocols = [{"proto": k, "count": v} for k, v in proto_counter.most_common(5)]
    top_talkers = [{"ip": k, "count": v} for k, v in ip_counter.most_common(5)]

    # ----------- ADDED METRICS FOR SIGNATURE-BASED ATTACKS -----------
    udp_rate = 0
    icmp_rate = 0
    syn_rate = 0

    ports_by_src = {}
    unique_dst_ips_set = set()

    for e in entries:
        p = (e.get("proto") or "").upper()
        if p == "UDP":
            udp_rate += 1
        if p == "ICMP":
            icmp_rate += 1

        nt = (e.get("note") or "").lower()
        if "syn" in nt:
            syn_rate += 1

        src = e.get("src")
        dport = e.get("dport")
        if src and dport and str(dport).isdigit():
            ports_by_src.setdefault(src, set()).add(int(dport))

        dst = e.get("dst")
        if dst:
            unique_dst_ips_set.add(dst)

    dst_port_variety = 0
    if ports_by_src:
        dst_port_variety = max(len(s) for s in ports_by_src.values())

    unique_dst_ips = len(unique_dst_ips_set)
    # ---------------------------------------------------------------

    return {
        "duration_sec": duration,
        "total_packets": total_packets,
        "top_protocols": top_protocols,
        "top_talkers": top_talkers,
        "entries": entries[-300:],

        # metrics used by threat_signatures (indicator column)
        "udp_rate": udp_rate,
        "icmp_rate": icmp_rate,
        "syn_rate": syn_rate,
        "dst_port_variety": dst_port_variety,
        "unique_dst_ips": unique_dst_ips,
    }


if __name__ == "__main__":
    print("Capturing traffic (requires sudo)...")
    data = capture_traffic(duration=5, iface=None, packet_count=200)
    print(data)
