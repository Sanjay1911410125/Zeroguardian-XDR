#!/usr/bin/env python3
# simulator/simulate.py
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Zero-Day Attack Simulator
# Injects realistic malicious traffic patterns into your loopback interface
# so the detection pipeline can identify them without touching real networks.
#
# Usage (from ~/ZeroGuardian-XDR/):
#   source venv/bin/activate
#   sudo python3 simulator/simulate.py
#
# All traffic goes to 127.0.0.1 (loopback) — safe, self-contained, VM-only.
# ─────────────────────────────────────────────────────────────────────────────

import os, sys, time, random, argparse

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
        send, RandShort, conf
    )
    conf.verb = 0          # suppress scapy output
except ImportError:
    print("[Simulator] ERROR: Scapy not found. Run: pip install scapy")
    sys.exit(1)

TARGET   = "127.0.0.1"    # loopback — never touches real network
SRC_BASE = "10.0.0."      # spoofed source IPs for realism


def _rand_src():
    return SRC_BASE + str(random.randint(2, 254))

def _log(scenario, msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] [{scenario}] {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 1 — Stealth Port Scan (SYN scan across many ports)
# Indicator: dst_port_variety spike from a single source IP
# ─────────────────────────────────────────────────────────────────────────────
def scenario_port_scan(count=120, delay=0.02):
    _log("PORT-SCAN", f"Sending SYN scan across {count} ports → {TARGET}")
    src = _rand_src()

    # Common + unusual ports to trigger dst_port_variety detection
    ports = list(range(20, 25)) + list(range(79, 83)) + \
            [135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080, 8443] + \
            random.sample(range(1024, 65535), max(0, count - 50))
    ports = ports[:count]

    for port in ports:
        pkt = IP(src=src, dst=TARGET) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(delay)

    _log("PORT-SCAN", f"Done — {len(ports)} SYN packets sent from {src}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 2 — Brute Force Login (rapid TCP connections to SSH / HTTP)
# Indicator: high SYN rate to a single port, many failed attempt patterns
# ─────────────────────────────────────────────────────────────────────────────
def scenario_brute_force(count=80, port=22, delay=0.03):
    _log("BRUTE-FORCE", f"Simulating {count} login attempts → {TARGET}:{port}")
    src = _rand_src()

    for i in range(count):
        # SYN (connection attempt)
        pkt = IP(src=src, dst=TARGET) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt, verbose=0)

        # Simulate immediate RST (failed auth = connection reset)
        rst = IP(src=src, dst=TARGET) / TCP(sport=RandShort(), dport=port, flags="R")
        send(rst, verbose=0)

        time.sleep(delay)
        if (i + 1) % 20 == 0:
            _log("BRUTE-FORCE", f"  {i+1}/{count} attempts sent …")

    _log("BRUTE-FORCE", f"Done — {count} failed connections to port {port}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 3 — C2 Beaconing (periodic callbacks to simulate malware check-in)
# Indicator: regular interval TCP/UDP packets to unusual ports
# ─────────────────────────────────────────────────────────────────────────────
def scenario_c2_beacon(cycles=12, interval=3.0, port=4444):
    _log("C2-BEACON", f"Starting {cycles} beacon cycles to {TARGET}:{port} "
                      f"(every {interval}s)")
    src = _rand_src()

    for i in range(cycles):
        # Beacon packet with simulated encoded payload
        payload = f"BEACON|id={random.randint(1000,9999)}|ts={int(time.time())}|ok"
        pkt = IP(src=src, dst=TARGET) / \
              TCP(sport=RandShort(), dport=port, flags="PA") / \
              Raw(load=payload.encode())
        send(pkt, verbose=0)

        _log("C2-BEACON", f"  Beacon {i+1}/{cycles} sent (payload: {len(payload)} bytes)")
        time.sleep(interval)

    _log("C2-BEACON", f"Done — {cycles} beacons sent from {src}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 4 — DNS Exfiltration (data encoded in DNS query subdomains)
# Indicator: high DNS query rate, long subdomain names, unusual query patterns
# ─────────────────────────────────────────────────────────────────────────────
def scenario_dns_exfil(chunks=40, delay=0.1):
    _log("DNS-EXFIL", f"Simulating DNS tunnel exfiltration — {chunks} queries")
    src = _rand_src()

    # Simulate base64-encoded data chunks in DNS subdomains
    import base64
    fake_data = b"SENSITIVE_INTERNAL_DATA_EXFILTRATION_SIMULATION_" * 3

    chunk_size = 30
    for i in range(chunks):
        start  = (i * chunk_size) % len(fake_data)
        chunk  = fake_data[start:start + chunk_size]
        encoded = base64.b32encode(chunk).decode().lower().rstrip("=")

        # DNS query: <encoded_data>.<seq>.<c2domain>.com
        qname = f"{encoded}.{i:04d}.c2-malware-sim.example.com."

        pkt = IP(src=src, dst=TARGET) / \
              UDP(sport=RandShort(), dport=53) / \
              DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        send(pkt, verbose=0)
        time.sleep(delay)

        if (i + 1) % 10 == 0:
            _log("DNS-EXFIL", f"  {i+1}/{chunks} DNS queries sent …")

    _log("DNS-EXFIL", f"Done — {chunks} DNS exfil packets from {src}")


# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO 5 — Rogue Device / Traffic Spike (unknown IP floods network)
# Indicator: new IP not in device list, high packet rate, traffic spike
# ─────────────────────────────────────────────────────────────────────────────
def scenario_rogue_device(count=200, delay=0.01):
    _log("ROGUE-DEVICE", f"Simulating rogue device traffic spike — {count} packets")

    # Use an IP that will not appear in your normal device list
    rogue_ip = "10.99.88.77"

    for i in range(count):
        proto = random.choice(["tcp", "udp", "icmp"])
        if proto == "tcp":
            pkt = IP(src=rogue_ip, dst=TARGET) / \
                  TCP(sport=RandShort(), dport=random.randint(1024, 9000), flags="S")
        elif proto == "udp":
            pkt = IP(src=rogue_ip, dst=TARGET) / \
                  UDP(sport=RandShort(), dport=random.randint(1024, 9000)) / \
                  Raw(load=os.urandom(random.randint(64, 512)))
        else:
            pkt = IP(src=rogue_ip, dst=TARGET) / ICMP()

        send(pkt, verbose=0)
        time.sleep(delay)

        if (i + 1) % 50 == 0:
            _log("ROGUE-DEVICE", f"  {i+1}/{count} packets sent from {rogue_ip} …")

    _log("ROGUE-DEVICE", f"Done — {count} packets from rogue IP {rogue_ip}")


# ─────────────────────────────────────────────────────────────────────────────
# MENU
# ─────────────────────────────────────────────────────────────────────────────
SCENARIOS = {
    "1": ("Stealth port scan",          scenario_port_scan),
    "2": ("SSH brute force",            scenario_brute_force),
    "3": ("C2 beaconing",               scenario_c2_beacon),
    "4": ("DNS data exfiltration",      scenario_dns_exfil),
    "5": ("Rogue device traffic spike", scenario_rogue_device),
    "6": ("Run ALL scenarios (full demo)", None),
}

def run_all():
    for key in ("1", "2", "3", "4", "5"):
        name, fn = SCENARIOS[key]
        print(f"\n{'='*60}")
        print(f" Running: {name}")
        print(f"{'='*60}")
        fn()
        print(f"[Simulator] Pausing 5s before next scenario …")
        time.sleep(5)


def menu():
    print("\n" + "="*60)
    print("  ZeroGuardian XDR — Zero-Day Attack Simulator")
    print("  All traffic → loopback (127.0.0.1) — VM safe")
    print("="*60)
    for k, (name, _) in SCENARIOS.items():
        print(f"  [{k}] {name}")
    print("  [q] Quit")
    print("="*60)

    choice = input("  Select scenario: ").strip().lower()

    if choice == "q":
        print("[Simulator] Exiting.")
        sys.exit(0)
    elif choice == "6":
        run_all()
    elif choice in SCENARIOS:
        name, fn = SCENARIOS[choice]
        print(f"\n[Simulator] Starting: {name}\n")
        fn()
    else:
        print("[Simulator] Invalid choice.")

    input("\n[Simulator] Press Enter to return to menu …")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ZeroGuardian XDR Simulator")
    parser.add_argument("--scenario", type=str, default=None,
                        help="Run scenario directly: 1-5 or all")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[Simulator] WARNING: Not running as root — packet sending may fail.")
        print("            Run with: sudo python3 simulator/simulate.py")

    if args.scenario:
        s = args.scenario.strip()
        if s == "all":
            run_all()
        elif s in SCENARIOS and s != "6":
            _, fn = SCENARIOS[s]
            fn()
        else:
            print(f"[Simulator] Unknown scenario '{s}'. Use 1-5 or all.")
    else:
        while True:
            menu()
