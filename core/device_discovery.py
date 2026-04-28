import subprocess
import socket
import re
from collections import OrderedDict

def _get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def _clean_ip(token):
    if not token:
        return token
    return token.strip().strip("()")

def _clean_ip(token):
    if not token:
        return token
    return token.strip().strip("()")

# ---------- Method 1: ARP / Neighbor discovery ----------
def discover_arp():
    devices = []
    try:
        output = subprocess.check_output(["ip", "neigh"], text=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 1:
                ip = parts[0]

                mac = None
                if "lladdr" in parts:
                    try:
                        mac = parts[parts.index("lladdr") + 1]
                    except:
                        mac = None

                devices.append({
                    "ip": ip,
                    "state": "observed",
                    "name": _get_hostname(ip) or "Unknown Device",
                    "mac": mac
                })
    except:
        pass
    return devices


# ---------- Method 2: Gateway discovery ----------
def discover_gateway():
    try:
        output = subprocess.check_output(["ip", "route"], text=True)
        for line in output.splitlines():
            if line.startswith("default"):
                gw = line.split()[2]
                return [{
                    "ip": gw,
                    "state": "gateway",
                    "name": _get_hostname(gw) or "Unknown Device"
                }]
    except:
        pass
    return []


# ---------- Method 3: Passive (self IP) ----------
def discover_self():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return [{"ip": ip, "state": "self", "name": hostname}]
    except:
        return []


# ---------- Method 4: Active scan (only if allowed) ----------
def discover_nmap():
    devices = []
    try:
        # detect current subnet automatically
        route = subprocess.check_output(["ip", "route"], text=True)

        subnet = None
        for line in route.splitlines():
            if "src" in line and "/" in line:
                subnet = line.split()[0]
                break

        if not subnet:
            return []

        output = subprocess.check_output(
            ["nmap", "-sn", "-T4", "--host-timeout", "2s", subnet],
            text=True
        )

        for line in output.splitlines():
            if "Nmap scan report for" in line:
                # formats:
                # 1) Nmap scan report for NAME (10.0.0.5)
                # 2) Nmap scan report for 10.0.0.5
                m = re.search(r"Nmap scan report for\s+(.*)", line)
                if not m:
                    continue

                tail = m.group(1).strip()

                name = None
                ip = None

                m2 = re.search(r"(.+)\s+\(([\d\.]+)\)$", tail)
                if m2:
                    name = m2.group(1).strip()
                    ip = m2.group(2).strip()
                else:
                    ip = _clean_ip(tail)

                if not ip:
                    continue

                hostname = _get_hostname(ip)
                final_name = hostname or name or "Unknown Device"

                devices.append({"ip": ip, "state": "lan", "name": final_name})

    except:
        pass

    return devices


# ---------- Combine everything ----------
def discover_devices():
    devices = []
    devices += discover_self()
    devices += discover_gateway()
    devices += discover_arp()
    devices += discover_nmap()

    # remove duplicates
    unique = OrderedDict()
    for d in devices:
        unique[d["ip"]] = d

    return list(unique.values())
