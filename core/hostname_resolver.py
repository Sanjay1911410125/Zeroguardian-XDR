import re
import socket
import subprocess

def _run(cmd, timeout=6):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return (p.stdout or "").strip()
    except Exception:
        return ""

def resolve_reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host or ""
    except Exception:
        return ""

def resolve_nmap_name(ip: str) -> str:
    # nmap -sn prints: "Nmap scan report for NAME (IP)" OR "Nmap scan report for IP"
    out = _run(["sudo", "nmap", "-sn", ip], timeout=10)
    m = re.search(r"Nmap scan report for\s+(.+?)\s+\(" + re.escape(ip) + r"\)", out)
    if m:
        name = m.group(1).strip()
        # avoid returning ip itself
        if name and name != ip:
            return name
    return ""

def resolve_mdns(ip: str) -> str:
    # Avahi is not IP-based directly; we do a quick browse and try to find a .local name tied to the IP.
    # This is a best-effort approach.
    out = _run(["avahi-browse", "-art"], timeout=8)
    # Often contains hostnames with .local; IP mapping is not always shown.
    # We'll just return first reasonable hostname if any line hints at it.
    for line in out.splitlines():
        if ".local" in line:
            # grab something like "DeviceName.local"
            m = re.search(r"([A-Za-z0-9\-_]+\.local)", line)
            if m:
                return m.group(1)
    return ""

def resolve_netbios(ip: str) -> str:
    out = _run(["sudo", "nbtscan", "-q", ip], timeout=8)
    # nbtscan output can vary; look for something that looks like a name token
    # Example: "10.0.0.5   MYPC   <server> ..."
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == ip:
            name = parts[1].strip()
            if name and name != ip:
                return name
    return ""

def resolve_hostname(ip: str) -> str:
    # Fast → slower fallbacks
    for fn in (resolve_reverse_dns, resolve_nmap_name, resolve_netbios, resolve_mdns):
        name = fn(ip)
        if name:
            return name
    return ""
