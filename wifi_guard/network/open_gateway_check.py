import socket
import subprocess
import sys

PORTS = {80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet"}

def get_gateway():
    if sys.platform.startswith("win"):
        out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
        for line in out.splitlines():
            if "Default Gateway" in line and ":" in line:
                gw = line.split(":")[-1].strip()
                if gw:
                    return gw
    return None

def check_open_gateway():
    gw = get_gateway()
    if not gw:
        return False, []

    reasons = []
    for p in PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((gw, p)) == 0:
            reasons.append(f"Gateway open port {p} ({PORTS[p]})")
        s.close()

    return bool(reasons), reasons