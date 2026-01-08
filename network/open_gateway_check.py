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
    elif sys.platform.startswith("linux"):
        out = subprocess.check_output("ip route list default", shell=True).decode(errors="ignore")
        for line in out.splitlines():
            if "default" in line:
                line = line.split()
                via = -1
                for i, word in enumerate(line):
                    if word == 'via':
                        via = i
                        break
                if via != -1:
                    return line[via + 1]
    return None

def check_open_gateway():
    gw = get_gateway()
    if not gw:
        return False, ["Не удалось определить шлюз"]
    reasons = []
    for p in PORTS:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((gw, p)) == 0:
            reasons.append(f"Gateway open port {p} ({PORTS[p]})")
        s.close()

    dangerous_ports = [22, 23]
    is_dangerous = False

    for p in dangerous_ports:
        s = socket.socket()
        s.settimeout(1)
        if s.connect_ex((gw, p)) == 0:
            is_dangerous = True
        s.close()

    return is_dangerous, reasons