import subprocess

def scan_wifi_networks():
    #  Тут я добавил try-except, потому что не на всех системах есть netsh (смотри main.py)
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8",
            errors="ignore"
        )
    except FileNotFoundError:
        return
    nets = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID"):
            if current:
                nets.append(current)
                current = {}
            current["ssid"] = line.split(":", 1)[1].strip()
        elif "Signal" in line:
            current["signal"] = line.split(":", 1)[1].strip()
        elif "Authentication" in line:
            current["auth"] = line.split(":", 1)[1].strip()
        elif "Channel" in line:
            current["channel"] = line.split(":", 1)[1].strip()

    if current:
        nets.append(current)

    return nets
