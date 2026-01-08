import subprocess

def scan_wifi_networks():
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            encoding="utf-8",
            errors="ignore"
        )
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
            elif "BSSID" in line:
                current["bssid"] = line.split(":", 1)[1].strip()

        if current:
            nets.append(current)

        return nets
    except Exception as e:
        return []

def get_current_wifi():
    try:
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8",
            errors="ignore"
        )
        current = {}
        for line in out.splitlines():
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if "SSID" in key and "BSSID" not in key:
                    current["ssid"] = value
                elif "Signal" in key:
                    current["signal"] = value
        return current
    except:
        return {}