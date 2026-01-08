import subprocess
import sys
import time

gateway_changes = 0
last_gateway = None

def get_gateway_ip():
    if sys.platform.startswith("win"):
        try:
            out = subprocess.check_output("ipconfig", shell=True).decode(errors="ignore")
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if gw and gw != "---":
                        return gw
        except:
            pass
    return None

def monitor_gateway():
    global last_gateway, gateway_changes

    while True:
        current_gateway = get_gateway_ip()

        if current_gateway:
            if last_gateway and last_gateway != current_gateway:
                gateway_changes += 1
            last_gateway = current_gateway

        time.sleep(10)

def is_gateway_unstable():
    return gateway_changes > 3