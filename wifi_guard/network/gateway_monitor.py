import psutil
import time

gateway_changes = 0
last_gateway = None

def monitor_gateway():
    global last_gateway, gateway_changes

    while True:
        gws = psutil.net_if_stats()
        current = list(gws.keys())

        if last_gateway and current != last_gateway:
            gateway_changes += 1

        last_gateway = current
        time.sleep(10)

def is_gateway_unstable():
    return gateway_changes > 3