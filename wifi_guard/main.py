import threading
import time

from utils.logger import log
from risk_engine import calculate_risk

from network.arp_monitor import start_arp_monitor, is_arp_attack
from network.dns_check import check_dns_spoof
from network.tls_check import check_tls
from network.dos_monitor import start_dos_monitor, is_dos_detected
from network.portscan_monitor import start_portscan_monitor, is_portscan_detected
from network.gateway_monitor import monitor_gateway, is_gateway_unstable
from network.open_gateway_check import check_open_gateway
from network.wifi_scanner import scan_wifi_networks

def run():
    log("WiFi Guard started")

    threading.Thread(target=start_arp_monitor, daemon=True).start()
    threading.Thread(target=start_dos_monitor, daemon=True).start()
    threading.Thread(target=start_portscan_monitor, daemon=True).start()
    threading.Thread(target=monitor_gateway, daemon=True).start()

    log("Nearby Wi-Fi networks:")
    for n in scan_wifi_networks():
        log(f"{n.get('ssid','<hidden>')} | {n.get('auth')} | {n.get('signal')}")

    time.sleep(15)

    og, og_reasons = check_open_gateway()

    events = {
        "arp": is_arp_attack(),
        "dns": check_dns_spoof("google.com"),
        "tls": check_tls("google.com"),
        "dos": is_dos_detected(),
        "portscan": is_portscan_detected(),
        "gateway": is_gateway_unstable(),
        "open_gateway": og_reasons if og else False
    }

    score, reasons = calculate_risk(events)

    log(f"RISK SCORE: {score}/100")
    for r in reasons:
        log(f"- {r}")

    input("\nPress ENTER to exit\n")

if __name__ == "__main__":
    run()