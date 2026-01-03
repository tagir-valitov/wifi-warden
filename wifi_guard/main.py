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

#  ПРОСТО ПРИМЕР, как можно сделать прогрессбар (используется в run()).
def progressbar(delay: int, width: int = 50) -> None:
    def render(passed: int) -> str:
        return '[' + '#' * passed + ' ' * (width - passed) + ']'

    print(render(0), end='', flush=True)
    for i in range(1, delay * 2 + 1):
        time.sleep(0.5)
        passed = width * i // (delay * 2)
        print('\r' + render(passed), end='', flush=True)
    print()


def run():
    log("WiFi Guard started")

    threading.Thread(target=start_arp_monitor, daemon=True).start()
    threading.Thread(target=start_dos_monitor, daemon=True).start()
    threading.Thread(target=start_portscan_monitor, daemon=True).start()
    threading.Thread(target=monitor_gateway, daemon=True).start()

    #  У меня нет netsh (у меня ж линукс как никак), поэтому scan_wifi_networks
    #  ошибался и всё падало. Я пока проверочку оставил:
    log("Nearby Wi-Fi networks:")
    networks = scan_wifi_networks()
    if networks is None:
        log('Unavailable')
    else:
        for n in networks:
            log(f"{n.get('ssid','<hidden>')} | {n.get('auth')} | {n.get('signal')}")

    #  Здесь хочется прогрессбар
    log("Scanning the network...")
    progressbar(15)

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
