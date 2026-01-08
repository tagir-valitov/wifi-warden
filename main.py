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
from network.wifi_scanner import scan_wifi_networks, get_current_wifi

def select_network():
    log("Scanning available Wi-Fi networks...")
    networks = scan_wifi_networks()
    
    if not networks:
        log("No networks found. Using current connection.")
        current = get_current_wifi()
        if current.get('ssid'):
            log(f"Current network: {current.get('ssid')}")
        return None
    

    log("\nAvailable Wi-Fi networks:")
    log("-" * 60)
    for i, n in enumerate(networks, 1):
        ssid = n.get('ssid', '<hidden>')
        auth = n.get('auth', 'Unknown')
        signal = n.get('signal', 'Unknown')
        channel = n.get('channel', 'Unknown')
        log(f"{i}. {ssid}")
        log(f"   Auth: {auth} | Signal: {signal} | Channel: {channel}")
    

    current = get_current_wifi()
    if current.get('ssid'):
        log(f"\nCurrent network: {current.get('ssid')}")

    log("\n" + "-" * 60)
    while True:
        try:
            choice = input(f"\nSelect network to scan (1-{len(networks)}) or press ENTER to use current: ").strip()
            if not choice:
                if current.get('ssid'):
                    log(f"Using current network: {current.get('ssid')}")
                    return current.get('ssid')
                else:
                    log("No current network. Using first available.")
                    return networks[0].get('ssid')
            
            idx = int(choice) - 1
            if 0 <= idx < len(networks):
                selected = networks[idx]
                log(f"Selected network: {selected.get('ssid', '<hidden>')}")
                return selected.get('ssid')
            else:
                log(f"Please enter a number between 1 and {len(networks)}")
        except ValueError:
            log("Please enter a valid number or press ENTER")
        except KeyboardInterrupt:
            log("\nCancelled. Using current network.")
            return current.get('ssid') if current.get('ssid') else None

def run():
    log("WiFi Guard started")
    log("=" * 60)
    

    selected_network = select_network()
    if selected_network:
        log(f"\nMonitoring network: {selected_network}")
    log("=" * 60)
    
 
    log("\nStarting security monitors...")
    threading.Thread(target=start_arp_monitor, daemon=True).start()
    threading.Thread(target=start_dos_monitor, daemon=True).start()
    threading.Thread(target=start_portscan_monitor, daemon=True).start()
    threading.Thread(target=monitor_gateway, daemon=True).start()
    
    log("Monitoring for 15 seconds...")
    time.sleep(15)


    log("\nRunning security checks...")
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

    log("\n" + "=" * 60)
    log(f"RISK SCORE: {score}/100")
    log("=" * 60)
    if reasons:
        log("\nDetected issues:")
        for r in reasons:
            log(f"  - {r}")
    else:
        log("\nNo threats detected")

    input("\nPress ENTER to exit\n")

if __name__ == "__main__":
    run()
