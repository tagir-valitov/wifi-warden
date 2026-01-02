from scapy.all import sniff, TCP, IP
import time

scan_data = {}
scan_detected = False

THRESHOLD = 20
INTERVAL = 10

def process_packet(pkt):
    global scan_detected

    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        port = pkt[TCP].dport

        now = time.time()
        scan_data.setdefault(src, []).append((port, now))

        scan_data[src] = [(p, t) for p, t in scan_data[src] if now - t < INTERVAL]

        ports = {p for p, _ in scan_data[src]}
        if len(ports) > THRESHOLD:
            scan_detected = True

def start_portscan_monitor():
    sniff(prn=process_packet, store=False)

def is_portscan_detected():
    return scan_detected