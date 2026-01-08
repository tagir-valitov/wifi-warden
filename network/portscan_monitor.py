from scapy.all import sniff, TCP, IP
import time

scan_data = {}
scan_detected = False

THRESHOLD = 20
INTERVAL = 10

def is_syn_packet(pkt):
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return False
    
    flags = pkt[TCP].flags
    if isinstance(flags, str):
        return "S" in flags and "A" not in flags
    else:
        return (flags & 0x02) != 0 and (flags & 0x10) == 0

def process_packet(pkt):
    global scan_detected

    if is_syn_packet(pkt):
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