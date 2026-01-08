from scapy.all import sniff, IP, TCP, UDP
import time

packet_count = 0
dos_detected = False
START = time.time()

THRESHOLD = 300
INTERVAL = 10

def process(pkt):
    global packet_count, dos_detected, START

    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        packet_count += 1

    if time.time() - START > INTERVAL:
        if packet_count > THRESHOLD:
            dos_detected = True
        packet_count = 0
        START = time.time()

def start_dos_monitor():
    sniff(prn=process, store=False)

def is_dos_detected():
    return dos_detected