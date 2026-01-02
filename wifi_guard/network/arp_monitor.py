from scapy.all import sniff, ARP
import time
arp_table = {}
arp_attack_detected = False

def process_arp(packet):
    global arp_attack_detected
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ip in arp_table and arp_table[ip] != mac:
            arp_attack_detected = True
        arp_table[ip] = mac
def start_arp_monitor():
    sniff(filter="arp", prn=process_arp, store=False)
def is_arp_attack():
    return arp_attack_detected