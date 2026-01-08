from scapy.all import sniff, ARP
import time

arp_table = {}
mac_to_ips = {}
arp_attack_detected = False

def process_arp(packet):
    global arp_attack_detected
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        

        if ip in arp_table and arp_table[ip] != mac:
            arp_attack_detected = True
        if mac in mac_to_ips:
            mac_to_ips[mac].add(ip)
            if len(mac_to_ips[mac]) > 3:
                arp_attack_detected = True
        else:
            mac_to_ips[mac] = {ip}
        

        old_mac = arp_table.get(ip)
        if old_mac and old_mac in mac_to_ips:
            mac_to_ips[old_mac].discard(ip)
            if not mac_to_ips[old_mac]:
                del mac_to_ips[old_mac]
        
        arp_table[ip] = mac

def start_arp_monitor():
    sniff(filter="arp", prn=process_arp, store=False)

def is_arp_attack():
    return arp_attack_detected