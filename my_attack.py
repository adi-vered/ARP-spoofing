import scapy.all as scapy

target_ip = "" 
self_ip = ""
interface = ""

def find_mac_address(ip):
    packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.arp(pdst = ip)
    answer = scapy.srp(packet, iface=interface, timeout=2, verbose=False)[0]
    mac_address = answer[1].hwsrc
    return mac_address
 