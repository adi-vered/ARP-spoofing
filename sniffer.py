import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    print("new packet")
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"url is {url}")
        cred = get_credentials(packet)
        if cred:
            print("Print possible credential info")

sniff("Wi-Fi")
