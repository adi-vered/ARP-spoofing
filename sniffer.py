import scapy.all as scapy
from scapy.layers import http

def sniff_packets(interface):
    scapy.sniff(store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"url is {url}")
        cred = get_credentials(packet)
        if cred:
            print("Print possible credential info")

sniff_packets("Ether")
# print(scapy.interfaces.get_if_list())