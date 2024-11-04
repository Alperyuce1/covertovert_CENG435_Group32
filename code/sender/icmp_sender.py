import scapy
from scapy.all import ICMP, IP, send
def send_icmp():

    destination_ip = "172.18.0.2"

    ip_packet = IP(dst=destination_ip, ttl=1)

    icmp_packet = ICMP()

    packet = ip_packet / icmp_packet

    send(packet)

if __name__ == "__main__":
    send_icmp()

