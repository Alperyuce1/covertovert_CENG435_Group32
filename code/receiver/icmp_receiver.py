import scapy
from scapy.all import sniff, IP, ICMP

def handle_packet(packet):
    if IP in packet and ICMP in packet:
        
        if packet[ICMP].type == 8:
            packet.show()

def receive_icmp():
    
    sniff(filter="icmp", prn=handle_packet, count=1)

if __name__ == "__main__":
    receive_icmp()


