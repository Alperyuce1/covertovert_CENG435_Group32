import scapy

def handle_packet(packet):
    if scapy.IP in packet and scapy.ICMP in packet:
        # Check if it is an ICMP request (Type 8 is Echo Request)
        if packet[scapy.ICMP].type == 8:
            print("Received ICMP request packet:")
            packet.show()

def receive_icmp():
    print("Listening for ICMP packets...")
    # Capture ICMP packets
    scapy.sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    receive_icmp()
    
# Implement your ICMP receiver here
