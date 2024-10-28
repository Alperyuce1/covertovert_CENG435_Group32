from scapy.all import sniff, IP, ICMP

def handle_packet(packet):
    if IP in packet and ICMP in packet:
        # Check if it is an ICMP request (Type 8 is Echo Request)
        if packet[ICMP].type == 8:
            print("Received ICMP request packet:")
            packet.show()

def receive_icmp():
    print("Listening for ICMP packets...")
    # Capture ICMP packets
    sniff(filter="icmp", prn=handle_packet)

if __name__ == "__main__":
    receive_icmp()
# Implement your ICMP receiver here
