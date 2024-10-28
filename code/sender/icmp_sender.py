import scapy

def send_icmp():
    # Define the destination IP (replace with the receiver container's IP)
    destination_ip = "receiver_container_ip"

    # Create an IP packet with TTL = 1
    ip_packet = scapy.IP(dst=destination_ip, ttl=1)

    # Create an ICMP packet
    icmp_packet = scapy.ICMP()

    # Combine the IP and ICMP packet
    packet = ip_packet / icmp_packet

    # Send the packet
    print("Sending ICMP packet...")
    scapy.send(packet)
    print("ICMP packet sent.")

if __name__ == "__main__":
    send_icmp()
    
# Implement your ICMP sender here
