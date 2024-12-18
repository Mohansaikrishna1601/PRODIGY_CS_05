from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Print basic information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

        # Check for TCP or UDP and print payload if available
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"TCP Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        print("-" * 50)

def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    # Start sniffing packets
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # You can specify the network interface to sniff on, e.g., 'eth0' or 'wlan0'
    start_sniffing()