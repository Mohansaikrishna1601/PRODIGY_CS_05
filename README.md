# Packet Sniffer

## Description
This Python script implements a simple packet sniffer using the `scapy` library. The packet sniffer captures and logs network packets, displaying information such as source and destination IP addresses, protocols, and payloads for TCP and UDP packets.

## Features
- Packet Capture: Captures network packets in real-time.
- Detailed Information: Displays source IP, destination IP, protocol, source port, destination port, and payload (if available) for each packet.
- Supports TCP and UDP: Handles both TCP and UDP packets, providing relevant details.

## How It Works
- IP Layer: Checks if the packet has an IP layer and extracts source IP, destination IP, and protocol.
- TCP and UDP: For TCP and UDP packets, it extracts source and destination ports. If the packet contains raw data, it prints the payload.
- Packet Sniffing: Utilizes the `scapy.sniff` function to capture packets from the specified network interface.

## Code Explanation
- **packet_callback(packet)**: 
  - Checks if the packet contains an IP layer.
  - Extracts and prints source IP, destination IP, and protocol.
  - For TCP packets: Extracts and prints source port, destination port, and payload (if available).
  - For UDP packets: Extracts and prints source port, destination port, and payload (if available).
  - Prints a separator line for readability.

- **start_sniffing(interface=None)**:
  - Starts packet sniffing on the specified network interface or the default interface.
  - Calls the `packet_callback` function for each captured packet.

## Usage
### Clone the Repository

    git clone https://github.com/Mohansaikrishna1601/PRODIGY_CS_01.git
    cd PRODIGY_CS_01

### Install Required Libraries
    pip install scapy

### Run the Script
    python packet_sniffer.py
    
### Stop the Packet Sniffer
    Press Ctrl+C to stop the packet sniffer gracefully.

### Example
Starting packet sniffing...

Source IP: 192.168.0.1, Destination IP: 192.168.0.2, Protocol: 6

TCP Source Port: 443, Destination Port: 50438

Payload: b'HTTP/1.1 200 OK...'

--------------------------------------------------

As packets are captured, their details will be displayed.


### Requirements
   Python 3.x
   scapy library

### Author
   Mohan Sai Krishna G M
