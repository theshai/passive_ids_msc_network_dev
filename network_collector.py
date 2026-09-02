from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime


def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_collector, store=False)  

def packet_collector(packet):
    print("Packet captured:",packet_callback(packet))      

def packet_callback(packet):

    #basic packet data extraction and printing to console. It captures the timestamp, source and destination IP addresses, protocol, source and destination ports, packet length, and TCP flags if applicable.
    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": packet[IP].src if IP in packet else None,
        "dst_ip": packet[IP].dst if IP in packet else None,
        "protocol": packet[IP].proto if IP in packet else None,             
        "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
        "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
        "packet_length": len(packet),
        "tcp_flags": packet[TCP].flags if TCP in packet else None,
    }

#basic network collector that captures packets and prints their details to the console. It uses the Scapy library to sniff network traffic and extract relevant information from IP, TCP, and UDP packets.    
    if IP in packet:
        packet_data["src_ip"] = packet[IP].src
        packet_data["dst_ip"] = packet[IP].dst
        

        if TCP in packet:
            packet_data["src_port"] = packet[TCP].sport
            packet_data["dst_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = packet[TCP].flags
            packet_data["protocol"] = "tcp"
        elif UDP in packet:
            packet_data["src_port"] = packet[UDP].sport
            packet_data["dst_port"] = packet[UDP].dport
            packet_data["protocol"] = "udp"
        else:
            packet_data["src_port"] = None
            packet_data["dst_port"] = None

    return packet_data

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (or press Enter for default): ")
    if not interface:
        interface = None  # Use default interface
    start_sniffing(interface)