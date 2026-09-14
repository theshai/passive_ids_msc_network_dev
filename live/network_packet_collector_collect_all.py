from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
from scapy.layers.inet6 import IPv6
from datetime import datetime
import live.network_flow_tracker as ft
import socket
from scapy.data import IP_PROTOS


# One tracker for the entire program
tracker = ft.networkFlowTracker()

# Raw packets that will be saved to PCAP
captured_packets = []


def start_sniffing(interface=None):

    print("Starting packet sniffing...")

    try:

        sniff(
            iface=interface,
            filter="host 208.65.102.229 and port 86",
            prn=packet_collector_test,
            store=False
        )

    except KeyboardInterrupt:

        print("\nStopping packet capture...")

    finally:

        print(
            f"Saving {len(captured_packets)} packets..."
        )

        if captured_packets:

            wrpcap(
                "normal_test.pcap",
                captured_packets
            )

            print(
                "Saved normal_test.pcap"
            )

        else:

            print(
                "No packets were captured."
            )


def packet_collector_test(packet):

    # Save the original raw Scapy packet
    captured_packets.append(packet)

    # Send the same packet through your existing code
    packet_collector(packet)


def packet_collector(packet):

    packet_data = packet_callback(packet)

    # Ignore unusable packets
    if (
        packet_data is None
        or packet_data["protocol"] is None
    ):
        return

    flow = tracker.process_packet(
        packet_data
    )

def packet_callback(packet):

    #basic packet data extraction and printing to console. It captures the timestamp, source and destination IP addresses, protocol, source and destination ports, packet length, and TCP flags if applicable.
    packet_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": packet[IP].src if IP in packet else None,
        "dst_ip": packet[IP].dst if IP in packet else None,
        "protocol": "unas",#packet[IP].proto if IP in packet else None,             
        "src_port": packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None),
        "dst_port": packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None),
        "packet_length": len(packet),
        "tcp_flags": packet[TCP].flags if TCP in packet else None,
        "ttl": packet[IP].ttl if IP in packet else None, # also hop limit for IPv6 packets
        "icmp_type":None,
        "icmp_code": None,
        "tcp_window":None,
        "tcp_seq":None,
        "tcp_ack":None,
        "tcp_payload_len": 0,
    }

#basic network collector that captures packets and prints their details to the console. It uses the Scapy library to sniff network traffic and extract relevant information from IP, TCP, and UDP packets.    
    
    # ARP (moved up,didnt get it other way)
    if ARP in packet:
        packet_data["src_ip"] = packet[ARP].psrc
        packet_data["dst_ip"] = packet[ARP].pdst
        packet_data["src_port"] = 0
        packet_data["dst_port"] = 0
        packet_data["protocol"] =  packet_data["protocol"]=get_proto_name_from_packet(packet)
        packet_data["ttl"] = None
        return packet_data
    
    if IP in packet:
        packet_data["src_ip"] = packet[IP].src
        packet_data["dst_ip"] = packet[IP].dst
        packet_data["ttl"] = packet[IP].ttl
        #one for all protocols
        packet_data["protocol"]=get_proto_name_from_packet(packet)

        if TCP in packet:
            packet_data["src_port"] = packet[TCP].sport
            packet_data["dst_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = packet[TCP].flags
            packet_data["tcp_window"] = packet[TCP].window
            packet_data["tcp_seq"] = packet[TCP].seq
            packet_data["tcp_ack"] = packet[TCP].ack
            packet_data["tcp_payload_len"] = len(bytes(packet[TCP].payload))

            #packet_data["protocol"] = "tcp"
        elif UDP in packet:
            packet_data["src_port"] = packet[UDP].sport
            packet_data["dst_port"] = packet[UDP].dport
            #packet_data["protocol"] = "udp"
        elif ICMP in packet:
            #packet_data["protocol"] = "icmp"
            packet_data["icmp_type"] = packet[ICMP].type
        else:
            packet_data["src_port"] = None
            packet_data["dst_port"] = None
    elif IPv6 in packet:
        packet_data["src_ip"] = packet[IPv6].src
        packet_data["dst_ip"] = packet[IPv6].dst
        packet_data["ttl"] = packet[IPv6].hlim  # Hop Limit field indicates the TTL
        if TCP in packet:
            packet_data["src_port"] = packet[TCP].sport
            packet_data["dst_port"] = packet[TCP].dport
            packet_data["tcp_flags"] = packet[TCP].flags
            packet_data["tcp_window"] = packet[TCP].window
            packet_data["tcp_seq"] = packet[TCP].seq
            packet_data["tcp_ack"] = packet[TCP].ack
            packet_data["tcp_payload_len"] = len(bytes(packet[TCP].payload))

            packet_data["protocol"] = "tcp"
        elif UDP in packet:
            packet_data["src_port"] = packet[UDP].sport
            packet_data["dst_port"] = packet[UDP].dport
            packet_data["protocol"] = "udp"
        elif ICMP in packet:
            packet_data["protocol"] = "icmp"
            packet_data["icmp_type"] = packet[ICMP].type
            packet_data["icmp_code"] = packet[ICMP].code
        else:
            packet_data["src_port"] = None
            packet_data["dst_port"] = None

    return packet_data
#-------------------------------------------------
#support function to get protocol name from number
#-------------------------------------------------
def get_proto_name_from_packet(packet):

    if ARP in packet:
       return "arp"
    # IPv4
    if IP in packet:
        proto_number = packet[IP].proto
    # IPv6
    elif IPv6 in packet:
        proto_number = packet[IPv6].nh
    else:
        return "unas"
    try:
        #incase no number exist
        protocol_name = str(IP_PROTOS[proto_number]).lower()
    except (KeyError, IndexError):
        protocol_name = "unas"

    return protocol_name
    
    

if __name__ == "__main__":
    interface = input("Enter the network interface to sniff (or press Enter for default): ")
    if not interface:
        interface = None  # Use default interface
    start_sniffing(interface)