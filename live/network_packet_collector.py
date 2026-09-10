from scapy.all import sniff, IP, TCP, UDP,ICMP,ARP
from scapy.layers.inet6 import IPv6
from datetime import datetime
import live.network_flow_tracker as ft
import socket
from scapy.data import IP_PROTOS # for protocol translation

#one tracker for the entire program, to keep track of all flows across packets
tracker = ft.networkFlowTracker()

def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_collector, store=False)  
    
    #for testing purposes, we can use a filter to capture only ICMP packets to and from
    """
    sniff(
        iface=interface,
        filter="icmp and host 8.8.8.8",
        prn=packet_collector,
        store=False
    )
    """
    
def packet_collector(packet):
    #print("Packet captured:",packet_callback(packet))
    """""
    if IP in packet:
        #print("protocol#",socket.getprotobynumber(packet[IP].proto) )   
        proto_number = packet[IP].proto
        try:
            protocol_name = IP_PROTOS[proto_number]
                       
        except Exception:
             protocol_name = "unas"

        print(f"protocol{proto_number}{protocol_name}")
    """
    packet_data = packet_callback(packet)  

    #getting rid of no data and no protocol packets, as they are not useful for flow tracking
    if packet_data is None or packet_data["protocol"] is None:
        return
    
    flow=tracker.process_packet(packet_data)
    """"
    no need for that, I only care about the expired flows, so I will remove the print statement for the flow details here.
    print(
    f"Forward packets={flow.forward_packet_count} "
    f"Backward packets={flow.backward_packet_count} "
    f"Total packets={flow.total_packets} "
    f"Forward bytes={flow.forward_bytes} "
    f"Backward bytes={flow.backward_bytes} "
    f"Total bytes={flow.total_bytes} "
    f"duration={flow.duration:.6f} "
    f"Packet rate={flow.packet_rate:.2f} "
    f"Byte rate={flow.byte_rate:.2f} "
   )
   """

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