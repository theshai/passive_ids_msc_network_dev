from datetime import datetime
import time
import threading
import statistics
from arrow import now
import csv
import os
from extractors import unsw_extractor
from extractors import cic2017_extractor
import pandas as pd
import requests

FLOW_TIMEOUT = 30  # Timeout in seconds for flow expiration (random)
MIN_FLOW_DURATION = 0.001  # Minimum duration in seconds to consider a flow for rate calculations

TCP_TIMEOUT = 120
TCP_CLOSED_TIMEOUT = 2
UDP_TIMEOUT = 30

TCP_IDLE_TIMEOUT = 30
TCP_ACTIVE_TIMEOUT = 300#60

UDP_IDLE_TIMEOUT = 30
UDP_ACTIVE_TIMEOUT = 60

#save unlabled live data, as normal
UNSW_NORMAL_CAPTURE_FILE = "unsw_live_normal_capture.csv"

#------------------------------------------------------------
#Information needed to be updated from IDS selection
#------------------------------------------------------------

#needs to be dynamic
IDS_CONFIG_URL="http://localhost:8000/capture/config"

ids_config={
    "running": True,
    "dataset": "cic2017",
    "model": "random_forest",
    "protocol": "all"
    }

ids_config_lock = threading.Lock()

class networkFlowObject:
    #basic network flow class that represents a network flow and its associated attributes. 
    # It captures the start time, last seen time, protocol, source and destination IP addresses, 
    # source and destination ports, and packet counts for both forward and backward directions. 
    # The update method is used to update the flow's attributes based on new packets.
    def __init__(self,packet):
        packet_time = datetime.fromtimestamp(packet["timestamp"])
        self.start_time = packet_time# datetime.now()
        self.last_seen = packet_time# datetime.now()

        packet_timestamp = float(packet["timestamp"])

        # CIC Active / Idle tracking
        self.cic_start_active = packet_timestamp
        self.cic_last_active = packet_timestamp

        self.cic_active = []
        self.cic_idle = []

        self.protocol = packet["protocol"]
        self.src_ip = packet["src_ip"]  
        self.dst_ip = packet["dst_ip"]
        self.src_port = packet["src_port"]  
        self.dst_port = packet["dst_port"]
        #--------------------------------------------
        #Test for directional flow
        #--------------------------------------------
        """"
        print(
            f"\n[NEW FLOW] "
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} "
            f"flags={packet.get('tcp_flags')}"
        )
        """


        self.forward_packet_count = 0
        self.backward_packet_count = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.source_ttl=None
        self.destination_ttl=None
        self.last_forward_packet_time = None
        self.last_backward_packet_time = None
        self.forward_interpacket_times = []
        self.backward_interpacket_times = []
        self.tcp_syn_seen = False
        self.tcp_ack_seen = False
        self.tcp_fin_seen = False
        self.tcp_rst_seen = False
        self.source_window = None
        self.destination_window = None
        self.source_tcp_base_seq = None
        self.destination_tcp_base_seq = None
        self.source_loss = 0
        self.destination_loss = 0
        self.source_tcp_sequences = set()
        self.destination_tcp_sequences = set()
        self.icmp_types = set()
        self.icmp_codes = set()
        self.tcp_syn_time = None
        self.tcp_synack_time = None
        self.tcp_ack_time = None
        self.tcp_synack = 0
        self.tcp_ackdat = 0
        self.response_body_len=0
        #--------------------------------------------
        #extentended to support cic_2017
        #---------------------------------------------
        self.forward_packet_lengths = []
        self.backward_packet_lengths = []
        self.all_packet_times = []
        self.forward_packet_times = []
        self.backward_packet_times = []
        self.forward_psh_flags = 0
        self.backward_psh_flags = 0
        self.forward_urg_flags = 0
        self.backward_urg_flags = 0
        self.fin_flag_count = 0
        self.rst_flag_count = 0
        self.psh_flag_count = 0
        self.ack_flag_count = 0
        self.urg_flag_count = 0
        self.forward_header_length = 0
        self.backward_header_length = 0
        self.initial_forward_window = None
        self.initial_backward_window = None
        # CIC-IDS2017 minimum forward segment/header size
        self.min_forward_segment_size = None
        # Forward bulk temporary state
        self.forward_bulk_start_tmp = 0
        self.forward_bulk_last_timestamp = 0
        self.forward_bulk_count_tmp = 0
        self.forward_bulk_size_tmp = 0

        # Forward confirmed bulk statistics
        self.forward_bulk_count = 0
        self.forward_bulk_packet_count = 0
        self.forward_bulk_size = 0
        self.forward_bulk_duration = 0

        # Backward bulk temporary state
        self.backward_bulk_start_tmp = 0
        self.backward_bulk_last_timestamp = 0
        self.backward_bulk_count_tmp = 0
        self.backward_bulk_size_tmp = 0

        # Backward confirmed bulk statistics
        self.backward_bulk_count = 0
        self.backward_bulk_packet_count = 0
        self.backward_bulk_size = 0
        self.backward_bulk_duration = 0

        # Same values used by CICFlowMeter
        self.bulk_timeout = 1.0
        self.bulk_bound = 4
        #--------------------------------------------
        #end of extended section
        #---------------------------------------------

        ######self.update(packet)

    def update(self, packet):

        
        #--------------------------------------------
        #Test for directional flow
        #--------------------------------------------
        """"
        is_forward = (
            packet["src_ip"] == self.src_ip
            and packet["dst_ip"] == self.dst_ip
            and packet["src_port"] == self.src_port
            and packet["dst_port"] == self.dst_port
        )

        if is_forward:
            direction = "forward"
        else:
            direction = "backward"

        print(
            f"[{direction.upper()}] "
            f"{packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']} "
            f"flags={packet.get('tcp_flags')}"
        )

        """

        packet_timestamp = float(packet["timestamp"])
        now = datetime.fromtimestamp(packet_timestamp)

        # ---------------------------------------------------------
        # CIC Active / Idle tracking
        # ---------------------------------------------------------
        previous_timestamp = self.last_seen.timestamp()

        gap = packet_timestamp - previous_timestamp

        # CIC active timeout = 5 seconds (from cicflowmeter)
        if gap > 5.0:

            active_duration = previous_timestamp - self.cic_start_active

            if active_duration > 0:
                self.cic_active.append(active_duration)

            self.cic_idle.append(gap)

            # Current packet starts a new active period
            self.cic_start_active = packet_timestamp

        self.cic_last_active = packet_timestamp

        # NOW update last_seen
        self.last_seen = now

        self.all_packet_times.append(now)

        # Track TCP flags
        if self.protocol == "tcp" and packet.get("tcp_flags") is not None:

            flags = str(packet["tcp_flags"])

            # CIC-IDS2017 TCP flag counters
            if "F" in flags:
                self.fin_flag_count += 1
            if "R" in flags:
                self.rst_flag_count += 1
            if "P" in flags:
                self.psh_flag_count += 1
            if "A" in flags:
                self.ack_flag_count += 1
            if "U" in flags:
                self.urg_flag_count += 1

            # SYN-ACK must be checked BEFORE plain SYN
            if "S" in flags and "A" in flags:

                self.tcp_ack_seen = True

                # Record first SYN-ACK only
                if self.tcp_synack_time is None:
                    self.tcp_synack_time = now

                    # SYN -> SYN-ACK
                    if self.tcp_syn_time is not None:
                        self.tcp_synack = (
                            self.tcp_synack_time - self.tcp_syn_time
                        ).total_seconds()

            # Plain SYN
            elif "S" in flags:

                self.tcp_syn_seen = True

                # Record first SYN only
                if self.tcp_syn_time is None:
                    self.tcp_syn_time = now

            # ACK
            if "A" in flags:

                self.tcp_ack_seen = True

                # We want the ACK AFTER SYN-ACK
                if (
                    self.tcp_synack_time is not None
                    and self.tcp_ack_time is None
                    and "S" not in flags
                ):
                    self.tcp_ack_time = now

                    self.tcp_ackdat = (
                        self.tcp_ack_time - self.tcp_synack_time
                    ).total_seconds()

            if "F" in flags:
                self.tcp_fin_seen = True

            if "R" in flags:
                self.tcp_rst_seen = True

        # Track ICMP message types
        if self.protocol == "icmp":
            icmp_type = packet.get("icmp_type")
            icmp_code = packet.get("icmp_code")

            if icmp_type is not None:
                self.icmp_types.add(icmp_type)

            if icmp_code is not None:
                self.icmp_codes.add(icmp_code)

        # Forward packet
        if (
            (packet["src_ip"], packet["src_port"]) == (self.src_ip, self.src_port)
            and
            (packet["dst_ip"], packet["dst_port"]) == (self.dst_ip, self.dst_port)
        ):

            self.forward_packet_count += 1
            self.forward_bytes += packet["packet_length"]
            # CICFlowMeter bulk tracking
            self.update_bulk(packet, "forward")

            # CIC-IDS2017 forward-direction tracking
            self.forward_packet_lengths.append(packet["packet_length"])
            self.forward_packet_times.append(now)
            #self.forward_header_length += packet.get("transport_header_length", 0)
            if self.protocol == "tcp":
                self.forward_header_length += 20
            else:
                self.forward_header_length += packet.get(
                    "transport_header_length", 0
    )
            # CIC-IDS2017 min_seg_size_forward
            if self.protocol == "tcp":
                segment_size = 20
                if (
                    self.min_forward_segment_size is None
                    or segment_size < self.min_forward_segment_size
                  ):
                    self.min_forward_segment_size = segment_size

            if self.protocol == "tcp":
                cic_flags = str(packet.get("tcp_flags", ""))
                if "P" in cic_flags:
                    self.forward_psh_flags += 1
                if "U" in cic_flags:
                    self.forward_urg_flags += 1

            if packet["ttl"] is not None:
                self.source_ttl = packet["ttl"]

            # TCP source-side tracking
            if self.protocol == "tcp":

                seq = packet.get("tcp_seq")
                payload_len = packet.get("tcp_payload_len", 0)

                # Detect repeated TCP data packets
                if seq is not None and payload_len > 0:

                    packet_sig = (
                        seq,
                        payload_len
                    )

                    if packet_sig in self.source_tcp_sequences:
                        self.source_loss += 1
                    else:
                        self.source_tcp_sequences.add(packet_sig)

                # Source TCP advertised window
                if packet.get("tcp_window") is not None:
                    self.source_window = packet["tcp_window"]

                # CIC-IDS2017 initial forward TCP window
                if (
                    self.initial_forward_window is None
                    and packet.get("tcp_window") is not None
                ):
                    self.initial_forward_window = packet["tcp_window"]

                # Source TCP base sequence number
                if (
                    self.source_tcp_base_seq is None
                    and packet.get("tcp_seq") is not None
                ):
                    self.source_tcp_base_seq = packet["tcp_seq"]

            # Forward inter-packet timing
            if self.last_forward_packet_time is not None:

                diff = (
                    now - self.last_forward_packet_time
                ).total_seconds() * 1000

                self.forward_interpacket_times.append(diff)

            self.last_forward_packet_time = now

        # Backward packet
        elif (
            (packet["src_ip"], packet["src_port"]) == (self.dst_ip, self.dst_port)
            and
            (packet["dst_ip"], packet["dst_port"]) == (self.src_ip, self.src_port)
        ):

            self.backward_packet_count += 1
            self.backward_bytes += packet["packet_length"]
            # CICFlowMeter bulk tracking
            self.update_bulk(packet, "backward")
            
            # CIC-IDS2017 backward-direction tracking
            self.backward_packet_lengths.append(packet["packet_length"])
            self.backward_packet_times.append(now)
            #self.backward_header_length += packet.get("transport_header_length", 0)
            if self.protocol == "tcp":
                self.backward_header_length += 20
            else:
                self.backward_header_length += packet.get(
                    "transport_header_length", 0
    )

            if self.protocol == "tcp":
                cic_flags = str(packet.get("tcp_flags", ""))
                if "P" in cic_flags:
                    self.backward_psh_flags += 1
                if "U" in cic_flags:
                    self.backward_urg_flags += 1

            if packet["ttl"] is not None:
                self.destination_ttl = packet["ttl"]

            # TCP-specific backward-direction information
            if self.protocol == "tcp":

                seq = packet.get("tcp_seq")
                payload_len = packet.get("tcp_payload_len", 0)

                # Detect repeated TCP data packets
                if seq is not None and payload_len > 0:

                    packet_sig = (
                        seq,
                        payload_len
                    )

                    if packet_sig in self.destination_tcp_sequences:
                        self.destination_loss += 1
                    else:
                        self.destination_tcp_sequences.add(packet_sig)

                # Destination TCP advertised window
                if packet.get("tcp_window") is not None:
                    self.destination_window = packet["tcp_window"]

                # CIC-IDS2017 initial backward TCP window
                if (
                    self.initial_backward_window is None
                    and packet.get("tcp_window") is not None
                ):
                    self.initial_backward_window = packet["tcp_window"]

                # Destination TCP base sequence number
                # Only store the first observed sequence number
                if (
                    self.destination_tcp_base_seq is None
                    and packet.get("tcp_seq") is not None
                ):
                    self.destination_tcp_base_seq = packet["tcp_seq"]

                # Estimate plain HTTP response payload
                if self.service == "http":
                    self.response_body_len += payload_len

            # Backward inter-packet timing
            if self.last_backward_packet_time is not None:

                diff = (
                    now - self.last_backward_packet_time
                ).total_seconds() * 1000

                self.backward_interpacket_times.append(diff)

            self.last_backward_packet_time = now  

    def update_bulk(self, packet, direction):
        """
        CICFlowMeter-compatible bulk tracking.

        direction:
            "forward"
            "backward"
        """

        payload_size = packet.get("payload_size", 0)

        if payload_size is None:
            payload_size = 0

        # CICFlowMeter ignores packets without payload
        if payload_size == 0:
            return

        packet_time = float(packet["timestamp"])

        #-----------------------------------------------------------
        # FORWARD
        #-----------------------------------------------------------
        if direction == "forward":

            # Backward payload appeared after this potential forward
            # bulk started -> reset temporary forward bulk.
            if self.backward_bulk_last_timestamp > self.forward_bulk_start_tmp:
                self.forward_bulk_start_tmp = 0

            # Start a new potential bulk
            if self.forward_bulk_start_tmp == 0:

                self.forward_bulk_start_tmp = packet_time
                self.forward_bulk_last_timestamp = packet_time
                self.forward_bulk_count_tmp = 1
                self.forward_bulk_size_tmp = payload_size

            else:

                # More than 1 second since previous payload packet:
                # start a new potential bulk
                if (
                    packet_time - self.forward_bulk_last_timestamp
                    > self.bulk_timeout
                ):

                    self.forward_bulk_start_tmp = packet_time
                    self.forward_bulk_last_timestamp = packet_time
                    self.forward_bulk_count_tmp = 1
                    self.forward_bulk_size_tmp = payload_size

                else:

                    self.forward_bulk_count_tmp += 1
                    self.forward_bulk_size_tmp += payload_size

                    # Exactly 4 payload packets -> bulk becomes valid
                    if self.forward_bulk_count_tmp == self.bulk_bound:

                        self.forward_bulk_count += 1

                        self.forward_bulk_packet_count += (
                            self.forward_bulk_count_tmp
                        )

                        self.forward_bulk_size += (
                            self.forward_bulk_size_tmp
                        )

                        self.forward_bulk_duration += (
                            packet_time -
                            self.forward_bulk_start_tmp
                        )

                    # Bulk already established
                    elif self.forward_bulk_count_tmp > self.bulk_bound:

                        self.forward_bulk_packet_count += 1
                        self.forward_bulk_size += payload_size

                        self.forward_bulk_duration += (
                            packet_time -
                            self.forward_bulk_last_timestamp
                        )

                    self.forward_bulk_last_timestamp = packet_time

        #-----------------------------------------------------------
        # BACKWARD
        #-----------------------------------------------------------
        else:

            # Forward payload appeared after this potential backward
            # bulk started -> reset temporary backward bulk.
            if self.forward_bulk_last_timestamp > self.backward_bulk_start_tmp:
                self.backward_bulk_start_tmp = 0

            # Start a new potential bulk
            if self.backward_bulk_start_tmp == 0:

                self.backward_bulk_start_tmp = packet_time
                self.backward_bulk_last_timestamp = packet_time
                self.backward_bulk_count_tmp = 1
                self.backward_bulk_size_tmp = payload_size

            else:

                # More than 1 second since previous payload packet
                if (
                    packet_time - self.backward_bulk_last_timestamp
                    > self.bulk_timeout
                ):

                    self.backward_bulk_start_tmp = packet_time
                    self.backward_bulk_last_timestamp = packet_time
                    self.backward_bulk_count_tmp = 1
                    self.backward_bulk_size_tmp = payload_size

                else:

                    self.backward_bulk_count_tmp += 1
                    self.backward_bulk_size_tmp += payload_size

                    # Exactly 4 payload packets -> bulk becomes valid
                    if self.backward_bulk_count_tmp == self.bulk_bound:

                        self.backward_bulk_count += 1

                        self.backward_bulk_packet_count += (
                            self.backward_bulk_count_tmp
                        )

                        self.backward_bulk_size += (
                            self.backward_bulk_size_tmp
                        )

                        self.backward_bulk_duration += (
                            packet_time -
                            self.backward_bulk_start_tmp
                        )

                    # Bulk already established
                    elif self.backward_bulk_count_tmp > self.bulk_bound:

                        self.backward_bulk_packet_count += 1
                        self.backward_bulk_size += payload_size

                        self.backward_bulk_duration += (
                            packet_time -
                            self.backward_bulk_last_timestamp
                        )

                    self.backward_bulk_last_timestamp = packet_time                
    """"
    def is_expired(self,timeout=FLOW_TIMEOUT):
        #basic flow expiration check that determines if a flow has expired based on the time elapsed since the last seen packet. 
        # It compares the current time with the last seen time and checks if the difference exceeds the defined FLOW_TIMEOUT.
        return (datetime.now() - self.last_seen).total_seconds() >= timeout
    """
    def is_expired_dell(self):

        idle_time = (
            datetime.now() - self.last_seen
        ).total_seconds()

        if self.protocol == "tcp":

            if self.tcp_fin_seen or self.tcp_rst_seen:
                return idle_time >= TCP_CLOSED_TIMEOUT

            return idle_time >= TCP_TIMEOUT

        return idle_time >= UDP_TIMEOUT

    def is_expired(self):

        now = datetime.now()

        # Time since the last packet was seen
        idle_time = (
            now - self.last_seen
        ).total_seconds()

        # Total lifetime of this flow
        active_time = (
            now - self.start_time
        ).total_seconds()

        # TCP
        if self.protocol == "tcp":

            # If FIN or RST was seen, allow a short grace period
            # for the remaining TCP packets.
            if self.tcp_fin_seen or self.tcp_rst_seen:
                return idle_time >= TCP_CLOSED_TIMEOUT

            # Force long-lived TCP connections to be split.
            if active_time >= TCP_ACTIVE_TIMEOUT:
                return True

            # Otherwise expire after inactivity.
            return idle_time >= TCP_IDLE_TIMEOUT

        # UDP / ICMP / other protocols

        # Force long-lived flows to be split.
        if active_time >= UDP_ACTIVE_TIMEOUT:
            return True

        # Otherwise expire after inactivity.
        return idle_time >= UDP_IDLE_TIMEOUT
    
    #some basic properies to get the flow's attributes, such as the flow key, total packet count, total bytes, and duration of the flow.
    @property
    def duration(self):
        return (self.last_seen - self.start_time).total_seconds()

    @property
    def total_packets(self):
        return self.forward_packet_count + self.backward_packet_count

    @property
    def total_bytes(self):
        return self.forward_bytes + self.backward_bytes

    @property
    def packet_rate(self):
        if self.duration < MIN_FLOW_DURATION:
            return 0
        else:
            return self.total_packets / self.duration

    @property
    def byte_rate(self):
        if self.duration < MIN_FLOW_DURATION:
            return 0
        else:
            return self.total_bytes / self.duration
        
    #added properties to get the additional features as we go along

    @property
    def source_mean_packet_size(self):
        if self.forward_packet_count == 0:
            return 0
        else:
            return self.forward_bytes / self.forward_packet_count

    @property
    def destination_mean_packet_size(self):
        if self.backward_packet_count == 0:
            return 0
        else:
            return self.backward_bytes / self.backward_packet_count

    @property
    def source_interpacket_time_mean(self):
        if len(self.forward_interpacket_times) == 0:
            return 0
        else:
            return sum(self.forward_interpacket_times) / len(self.forward_interpacket_times)

    @property
    def destination_interpacket_time_mean(self):
        if len(self.backward_interpacket_times) == 0:
            return 0
        else:
            return sum(self.backward_interpacket_times) / len(self.backward_interpacket_times)

    @property
    def source_jitter(self):
        if len(self.forward_interpacket_times) < 2:
            return 0
        else:
            return statistics.stdev(self.forward_interpacket_times) 

    @property
    def destination_jitter(self):
        if len(self.backward_interpacket_times) < 2:
            return 0
        else:
            return statistics.stdev(self.backward_interpacket_times)
    #this property was mde to accomondate all the services in the original dataset
    @property
    def service(self):
        ports = {self.src_port, self.dst_port}
        if 20 in ports:
            return "ftp-data"
        if 21 in ports:
            return "ftp"
        if 22 in ports:
            return "ssh"
        if 25 in ports:
            return "smtp"
        if 53 in ports:
            return "dns"
        if 67 in ports or 68 in ports:
            return "dhcp"
        if 80 in ports:
            return "http"
        if 110 in ports:
            return "pop3"
        if 161 in ports or 162 in ports:
            if self.protocol == "udp":
             return "snmp"
        if 443 in ports and self.protocol=="tcp":# avoid udp as ssl
            return "ssl"
        if (1812 in ports or 1813 in ports) and self.protocol=="udp":
            return "radius"
        if 6667 in ports:
            return "irc"
        return "-" #bsically...none

    @property
    def state(self):
        if self.protocol == "icmp":
            if 8 in self.icmp_types:
                return "ECO"
            if 12 in self.icmp_types:
                return "PAR"
            if 3 in self.icmp_types and 0 in self.icmp_codes:
                return "URN"
            return "no"

        if self.protocol == "tcp":
            if self.tcp_rst_seen:
                return "RST"
            if self.tcp_fin_seen:
                return "FIN"
            if self.tcp_ack_seen:
                return "CON"
            if self.tcp_syn_seen:
                return "REQ"
            
            return "INT"

        if self.protocol == "udp":
            return "INT"

        return "no"

    @property
    def swin(self):
        return self.source_window if self.source_window is not None else 0

    @property
    def dwin(self):
        return self.destination_window if self.destination_window is not None else 0

    @property
    def stcpb(self):
        return self.source_tcp_base_seq if self.source_tcp_base_seq is not None else 0

    @property
    def dtcpb(self):
        return self.destination_tcp_base_seq if self.destination_tcp_base_seq is not None else 0

    @property
    def synack(self):
        return self.tcp_synack

    @property
    def ackdat(self):
        return self.tcp_ackdat

    @property
    def tcprtt(self):
        return self.tcp_synack + self.tcp_ackdat

    @property
    def sloss(self):
        return self.source_loss

    @property
    def dloss(self):
        return self.destination_loss

    @property
    def is_sm_ips_ports(self):

        if (
            self.src_ip == self.dst_ip
            and
            self.src_port == self.dst_port
        ):
            return 1
        return 0
   
class networkFlowTracker:
    #basic network flow class that represents a network flow and its associated attributes.
    def __init__(self) :
        self.flows = {}  # Dictionary to store flows with flow keys as keys and networkFlow objects as values
        self.running = True  # Flag to control the flow expiration thread
        # Lock to synchronize access to the flows dictionary in a multi-threaded environment
        self.flows_lock = threading.Lock()
        #start the flow expiration thread to periodically check for expired flows and remove them from the tracker.

        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        self.cleanup_thread.start()

        #added for the config read options
        self.config_thread = threading.Thread(
        target=update_ids_config,
        daemon=True
         )

        self.config_thread.start()

    def cleanup_loop(self):
        #basic flow expiration loop that runs in a separate thread and periodically checks for expired flows. 
        # It calls the remove_expired_flows method to remove any flows that have exceeded the defined FLOW_TIMEOUT.
        while self.running:
            time.sleep(1)
            self.remove_expired_flows()

    def process_packet_(self, packet):
        """
        Process an incoming packet and update/create its flow.

        IMPORTANT:
        The first packet that creates a flow must also be passed to update().
        Otherwise the first packet is missing from all CIC counters.
        """

        flow_key = generate_flow_key(packet)

        with self.flows_lock:

            if flow_key not in self.flows:
                self.flows[flow_key] = networkFlowObject(packet)

            # ALWAYS process the packet, including the packet
            # that created the flow.
            self.flows[flow_key].update(packet)

            return self.flows[flow_key]

    def process_packet(self, packet):

        flow_key = generate_flow_key(packet)

        with self.flows_lock:

            if flow_key not in self.flows:
             self.flows[flow_key] = networkFlowObject(packet)

            self.flows[flow_key].update(packet)

            return self.flows[flow_key]
    
    #adding removed flows based on expiration check. This method iterates through the flows and removes any expired flows from the tracker.
    def remove_expired_flows(self):

        expired_flows = []

        with self.flows_lock:

            expired_keys = [
                flow_key
                for flow_key, flow in self.flows.items()
                if flow.is_expired()
            ]

            for flow_key in expired_keys:

                flow = self.flows.pop(flow_key)

                expired_flows.append((flow_key, flow))

        # Lock is released here

        for flow_key, flow in expired_flows:

            """
            print(
                "\nExpired flow details: "
                f"Removing expired flow: {flow_key} "
                f"Forward packets={flow.forward_packet_count} "
                f"Backward packets={flow.backward_packet_count} "
                f"Total packets={flow.total_packets} "
                f"Forward bytes={flow.forward_bytes} "
                f"Backward bytes={flow.backward_bytes} "
                f"Total bytes={flow.total_bytes} "
                f"duration={flow.duration:.6f} "
                f"Packet rate={flow.packet_rate:.2f} "
                f"Byte rate={flow.byte_rate:.2f}"
            )  
            """
            #testing the extraction of flow data using the UNSW extractor
            ######  extracted_data = unsw_extractor.extract_unsw_from_flow(flow)  
            #send_flow_to_ids(extracted_data,flow)
            #extracted_data = cic2017_extractor.extract_cic2017_from_flow(flow) 
            #print("CIC as pd.dataframe:", extracted_data) 
            #live_as_df=pd.DataFrame([extracted_data]) 
            #print("UNSW features:", extracted_data) 
            #print("UNSW as pd.dataframe:", live_as_df) 
            """"
            print(
                f"\nCIC FLOW: "
                f"{flow.src_ip}:{flow.src_port} -> "
                f"{flow.dst_ip}:{flow.dst_port}"
            )
            """

            ###########features = cic2017_extractor.extract_cic2017_from_flow(flow) 

            #print("CIC Features:")
            #print(features)

            ##########send_flow_to_ids(features,flow, dataset="cic2017")
            #send_flow_to_ids(features,flow)
            # Read current dashboard configuration
            
          

            with ids_config_lock:
                config = ids_config.copy()


            # Dashboard has capture stopped
            if not config.get("running", False):
                continue

            # Protocol filtering
            selected_protocol = config.get(
                "protocol",
                "all"
            ).lower()

            flow_protocol = str(
                flow.protocol
            ).lower()

            if (
                selected_protocol != "all"
                and flow_protocol != selected_protocol
            ):
                continue

            # Dataset selection

            dataset = config.get(
                "dataset",
                "unsw"
            ).lower()

            if dataset == "cic2017":

                print("\n*** CIC FLOW EXPIRED - PROCESSING ***")
                print("Selected model:", config.get("model"))

                features = (
                    cic2017_extractor
                    .extract_cic2017_from_flow(flow)
                )

                print("CIC features extracted:", len(features))

                send_flow_to_ids(
                    features,
                    flow,
                    dataset="cic2017"
                )

            elif dataset == "unsw":

                features = (
                    unsw_extractor
                    .extract_unsw_from_flow(flow)
                )

                # -------------------------------------------------
                # Save raw UNSW-compatible live flow to CSV
                # Activate only for collection normal dataflow
                # -------------------------------------------------
                """"
                save_unsw_features_to_csv(
                    features
                )
                """

                #sanity check for usnw categorical values....
                """
                print("\nLIVE UNSW RAW CATEGORICAL VALUES")
                print("proto   =", features["proto"])
                print("service =", features["service"])
                print("state   =", features["state"])
                """
                print("\n========================================")
                print("UNSW FEATURES SENT TO IDS")
                print("========================================")

                for key, value in features.items():
                    print(f"{key}: {value}")

                print("========================================\n")

                #----------------------------------------------
                #bloc while pushing to csv
                #---------------------------------------------
                
                send_flow_to_ids(
                    features,
                    flow,
                    dataset="unsw"
                )
                

            else:

                print(
                    "Unsupported dataset selected:",
                    dataset
                )


# Allows the sensor to change configuration when change happens on the dashboard               
def update_ids_config():
    """
    Periodically retrieve the capture configuration from FastAPI.

    The Network Agent continues running even when capture is stopped.
    The dashboard controls whether flows are sent to the IDS.
    """

    global ids_config

    while True:

        try:

            response = requests.get(
                IDS_CONFIG_URL,
                timeout=2
            )

            if response.status_code == 200:

                new_config = response.json()

                with ids_config_lock:

                    # Print only when something actually changed
                    if new_config != ids_config:

                        print(
                            "\nIDS configuration changed:",
                            new_config
                        )

                    ids_config = new_config

        except requests.exceptions.ConnectionError:

            # FastAPI may temporarily be unavailable.
            # Keep the Network Agent alive.
            pass

        except requests.exceptions.Timeout:
            pass

        except Exception as e:

            print(
                "Unable to retrieve IDS configuration:",
                e
            )

        time.sleep(1)                
             

        
  
   

def generate_flow_key(packet):
    #basic flow key generation function that generates a unique flow key based on the source and destination IP addresses, 
    # ports, and protocol of a packet.
    # It returns a tuple representing the flow key, which can be used to identify and track
    endpoint1 = (packet["src_ip"], packet["src_port"])
    endpoint2 = (packet["dst_ip"], packet["dst_port"])

    if endpoint1 <= endpoint2:
        return (endpoint1, endpoint2, packet["protocol"])  
    else:
        return (endpoint2, endpoint1, packet["protocol"])
    
#---------------------------------------------------------------
#support function that send the flow line to the IDS system
#--------------------------------------------------------------
def send_flow_to_ids_old(features,flow):

    url = "http://localhost:8000/predict/unsw"

    response = requests.post(
        url,
        json=features,
        timeout=30
    )

    response.raise_for_status()

    result = response.json()

    print(
        f"\n\n"
        f"FLOW: "
        f"{flow.src_ip}:{flow.src_port} -> "
        f"{flow.dst_ip}:{flow.dst_port}\n"
        f"Duration={flow.duration:.6f} "
        f"spkts={flow.forward_packet_count} "
        f"dpkts={flow.backward_packet_count}\n"
        f"Features={features}\n"
        f"Prediction={result['label']} "
        f"Probability={result['attack_probability']:.4f}"
    )

    return result

def send_flow_to_ids_unsw_only(extracted_data, flow):

    try:

        response = requests.post(
            "http://localhost:8000/predict/unsw",
            json=extracted_data,
            timeout=30
        )

        if response.status_code != 200:
            print(
                f"IDS ERROR {response.status_code}: "
                f"{response.text}"
            )
            return

        result = response.json()

        print(
            "IDS Prediction:",
            result
        )

    except requests.exceptions.Timeout:

        print("IDS request timed out")

    except requests.exceptions.ConnectionError as e:

        print(
            "Cannot connect to IDS server:",
            e
        )

    except requests.exceptions.RequestException as e:

        print(
            "IDS request failed:",
            e
        )

    except Exception as e:

        print(
            "Unexpected IDS error:",
            e
        )   

def send_flow_to_ids_working_no_meta_data(extracted_data, flow, dataset="unsw"):

    try:

        # Select IDS endpoint based on dataset
        if dataset == "unsw":
            url = "http://localhost:8000/predict/unsw"

        elif dataset == "cic2017":
            url = "http://localhost:8000/predict/cic2017"

        else:
            print(
                f"Unsupported IDS dataset: {dataset} - please select only trained dataset"
            )
            return

        response = requests.post(
            url,
            json=extracted_data,
            timeout=30
        )

        if response.status_code != 200:
            print(
                f"IDS ERROR {response.status_code}: "
                f"{response.text}"
            )
            return

        result = response.json()

        print(
            f"\nIDS Prediction [{dataset}]:",
            result
        )

        return result

    except requests.exceptions.Timeout:

        print("IDS request timed out")

    except requests.exceptions.ConnectionError as e:

        print(
            "Cannot connect to IDS server:",
            e
        )

    except requests.exceptions.RequestException as e:

        print(
            "IDS request failed:",
            e
        )

    except Exception as e:

        print(
            "Unexpected IDS error:",
            e
        )

def send_flow_to_ids(extracted_data, flow, dataset="unsw"):

    try:

        # --------------------------------------------------
        # Select endpoint
        # --------------------------------------------------

        if dataset == "unsw":
            url = "http://localhost:8000/predict/unsw"

        elif dataset == "cic2017":
            url = "http://localhost:8000/predict/cic2017"

        else:
            print(
                f"Unsupported IDS dataset: {dataset}"
            )
            return


        # --------------------------------------------------
        # Metadata - NOT used by the ML model
        # --------------------------------------------------

        metadata = {
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,

            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,

            "protocol": flow.protocol,
            #not included in the 46 features, added anyway for dashboard
            "service":getattr(flow,"service",""),
            "state":getattr(flow,"state",""),

            "packets":
                flow.forward_packet_count +
                flow.backward_packet_count,

            "bytes":
                flow.forward_bytes +
                flow.backward_bytes
        }


        # --------------------------------------------------
        # Request payload
        # --------------------------------------------------
        
        if dataset=="cic2017":
            payload = {
                "features": extracted_data,
                "metadata": metadata
            }
        else:
            payload=extracted_data


        response = requests.post(
            url,
            json=payload,
            timeout=30
        )


        if response.status_code != 200:
            print(
                f"IDS ERROR {response.status_code}: "
                f"{response.text}"
            )
            return


        result = response.json()

        print(
            f"\nIDS Prediction [{dataset}]:",
            result
        )

        return result


    except requests.exceptions.Timeout:

        print("IDS request timed out")


    except requests.exceptions.ConnectionError as e:

        print(
            "Cannot connect to IDS server:",
            e
        )


    except requests.exceptions.RequestException as e:

        print(
            "IDS request failed:",
            e
        )


    except Exception as e:

        print(
            "Unexpected IDS error:",
            e
        )    

def save_unsw_features_to_csv(features):
    """
    Append one UNSW feature dictionary to a CSV file.

    The first call creates the file and writes the header.
    Later calls append one row per flow.
    """

    file_exists = os.path.isfile(
        UNSW_NORMAL_CAPTURE_FILE
    )

    with open(
        UNSW_NORMAL_CAPTURE_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        fieldnames = [
            "capture_time",
            *features.keys()
        ]

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        if not file_exists:
            writer.writeheader()

        row = {
            "capture_time":
                datetime.now().isoformat(
                    timespec="seconds"
                )
        }

        row.update(
            features
        )

        writer.writerow(
            row
        )