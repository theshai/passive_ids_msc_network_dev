from datetime import datetime
import time
import threading

FLOW_TIMEOUT = 5  # Timeout in seconds for flow expiration

class networkFlowObject:
    #basic network flow class that represents a network flow and its associated attributes. 
    # It captures the start time, last seen time, protocol, source and destination IP addresses, 
    # source and destination ports, and packet counts for both forward and backward directions. 
    # The update method is used to update the flow's attributes based on new packets.
    def __init__(self,packet):
        self.start_time = datetime.now()
        self.last_seen = datetime.now()
        self.protocol = packet["protocol"]
        self.src_ip = packet["src_ip"]  
        self.dst_ip = packet["dst_ip"]
        self.src_port = packet["src_port"]  
        self.dst_port = packet["dst_port"]
        self.forward_packet_count = 0
        self.backward_packet_count = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
        self.update(packet)

    def update(self, packet):
           self.last_seen = datetime.now()
           #fix for forward and backward packet count based on the direction of the packet in relation to the flow's
           # source and destination IP addresses and ports.
           if (
               (packet["src_ip"], packet["src_port"])  == (self.src_ip, self.src_port) 
                and (packet["dst_ip"], packet["dst_port"]) == (self.dst_ip, self.dst_port)):
                self.forward_packet_count += 1    
                self.forward_bytes += packet["packet_length"]  # Update forward bytes  
           elif ((packet["src_ip"], packet["src_port"]) == (self.dst_ip, self.dst_port) 
                 and (packet["dst_ip"], packet["dst_port"]) == (self.src_ip, self.src_port)):
                 self.backward_packet_count += 1  
                 self.backward_bytes += packet["packet_length"]  # Update backward bytes

    def is_expired(self,timeout=FLOW_TIMEOUT):
        #basic flow expiration check that determines if a flow has expired based on the time elapsed since the last seen packet. 
        # It compares the current time with the last seen time and checks if the difference exceeds the defined FLOW_TIMEOUT.
        return (datetime.now() - self.last_seen).total_seconds() >= timeout

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
        if self.duration > 0:
            return self.total_packets / self.duration
        else:
            return 0

    @property
    def byte_rate(self):
        if self.duration > 0:
            return self.total_bytes / self.duration
        else:
            return 0

class networkFlowTracker:
    #basic network flow class that represents a network flow and its associated attributes.
    def __init__(self) :
        self.flows = {}  # Dictionary to store flows with flow keys as keys and networkFlow objects as values
        self.running = True  # Flag to control the flow expiration thread
        #start the flow expiration thread to periodically check for expired flows and remove them from the tracker.
        self.cleanup_thread = threading.Thread(target=self.cleanup_loop, daemon=True)
        self.cleanup_thread.start()

    def cleanup_loop(self):
        #basic flow expiration loop that runs in a separate thread and periodically checks for expired flows. 
        # It calls the remove_expired_flows method to remove any flows that have exceeded the defined FLOW_TIMEOUT.
        while self.running:
            time.sleep(1)
            self.remove_expired_flows()

    def process_packet(self, packet):
        #basic packet processing method that processes incoming packets and updates the corresponding flow in the tracker.
        # It generates a flow key based on the packet's source and destination IP addresses, ports
        # and protocol, and checks if the flow already exists in the tracker. If it does, it updates the flow with the new packet.
        # If it doesn't exist, it creates a new flow object and adds it to the tracker. The method returns the flow object for the current packet.
        #***please note that the flow expiration check is performed before processing the new packet to ensure that expired flows are removed from the tracker.
        self.remove_expired_flows()  # Remove expired flows before processing the new packet

        flow_key = generate_flow_key(packet)
        if flow_key in self.flows:
            self.flows[flow_key].update(packet)
        else:
            self.flows[flow_key] = networkFlowObject(packet)
        #always return the flow object for the current packet, regardless of whether it was updated or newly created
        return self.flows[flow_key]
    #adding removed flows based on expiration check. This method iterates through the flows and removes any expired flows from the tracker.
    def remove_expired_flows(self):
        expired_keys = []   
        for flow_key, flow in self.flows.items():
            if flow.is_expired():
                expired_keys.append(flow_key)

        for flow_key in expired_keys:

            #print(f"Removing expired flow: {flow_key}") ** just for testing purposes, we can print the flow details before removing it from the tracker. This can help in debugging and understanding the flow's attributes before it is removed.
            print("\nExpired flow details:"
                f"Removing expired flow: {flow_key} "
                f"Forward packets={self.flows[flow_key].forward_packet_count} "
                f"Backward packets={self.flows[flow_key].backward_packet_count} "
                f"Total packets={self.flows[flow_key].total_packets} "
                f"Forward bytes={self.flows[flow_key].forward_bytes} "
                f"Backward bytes={self.flows[flow_key].backward_bytes} "
                f"Total bytes={self.flows[flow_key].total_bytes} "
                f"duration={self.flows[flow_key].duration:.6f} "
                f"Packet rate={self.flows[flow_key].packet_rate:.2f} "
                f"Byte rate={self.flows[flow_key].byte_rate:.2f}"
            )
             
            del self.flows[flow_key]

        
  
   

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
    
    

    
    

         