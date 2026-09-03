from datetime import datetime

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

    @property
    def duration(self):
        return (self.last_seen - self.start_time).total_seconds()
           

class networkFlowTracker:
    #basic network flow class that represents a network flow and its associated attributes.
    def __init__(self) :
        self.flows = {}  # Dictionary to store flows with flow keys as keys and networkFlow objects as values
    def process_packet(self, packet):
        flow_key = generate_flow_key(packet)
        if flow_key in self.flows:
            self.flows[flow_key].update(packet)
        else:
            self.flows[flow_key] = networkFlowObject(packet)
        #always return the flow object for the current packet, regardless of whether it was updated or newly created
        return self.flows[flow_key]

  
   

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
    
    

    
    

         