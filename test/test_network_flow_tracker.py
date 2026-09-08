from live.network_flow_tracker import (
    networkFlowTracker, generate_flow_key,networkFlowObject 
    )

def create_test_packet(
        # Default values for the test packet attributes
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=443,
        protocol="tcp",
        packet_length=100,
        ttl=None
):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": packet_length,
        "ttl": ttl
    }

def test_generate_flow_key_different_packets():
    #the first one takes default values for the test packet 
    # attributes, while the second one overrides some of
    #  those values to create a different packet. The flow
    #  keys generated for these two packets are then
    #  compared to ensure they are not equal,
    #  confirming that the flow key generation function correctly
    #  distinguishes between different flows based on their attributes.
    packet1 = create_test_packet()
    packet2 = create_test_packet(
        src_ip="10.0.0.3",
        dst_ip="10.0.0.4",
        src_port=5001,
        dst_port=443,
        protocol="tcp",
        packet_length=150
    )
    flow_key1 = generate_flow_key(packet1)
    flow_key2 = generate_flow_key(packet2)
    #first  assertion checks that the flow keys generated for
    # two different packets are not equal, ensuring that the flow key generation function correctly distinguishes between different flows based on their attributes.
    assert flow_key1 != flow_key2 

def test_generate_flow_key_both_directions():
    #the first one takes default values for the test packet attributes,
    #while the second one overrides some of those values to create a different packet.
    #The flow keys generated for these two packets are then compared to ensure they are not equal,
    #confirming that the flow key generation function correctly distinguishes between different flows based on their attributes.
    packet1 = create_test_packet()
    packet2 = create_test_packet(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=443,
        dst_port=5000,
        protocol="tcp",
        packet_length=100
    )
    flow_key1 = generate_flow_key(packet1)
    flow_key2 = generate_flow_key(packet2)
    #The assertion checks that the flow keys generated for two identical packets are equal,
    #ensuring that the flow key generation function correctly generates the same key for the same flow.
    assert flow_key1 == flow_key2

def test_new_flow_counts_first_packet_as_forward():
    #the first one takes default values for the test packet attributes,
    #while the second one overrides some of those values to create a different packet.
    #The flow keys generated for these two packets are then compared to ensure they are not equal,
    #confirming that the flow key generation function correctly distinguishes between different flows based on their attributes.
    packet = create_test_packet(packet_length=200)
    flow = networkFlowObject(packet)
    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 0
    assert flow.forward_bytes == 200
    assert flow.backward_bytes == 0

def test_forward_packet_update():
   #two forward packets are created with different packet lengths, and the flow object
   # is updated with each packet. The assertions check that the forward packet count and 
   # forward bytes are correctly updated after processing both packets,
   #  while the backward packet count and backward bytes remain unchanged.  
    packet1 = create_test_packet(packet_length=150)
    flow = networkFlowObject(packet1)
    packet2 = create_test_packet(packet_length=250)
    flow.update(packet2)
    assert flow.forward_packet_count == 2
    assert flow.backward_packet_count == 0
    assert flow.forward_bytes == 400
    assert flow.backward_bytes == 0

def test_backward_packet_update():
    #a forward packet is created and used to initialize a flow object.
    # Then, a backward packet is created with the source and destination IP addresses and ports reversed    
    packet1 = create_test_packet(packet_length=100)
    flow = networkFlowObject(packet1)
    backward_packet1 = create_test_packet(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=443,
        dst_port=5000,
        protocol="tcp",
        packet_length=150
    )
    flow.update(backward_packet1)
    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 1
    assert flow.forward_bytes == 100
    assert flow.backward_bytes == 150

def test_different_ports_same_ips():
    #This test checks that packets with the same source and destination IP addresses 
    #but different ports are treated as separate flows. Two packets are created with the same IP 
    #addresses but different source ports, and they are processed by the networkFlowTracker. 
    #The assertion checks that the tracker correctly identifies them as two distinct flows by verifying that the
    # length of the flows dictionary is 2.
    packet1 = create_test_packet(src_port=5000, dst_port=443, packet_length=100)
    packet2 = create_test_packet(src_port=5001, dst_port=443, packet_length=200)
    tracker = networkFlowTracker()
    flow = tracker.process_packet(packet1)
    flow = tracker.process_packet(packet2)
    assert len(tracker.flows) == 2

def test_different_protocols_same_ips_ports():
    #This test checks that packets with the same source and destination IP addresses and ports 
    #but different protocols are treated as separate flows. Two packets are created with the same IP 
    #addresses and ports but different protocols, and they are processed by the networkFlowTracker. 
    #The assertion checks that the tracker correctly identifies them as two distinct flows by verifying that the
    # length of the flows dictionary is 2.
    packet1 = create_test_packet(protocol="tcp", packet_length=100)
    packet2 = create_test_packet(protocol="udp", packet_length=200)
    tracker = networkFlowTracker()
    flow = tracker.process_packet(packet1)
    flow = tracker.process_packet(packet2)
    assert len(tracker.flows) == 2


