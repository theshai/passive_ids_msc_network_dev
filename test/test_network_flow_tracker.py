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
        packet_length=100
):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": packet_length  
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
