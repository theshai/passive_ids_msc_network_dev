from live.network_flow_tracker_extended import (
    networkFlowTracker,
    generate_flow_key,
    networkFlowObject
)

"""
Simple unit tests for the network flow tracker and flow object classes.
Creating test packets and verifying that the flow tracker correctly identifies flows, counts packets, and calculates byte counts.
"""


def create_test_packet(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=443,
        protocol="tcp",
        packet_length=100,
        ttl=None,
        timestamp=1700000000.0
):
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "packet_length": packet_length,
        "ttl": ttl,
        "timestamp": timestamp
    }


def test_generate_flow_key_different_packets():
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

    assert flow_key1 != flow_key2


def test_generate_flow_key_both_directions():
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

    assert flow_key1 == flow_key2


def test_new_flow_counts_first_packet_as_forward():
    packet = create_test_packet(
        packet_length=200
    )

    tracker = networkFlowTracker()

    flow = tracker.process_packet(
        packet
    )

    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 0
    assert flow.forward_bytes == 200
    assert flow.backward_bytes == 0


def test_forward_packet_update():
    packet1 = create_test_packet(
        packet_length=150,
        timestamp=1700000000.0
    )

    packet2 = create_test_packet(
        packet_length=250,
        timestamp=1700000001.0
    )

    tracker = networkFlowTracker()

    flow = tracker.process_packet(
        packet1
    )

    flow = tracker.process_packet(
        packet2
    )

    assert flow.forward_packet_count == 2
    assert flow.backward_packet_count == 0
    assert flow.forward_bytes == 400
    assert flow.backward_bytes == 0


def test_backward_packet_update():
    packet1 = create_test_packet(
        packet_length=100,
        timestamp=1700000000.0
    )

    backward_packet1 = create_test_packet(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=443,
        dst_port=5000,
        protocol="tcp",
        packet_length=150,
        timestamp=1700000001.0
    )

    tracker = networkFlowTracker()

    flow = tracker.process_packet(
        packet1
    )

    flow = tracker.process_packet(
        backward_packet1
    )

    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 1
    assert flow.forward_bytes == 100
    assert flow.backward_bytes == 150


def test_different_ports_same_ips():
    packet1 = create_test_packet(
        src_port=5000,
        dst_port=443,
        packet_length=100
    )

    packet2 = create_test_packet(
        src_port=5001,
        dst_port=443,
        packet_length=200
    )

    tracker = networkFlowTracker()

    tracker.process_packet(
        packet1
    )

    tracker.process_packet(
        packet2
    )

    assert len(tracker.flows) == 2


def test_different_protocols_same_ips_ports():
    packet1 = create_test_packet(
        protocol="tcp",
        packet_length=100
    )

    packet2 = create_test_packet(
        protocol="udp",
        packet_length=200
    )

    tracker = networkFlowTracker()

    tracker.process_packet(
        packet1
    )

    tracker.process_packet(
        packet2
    )

    assert len(tracker.flows) == 2


def test_is_sm_ips_ports_is_true():
    packet = create_test_packet(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=5000,
        protocol="tcp",
        packet_length=100
    )

    flow = networkFlowObject(
        packet
    )

    assert flow.is_sm_ips_ports == 1


def test_is_sm_ips_ports_is_false():
    packet = create_test_packet(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=5000,
        dst_port=5001,
        protocol="tcp",
        packet_length=100
    )

    flow = networkFlowObject(
        packet
    )

    assert flow.is_sm_ips_ports == 0