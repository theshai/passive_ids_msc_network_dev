from live.network_flow_tracker_extended import networkFlowObject
from extractors.cic2017_extractor import extract_cic2017_from_flow
from pprint import pprint

timestamps=[
    1_700_000_000.0,
    1_700_000_001.0,
    1_700_000_008.0,
    1_700_000_010.0,
    1_700_000_019.0,
    ]


def make_packet(timestamp):
    return {
        "timestamp": timestamp,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "tcp",
        "packet_length": 100,
        "tcp_flags": "A",
        "ttl": 64,
        "icmp_type": None,
        "icmp_code": None,
        "tcp_window": 8192,
        "tcp_seq": 1000,
        "tcp_ack": 1000,
        "tcp_payload_len": 0,
        "payload_size": 0,
        "transport_header_length": 20,
    }

# Create the flow from the first packet
flow = networkFlowObject(make_packet(timestamps[0]))

# Same behavior as process_packet():
# first packet must be updated exactly once
flow.update(make_packet(timestamps[0]))

# Process remaining packets
for timestamp in timestamps[1:]:
    flow.update(make_packet(timestamp))


print("\nRaw tracker values:")
print("cic_active =", flow.cic_active)
print("cic_idle   =", flow.cic_idle)


features = extract_cic2017_from_flow(flow)


print("\nExtracted CIC features:")
print("Active Mean =", features["Active Mean"])
print("Active Std  =", features["Active Std"])
print("Active Max  =", features["Active Max"])
print("Idle Std    =", features["Idle Std"])

print("\nfeatures\n")
pprint(features, sort_dicts=False)

