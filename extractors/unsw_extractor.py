MIN_FLOW_DURATION = 0.001  # Minimum duration in seconds to consider a flow for rate calculations

def extract_unsw_from_flow(flow):
    """
    Extracts relevant information from a network flow object and returns it as a dictionary.

    **Taken from UNSW_NB15_training-set.csv**
    
    Args:
        flow (networkFlowObject): The network flow object to extract information from.
        
    Returns:
        dict: A dictionary containing extracted information from the flow.
    """
    return {
        "dur": flow.duration,
        "proto": flow.protocol,
        "service":flow.service,
        "state":flow.state,
        "spkts": flow.forward_packet_count,
        "dpkts": flow.backward_packet_count,
        "sbytes": flow.forward_bytes,
        "dbytes": flow.backward_bytes,
        "rate": flow.packet_rate,
        "sttl": flow.source_ttl if flow.source_ttl is not None else 0,  # Use 0 if source_ttl is None
        "dttl": flow.destination_ttl if flow.destination_ttl is not None else 0,  # Use 0 if destination_ttl is None    
        "smean":flow.source_mean_packet_size,
        "dmean":flow.destination_mean_packet_size,
        "sinpkt":flow.source_interpacket_time_mean,
        "dinpkt":flow.destination_interpacket_time_mean, 
        "sjit":flow.source_jitter,
        "djit":flow.destination_jitter,
        "sloss": flow.sloss,
        "dloss": flow.dloss,
        "sload": flow.forward_bytes*8 / flow.duration if flow.duration >= MIN_FLOW_DURATION else 0, #remove meaningless if duration is too small to avoid division by zero or unrealistic values
        "dload": flow.backward_bytes*8 / flow.duration if flow.duration >= MIN_FLOW_DURATION else 0,#remove meaningless if duration is too small to avoid division by zero or unrealistic values
        "swin": flow.swin,
        "dwin": flow.dwin,
        "stcpb": flow.stcpb,
        "dtcpb": flow.dtcpb,
        "synack": flow.synack,
        "ackdat": flow.ackdat,
        "tcprtt": flow.tcprtt
      
    }
 