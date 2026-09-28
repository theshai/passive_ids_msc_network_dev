MIN_FLOW_DURATION = 0.001  # Minimum duration in seconds to consider a flow for rate calculations

def extract_unsw_from_flow_faulty_attacks(flow):
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
        #"sttl": flow.source_ttl if flow.source_ttl is not None else 0,  # Use 0 if source_ttl is None
        #"dttl": flow.destination_ttl if flow.destination_ttl is not None else 0,  # Use 0 if destination_ttl is None    
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
        #"swin": flow.swin,
        #"dwin": flow.dwin,
        "stcpb": flow.stcpb,
        "dtcpb": flow.dtcpb,
        "synack": flow.synack,
        "ackdat": flow.ackdat,
        "tcprtt": flow.tcprtt,
        "is_sm_ips_ports": flow.is_sm_ips_ports,
        "response_body_len": flow.response_body_len,
      
    }




def extract_unsw_from_flow(flow):
    """
    Extracts UNSW-NB15-compatible features from a network flow object.

    The calculations here are specific to UNSW-NB15 semantics and are
    intentionally kept inside this extractor so they do not affect
    CIC-IDS2017 feature generation.

    Args:
        flow (networkFlowObject):
            The network flow object to extract information from.

    Returns:
        dict:
            A dictionary containing UNSW-NB15-compatible features.
    """

    # ---------------------------------------------------------
    # UNSW rate
    #
    # Verified against the dataset:
    #
    # rate = (total_packets - 1) / duration
    # ---------------------------------------------------------

    total_packets = (
        flow.forward_packet_count
        +
        flow.backward_packet_count
    )

    if (
        flow.duration >= MIN_FLOW_DURATION
        and total_packets > 1
    ):
        unsw_rate = (
            total_packets - 1
        ) / flow.duration

    else:
        unsw_rate = 0


    # ---------------------------------------------------------
    # UNSW state
    #
    # For UDP:
    #   bidirectional -> CON
    #   one direction -> INT
    #
    # Leave TCP / ICMP logic to the tracker.
    # ---------------------------------------------------------

    if flow.protocol == "udp":

        if (
            flow.forward_packet_count > 0
            and
            flow.backward_packet_count > 0
        ):
            unsw_state = "CON"

        else:
            unsw_state = "INT"

    else:
        unsw_state = flow.state


    # ---------------------------------------------------------
    # UNSW source load
    #
    # Verified candidate formula:
    #
    # (sbytes * 8 / dur) * ((spkts - 1) / spkts)
    #
    # If spkts <= 1, UNSW uses sload = 0.
    # ---------------------------------------------------------

    if (
        flow.duration >= MIN_FLOW_DURATION
        and
        flow.forward_packet_count > 1
    ):

        unsw_sload = (

            (
                flow.forward_bytes
                * 8
                / flow.duration
            )

            *

            (
                (
                    flow.forward_packet_count
                    - 1
                )

                /

                flow.forward_packet_count
            )
        )

    else:
        unsw_sload = 0


    # ---------------------------------------------------------
    # UNSW destination load
    #
    # Verified candidate formula:
    #
    # (dbytes * 8 / dur) * ((dpkts - 1) / dpkts)
    #
    # If dpkts <= 1, UNSW uses dload = 0.
    # ---------------------------------------------------------

    if (
        flow.duration >= MIN_FLOW_DURATION
        and
        flow.backward_packet_count > 1
    ):

        unsw_dload = (

            (
                flow.backward_bytes
                * 8
                / flow.duration
            )

            *

            (
                (
                    flow.backward_packet_count
                    - 1
                )

                /

                flow.backward_packet_count
            )
        )

    else:
        unsw_dload = 0


    # ---------------------------------------------------------
    # Return UNSW feature dictionary
    # ---------------------------------------------------------

    return {

        "dur": flow.duration,

        "proto": flow.protocol,

        "service": flow.service,

        "state": unsw_state,

        "spkts": flow.forward_packet_count,

        "dpkts": flow.backward_packet_count,

        "sbytes": flow.forward_bytes,

        "dbytes": flow.backward_bytes,

        "rate": unsw_rate,

        # "sttl": (
        #     flow.source_ttl
        #     if flow.source_ttl is not None
        #     else 0
        # ),

        # "dttl": (
        #     flow.destination_ttl
        #     if flow.destination_ttl is not None
        #     else 0
        # ),

        "smean": flow.source_mean_packet_size,

        "dmean": flow.destination_mean_packet_size,

        "sinpkt": flow.source_interpacket_time_mean,

        "dinpkt": flow.destination_interpacket_time_mean,

        "sjit": flow.source_jitter,

        "djit": flow.destination_jitter,

        "sloss": flow.sloss,

        "dloss": flow.dloss,

        "sload": unsw_sload,

        "dload": unsw_dload,

        # "swin": flow.swin,
        # "dwin": flow.dwin,

        "stcpb": flow.stcpb,

        "dtcpb": flow.dtcpb,

        "synack": flow.synack,

        "ackdat": flow.ackdat,

        "tcprtt": flow.tcprtt,

        "is_sm_ips_ports": flow.is_sm_ips_ports,

        "response_body_len": flow.response_body_len,
    }