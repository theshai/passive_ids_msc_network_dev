import numpy as np


def extract_cic2017_from_flow(flow):
    """
	Based on the previous unsw version, trying to extract all the reasonble 
	features to use in live info from the network
	
	***** ment to be used ONLY with the extended version of the files********

    IMPORTANT:
    CIC-IDS2017 / CICFlowMeter timing features are represented
    in microseconds.

    The tracker:
        - duration is stored in seconds
        - forward/backward interpacket times are stored in milliseconds

    Therefore conversions are performed here rather than changing
    the tracker, so the existing UNSW implementation is unaffected.
    """

    #-----------------------------------------------------------
    # FLOW DURATION
    #-----------------------------------------------------------

    # Tracker duration is seconds.
    # CIC Flow Duration is microseconds.
    flow_duration_us = flow.duration * 1_000_000


    #-----------------------------------------------------------
    # FLOW IAT
    #-----------------------------------------------------------
    # all_packet_times contains datetime objects.
    # Calculate consecutive packet differences in microseconds.

    flow_iats = []

    if len(flow.all_packet_times) > 1:

        for i in range(1, len(flow.all_packet_times)):

            diff = (
                flow.all_packet_times[i]
                - flow.all_packet_times[i - 1]
            ).total_seconds() * 1_000_000

            flow_iats.append(diff)


    flow_iat_mean = (
        sum(flow_iats) / len(flow_iats)
        if flow_iats
        else 0
    )

    flow_iat_std = (
    np.std(flow_iats)
    if len(flow_iats) > 1
    else 0
)

    flow_iat_min = (
        min(flow_iats)
        if flow_iats
        else 0
    )


    #-----------------------------------------------------------
    # FORWARD IAT
    #-----------------------------------------------------------
    # Existing tracker stores these in milliseconds.
    # Convert milliseconds -> microseconds.

    forward_iats_us = [
        value * 1000
        for value in flow.forward_interpacket_times
    ]

    fwd_iat_min = (
        min(forward_iats_us)
        if forward_iats_us
        else 0
    )


    #-----------------------------------------------------------
    # BACKWARD IAT
    #-----------------------------------------------------------

    backward_iats_us = [
        value * 1000
        for value in flow.backward_interpacket_times
    ]

    bwd_iat_total = (
        sum(backward_iats_us)
        if backward_iats_us
        else 0
    )

    bwd_iat_mean = (
        sum(backward_iats_us) / len(backward_iats_us)
        if backward_iats_us
        else 0
    )

    bwd_iat_std = (
        np.std(backward_iats_us)
        if len(backward_iats_us) > 1
        else 0
    )

    bwd_iat_max = (
        max(backward_iats_us)
        if backward_iats_us
        else 0
    )


    #-----------------------------------------------------------
    # PACKET LENGTHS
    #-----------------------------------------------------------

    fwd_lengths = flow.forward_packet_lengths
    bwd_lengths = flow.backward_packet_lengths

    all_lengths = (
        fwd_lengths +
        bwd_lengths
    )


    fwd_packet_length_max = (
        max(fwd_lengths)
        if fwd_lengths
        else 0
    )

    fwd_packet_length_min = (
        min(fwd_lengths)
        if fwd_lengths
        else 0
    )

    fwd_packet_length_mean = (
        sum(fwd_lengths) / len(fwd_lengths)
        if fwd_lengths
        else 0
    )


    bwd_packet_length_max = (
        max(bwd_lengths)
        if bwd_lengths
        else 0
    )

    bwd_packet_length_min = (
        min(bwd_lengths)
        if bwd_lengths
        else 0
    )


    min_packet_length = (
        min(all_lengths)
        if all_lengths
        else 0
    )


    #-----------------------------------------------------------
    # FLOW RATES
    #-----------------------------------------------------------
    # Tracker byte_rate and packet_rate are already per second.

    flow_bytes_per_second = flow.byte_rate
    flow_packets_per_second = flow.packet_rate


    #-----------------------------------------------------------
    # BACKWARD PACKETS / SECOND
    #-----------------------------------------------------------

    if flow.duration > 0:

        bwd_packets_per_second = (
            flow.backward_packet_count /
            flow.duration
        )

    else:

        bwd_packets_per_second = 0


    #-----------------------------------------------------------
    # DOWN / UP RATIO
    #-----------------------------------------------------------

    if flow.forward_packet_count > 0:

        down_up_ratio = (
            flow.backward_packet_count /
            flow.forward_packet_count
        )

    else:

        down_up_ratio = 0


    #-----------------------------------------------------------
    # INITIAL TCP WINDOWS
    #-----------------------------------------------------------

    init_win_forward = (
        flow.initial_forward_window
        if flow.initial_forward_window is not None
        else 0
    )

    init_win_backward = (
        flow.initial_backward_window
        if flow.initial_backward_window is not None
        else 0
    )

    min_seg_size_forward = (
        flow.min_forward_segment_size
        if flow.min_forward_segment_size is not None
        else 0
    )

    # Forward average bytes per bulk
    if flow.forward_bulk_count > 0:
        fwd_avg_bytes_bulk = (
            flow.forward_bulk_size /
            flow.forward_bulk_count
        )

        fwd_avg_packets_bulk = (
            flow.forward_bulk_packet_count /
            flow.forward_bulk_count
        )
    else:
        fwd_avg_bytes_bulk = 0
        fwd_avg_packets_bulk = 0


    # Forward average bulk rate
    if flow.forward_bulk_duration > 0:
        fwd_avg_bulk_rate = (
            flow.forward_bulk_size /
            flow.forward_bulk_duration
        )
    else:
        fwd_avg_bulk_rate = 0


    # Backward average bytes per bulk
    if flow.backward_bulk_count > 0:
        bwd_avg_bytes_bulk = (
            flow.backward_bulk_size /
            flow.backward_bulk_count
        )

        bwd_avg_packets_bulk = (
            flow.backward_bulk_packet_count /
            flow.backward_bulk_count
        )
    else:
        bwd_avg_bytes_bulk = 0
        bwd_avg_packets_bulk = 0


    # Backward average bulk rate
    if flow.backward_bulk_duration > 0:
        bwd_avg_bulk_rate = (
            flow.backward_bulk_size /
            flow.backward_bulk_duration
        )
    else:
        bwd_avg_bulk_rate = 0

    # ---------------------------------------------------------
    # CIC Active / Idle features
    # ---------------------------------------------------------

    if len(flow.cic_active) > 1:
        active_mean = float(np.mean(flow.cic_active))
        active_std = float(np.sqrt(np.var(flow.cic_active)))
        active_max = float(max(flow.cic_active))
    else:
        active_mean = 0
        active_std = 0
        active_max = 0


    if len(flow.cic_idle) > 1:
        idle_std = float(np.sqrt(np.var(flow.cic_idle)))
    else:
        idle_std = 0  

    # ---------------------------------------------------------
    # CIC Active / Idle values are stored in seconds.
    # CIC-IDS2017 timing features use microseconds.
    # ---------------------------------------------------------

    active_mean *= 1_000_000
    active_std *= 1_000_000
    active_max *= 1_000_000
    idle_std *= 1_000_000 


    #-----------------------------------------------------------
    # BUILD CIC-IDS2017 FEATURE DICTIONARY
    #-----------------------------------------------------------
    #
    # Keep the names EXACTLY as they appear in your training
    # dataframe / selected_columns.
    #-----------------------------------------------------------

    features = {

        "Destination Port":
            flow.dst_port if flow.dst_port is not None else 0,

        "Flow Duration":
            flow_duration_us,

        "Total Fwd Packets":
            flow.forward_packet_count,

        "Total Length of Fwd Packets":
            flow.forward_bytes,

        "Fwd Packet Length Max":
            fwd_packet_length_max,

        "Fwd Packet Length Min":
            fwd_packet_length_min,

        "Fwd Packet Length Mean":
            fwd_packet_length_mean,

        "Bwd Packet Length Max":
            bwd_packet_length_max,

        "Bwd Packet Length Min":
            bwd_packet_length_min,

        "Flow Bytes/s":
            flow_bytes_per_second,

        "FlowPackets/s":
            flow_packets_per_second,

        "Flow IAT Mean":
            flow_iat_mean,

        "Flow IAT Std":
            flow_iat_std,

        "Flow IAT Min":
            flow_iat_min,

        "Fwd IAT Min":
            fwd_iat_min,

        "Bwd IAT Total":
            bwd_iat_total,

        "Bwd IAT Mean":
            bwd_iat_mean,

        "Bwd IAT Std":
            bwd_iat_std,

        "Bwd IAT Max":
            bwd_iat_max,

        "Fwd PSH Flags":
            flow.forward_psh_flags,

        "Bwd PSH Flags":
            flow.backward_psh_flags,

        "Fwd URG Flags":
            flow.forward_urg_flags,

        "Bwd URG Flags":
            flow.backward_urg_flags,

        "Fwd Header Length":
            flow.forward_header_length,

        "Bwd Header Length":
            flow.backward_header_length,

        "Bwd Packets/s":
            bwd_packets_per_second,

        "min_seg_size_forward":
            min_seg_size_forward,

        "Min Packet Length":
            min_packet_length,

        "FIN Flag Count":
            flow.fin_flag_count,

        "RST Flag Count":
            flow.rst_flag_count,

        "PSH Flag Count":
            flow.psh_flag_count,

        "ACK Flag Count":
            flow.ack_flag_count,

        "URG Flag Count":
            flow.urg_flag_count,

        "Down/Up Ratio":
            down_up_ratio,

        "Init_Win_bytes_forward":
            init_win_forward,

        "Init_Win_bytes_backward":
            init_win_backward,

        "Fwd Avg Bytes/Bulk":
            fwd_avg_bytes_bulk,

        "Fwd Avg Packets/Bulk":
            fwd_avg_packets_bulk,

        "Fwd Avg Bulk Rate":
            fwd_avg_bulk_rate,

        "Bwd Avg Bytes/Bulk":
            bwd_avg_bytes_bulk,

        "Bwd Avg Packets/Bulk":
            bwd_avg_packets_bulk,

        "Bwd Avg Bulk Rate":
            bwd_avg_bulk_rate,

        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Idle Std": idle_std,
       
    }

    return features