Network Monitoring System

Overview

The Network Monitoring System is part of the Passive Intrusion Detection System (IDS). It captures live network traffic, analyzes network flows, and sends extracted features to the IDS backend for machine-learning-based intrusion detection.

Features

Live network packet capture

Network flow tracking

Network traffic feature extraction

Integration with the IDS prediction API

Detection of normal and suspicious network activity

Passive monitoring without blocking traffic

Requirements

Python 3

Required Python libraries

Npcap for packet capture on Windows

Running IDS backend

Usage

Run the network monitor:

python -m live.network_packet_collector_collect_all_extended (or use run.bat)
****Important : right now the sniffer is set to  sniffer = AsyncSniffer(
        iface=interface,
        #filter="host 208.65.102.229 and port 86", # my site for testing
        #filter="host 8.8.8.8",
        prn=packet_collector_test,
        store=False
    )
	Use your own filter for testing a specific IP

Select the network interface to monitor.

The system will start capturing network packets, extracting flow features, and sending completed flows to the IDS backend for classification.

IDS Integration

The monitor communicates with the IDS backend using:

POST http://localhost:8000/predict/unsw

Prediction results identify network flows as NORMAL or ATTACK.

Note

This is a passive monitoring system. It detects potentially malicious network activity but does not block or modify network traffic.