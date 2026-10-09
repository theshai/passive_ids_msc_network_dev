#Network Monitoring System

#Overview

The Network Monitoring System is a component of the Passive Intrusion Detection System (IDS).

It captures live network traffic, tracks network flows, extracts relevant network features, and sends the collected information to the IDS backend for machine-learning-based intrusion detection.

The system operates in passive mode, monitoring network activity without blocking or modifying traffic.

##Features

Live Packet Capture - Captures network packets from a selected network interface.

Network Flow Tracking - Groups packets into network flows for analysis.

Feature Extraction - Extracts network traffic characteristics for machine-learning classification.

IDS Integration - Sends extracted features to the IDS prediction API.

Intrusion Detection - Identifies potentially malicious network flows.

Passive Monitoring - Observes network traffic without interfering with network communications.

##Requirements

Before running the Network Monitor, ensure the following are installed or available:

Python 3

Required Python libraries

Npcap (for packet capture on Windows)

Running Passive IDS backend

##Running the Network Monitor

The monitor can be started using either of the following methods.

Option 1 - Python command

python -m live.network_packet_collector_collect_all_extended

Option 2 - Windows batch file

run.bat

After starting the application:

Select the network interface you want to monitor.

The system will begin capturing live network traffic.

Captured packets will be grouped into network flows.

Flow features will be extracted and sent to the IDS backend for classification.

Prediction results will identify traffic as NORMAL or ATTACK.

Configuring the Packet Capture Filter

Important: The network monitor currently uses the following AsyncSniffer configuration:

sniffer = AsyncSniffer(
    iface=interface,
    #filter="host 208.65.102.229 and port 86",  # Test server
    #filter="host 8.8.8.8",
    prn=packet_collector_test,
    store=False
)

By default, no packet filter is enabled, so the monitor captures all traffic visible on the selected network interface.

Monitoring a Specific IP Address

To monitor traffic associated with a specific IP address, enable the filter parameter:

sniffer = AsyncSniffer(
    iface=interface,
    filter="host 192.168.1.100",
    prn=packet_collector_test,
    store=False
)

Monitoring a Specific IP Address and Port

To capture only traffic associated with a particular IP address and port:

sniffer = AsyncSniffer(
    iface=interface,
    filter="host 192.168.1.100 and port 80",
    prn=packet_collector_test,
    store=False
)

Note: Replace the example IP address and port with your own testing configuration.

IDS Integration

The Network Monitor communicates with the Passive IDS backend through an HTTP API.

##Prediction endpoint:

POST http://localhost:8000/predict/unsw

The backend processes the extracted network features using the trained machine-learning model and returns a classification result.

Possible classifications:

NORMAL - Traffic classified as normal.

ATTACK - Traffic classified as potentially malicious.

##Limitations

The IDS backend must be running to perform predictions.

Packet capture requires appropriate permissions and a compatible capture driver.

Detection accuracy depends on the trained machine-learning model and the quality of extracted features.

Only traffic visible on the selected network interface can be monitored.

Important Note

This system is designed exclusively for passive intrusion detection.

It monitors and analyzes network traffic but does not block connections, modify packets, or automatically prevent attacks.