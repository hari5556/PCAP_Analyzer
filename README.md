# Network Traffic Analysis Tool

## Description
This project is a tool for analyzing network traffic to detect potential malware packets within a given PCAP (Packet Capture) file. By utilizing the Scapy library, the tool scans the packet data for specific patterns associated with malicious activities, helping network administrators and security professionals identify threats in their network traffic.

## Features
- Scans PCAP files for packets containing malicious payloads.
- Utilizes regular expressions to identify various types of malware, including trojans, exploits, backdoors, and more.
- Displays detailed information about matching packets, including timestamps, source and destination IPs, protocols, and packet summaries.

## Requirements
- Python 3.x
- Scapy library

## Installation
To install the required dependencies, you can use pip. Run the following command:

```bash
pip install scapy

