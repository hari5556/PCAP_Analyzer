from scapy.all import *
import re

def find_malicious_packets(pcap_file, pattern):
    matching_packets = []
    packets = rdpcap(pcap_file)
    for packet in packets:
        if packet.hasLayer(Raw):
            payload = str(packet[Raw].load)
            if re.search(pattern, payload, re.IGNORECASE):
                matching_packets.append(packet)
    return matching_packets

def print_packet_info(packet):
    print("Timestamp:", packet.time)
    print("Source IP:", packet[IP].src)
    print("Destination IP:", packet[IP].dst)
    print("Protocol:", packet[IP].proto)
    print("Packet Summary:", packet.summary())
    print()

if __name__ == "__main__":
    pcap_file = "2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap"  # Path to the pcap file
    malicious_pattern = r"(mal(?:icious|w(?:are|32164|orm))|trojan|exploit(?:action)?|backdoor|bot|ad(?:ware|vanced|\s-]?persistent|\s-]?threat)|rootkit|key(?:logger|gen)|bot(?:net)|virus|crypto(?:miner|jacking)|rat|remote|\s-]?access(?:[\s-]?tool)?|command|\s-]?and|\s-]?code|buffer|\s-]?overflow|zero|\s-]?day|apt|hack(?:ing|tivist)|ddos|denial|\s-]?off|\s-]?service|engineering)"  # Regular expression pattern
    matching_packets = find_malicious_packets(pcap_file, malicious_pattern)
    if matching_packets:
        print("Matching packets found:")
        for packet in matching_packets:
            print_packet_info(packet)
    else:
        print("No matching packets found.")
