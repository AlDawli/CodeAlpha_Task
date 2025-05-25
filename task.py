#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import sys

def packet_callback(pkt):
    # Only process IP packets
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        # Determine protocol name
        if proto == 1 and ICMP in pkt:
            proto_name = 'ICMP'
        elif proto == 6 and TCP in pkt:
            proto_name = 'TCP'
        elif proto == 17 and UDP in pkt:
            proto_name = 'UDP'
        else:
            proto_name = str(proto)

        # Ports (if applicable)
        sport = dport = None
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        # Payload
        payload = None
        if Raw in pkt:
            payload = pkt[Raw].load

        # Print summary
        summary = f"{src_ip} -> {dst_ip} | Protocol: {proto_name}"
        if sport and dport:
            summary += f" | Ports: {sport} -> {dport}"
        print(summary)

        # Print payload as hex/ascii
        if payload:
            try:
                printable = payload.decode('utf-8', errors='replace')
            except Exception:
                printable = str(payload)
            print(f"Payload:\n{printable}\n")
        else:
            print("No Payload\n")

def main():
    # Define capture settings
    iface = None  # Auto-select interface; or e.g., 'eth0'
    packet_count = 0  # 0 means infinite until user stops
    bpf_filter = ''  # Empty = capture all; e.g., 'tcp' or 'udp port 53'

    print("Starting packet capture... (Ctrl+C to stop)")
    try:
        sniff(iface=iface, filter=bpf_filter, prn=packet_callback, count=packet_count)
    except PermissionError:
        sys.exit("Permission denied: You need root privileges to capture packets.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

if __name__ == '__main__':
    main()


"""
Simple Python Network Packet Sniffer and Analyzer

Features:
1. Captures live packets using Scapy
2. Parses packet layers to extract:
   - Source and destination IP addresses
   - Protocol type (ICMP, TCP, UDP, etc.)
   - Source/destination ports (for TCP/UDP)
   - Payload (raw data)
3. Prints a concise summary and detailed view for each packet

Usage:
  sudo python3 packet_sniffer.py  # Root privileges required
  Press Ctrl+C to stop capturing

"""
