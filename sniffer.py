#!/usr/bin/env python3
"""
PhishGuard Academy - Basic Network Sniffer (Task 1)
--------------------------------------------------
An educational network analysis utility to capture and parse network traffic.
This program displays packet metadata including IP addresses, protocols,
port mappings, TCP flags, and safe payload dumps.

Requirements:
- Python 3.x
- scapy library ('pip install scapy')
- Administrator/Root privileges
- Npcap (Windows) or libpcap (Linux/macOS)
"""

import sys
import os
import argparse
import ctypes
from datetime import datetime

# Attempt to import Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
except ImportError:
    print("[!] Error: Scapy library is not installed.")
    print("    Install it using: pip install scapy")
    sys.exit(1)


def is_admin():
    """Checks if the script is running with administrative/root privileges."""
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False


def get_protocol_name(proto_num):
    """Maps protocol numbers to common names."""
    protocol_map = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        89: "OSPF"
    }
    return protocol_map.get(proto_num, f"PROTO-{proto_num}")


def get_tcp_flags(flags):
    """Parses TCP flags into a human-readable list."""
    flag_map = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }
    active_flags = [flag_map[char] for char in str(flags) if char in flag_map]
    return "|".join(active_flags) if active_flags else str(flags)


def format_payload(payload_bytes, max_len=64):
    """
    Safely formats packet payload into hex representation and clean ASCII text.
    Non-printable characters are replaced with dots ('.').
    """
    if not payload_bytes:
        return "No Payload"

    # Truncate if payload is too long
    truncated = len(payload_bytes) > max_len
    display_bytes = payload_bytes[:max_len]

    # Build Hex view
    hex_dump = " ".join(f"{b:02x}" for b in display_bytes)
    
    # Build ASCII view (filter out non-printable characters)
    ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in display_bytes)

    if truncated:
        hex_dump += " ..."
        ascii_dump += "..."

    return f"\n      [Hex]  {hex_dump}\n      [Text] {ascii_dump}"


def process_packet(packet):
    """Callback function executed for each captured packet."""
    # Check if packet contains IP layer
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    # Base packet metadata
    proto_name = get_protocol_name(ip_layer.proto)
    output = []
    output.append("=" * 80)
    output.append(f"[{timestamp}] - Packet Captured")
    output.append(f"  IP Header:  {ip_layer.src} ---> {ip_layer.dst}")
    output.append(f"  Details:    Protocol: {proto_name} | TTL: {ip_layer.ttl} | Len: {ip_layer.len} bytes")

    # Layer 4 - Transport Analysis
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        flags_str = get_tcp_flags(tcp_layer.flags)
        output.append(f"  TCP Info:   Source Port: {tcp_layer.sport} | Dest Port: {tcp_layer.dport}")
        output.append(f"              Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack} | Flags: [{flags_str}]")
        
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        output.append(f"  UDP Info:   Source Port: {udp_layer.sport} | Dest Port: {udp_layer.dport} | Len: {udp_layer.len}")
        
    elif packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        output.append(f"  ICMP Info:  Type: {icmp_layer.type} | Code: {icmp_layer.code}")

    # Payload - Raw Data Inspection
    if packet.haslayer(Raw):
        raw_payload = packet[Raw].load
        output.append(f"  Payload:    ({len(raw_payload)} bytes)" + format_payload(raw_payload))

    output.append("=" * 80 + "\n")
    print("\n".join(output))


def list_interfaces():
    """Prints the list of active network interfaces to console."""
    print("\n[*] Available Network Interfaces:")
    interfaces = get_if_list()
    for idx, interface in enumerate(interfaces):
        print(f"  [{idx}] {interface}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard Academy: Basic Network Sniffer for Packet Analysis."
    )
    parser.add_argument(
        "-i", "--interface", 
        help="Specify the network interface to sniff on (use -l to list)."
    )
    parser.add_argument(
        "-l", "--list", 
        action="store_true", 
        help="List all active network interfaces and exit."
    )
    parser.add_argument(
        "-c", "--count", 
        type=int, 
        default=0, 
        help="Number of packets to capture (default: 0 = continuous)."
    )
    parser.add_argument(
        "-f", "--filter", 
        default="ip", 
        help="BPF filter (e.g., 'tcp', 'udp', 'icmp', 'port 80'). Default: 'ip'"
    )
    
    args = parser.parse_args()

    # Handle interface listing
    if args.list:
        list_interfaces()
        sys.exit(0)

    # Check for privileges
    if not is_admin():
        print("[!] WARNING: Packet sniffing usually requires Administrator/Root privileges.")
        print("[*] Attempting to proceed. If packet capture fails, re-run with 'sudo' or as Administrator.")
        print("-" * 80)

    # Interface Configuration
    selected_iface = args.interface
    if not selected_iface:
        # Fallback to Scapy's default interface
        try:
            selected_iface = conf.iface
            print(f"[*] No interface specified. Defaulting to: '{selected_iface}'")
        except Exception:
            print("[!] Could not determine default interface. Please use -l and specify one with -i.")
            sys.exit(1)

    print(f"[*] Sniffing active on interface : '{selected_iface}'")
    print(f"[*] Sniffing BPF Filter applied  : '{args.filter}'")
    if args.count > 0:
        print(f"[*] Capture limit set to         : {args.count} packets")
    else:
        print(f"[*] Capture limit set to         : Continuous (Press Ctrl+C to stop)")
    print("[-] Waiting for network packets...")
    print("-" * 80 + "\n")

    # Start sniffing
    try:
        sniff(
            iface=selected_iface,
            filter=args.filter,
            prn=process_packet,
            count=args.count,
            store=False  # Do not store packets in memory to prevent overhead
        )
        print("\n[*] Capture completed successfully.")
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"\n[!] Error during capture: {e}")
        if os.name == 'nt' and "Npcap" in str(e):
            print("    Make sure Npcap is installed and running on your Windows host.")


if __name__ == "__main__":
    main()
