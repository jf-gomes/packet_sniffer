from scapy.all import sniff, IP, TCP, UDP, ICMP
import logging
import json
import os
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(message)s")

log_file = "logs/captured_packets.json"

def log_packet_json(packet_data):
    os.makedirs("logs", exist_ok=True)
    with open(log_file, "a") as f:
        json.dump(packet_data, f)
        f.write("\n")

def print_packet(packet):
    
    # Packet info.
    if IP in packet:
        ip_layer = packet[IP]
        proto = ip_layer.proto
        protocol = get_protocol_name(packet)

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        details = f"[{protocol}] Source IP: {source_ip} → Destination IP: {destination_ip}"

        # Port details
        if protocol in ["TCP", "UDP"]:
            source_port = packet[protocol].sport
            destination_port = packet[protocol].dport
            details += f" | Source port: {source_port} -> Destination port: {destination_port}"

        logging.info(details)

        # JSON logs
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "protocol": proto,
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
        }

        log_packet_json(packet_data=packet_data)

def get_protocol_name(packet):

    if TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    elif ICMP in packet:
        return "ICMP"
    else:
        return "OUTRO"

def capture_packets(interface="eth0", protocol=None, packet_count=0):

    bpf_filter = protocol if protocol else ""
    logging.info(f"Capturing packets in interface: {interface}")
    if bpf_filter:
        logging.info(f"Filter: {bpf_filter.upper()}")
    logging.info("Press Ctrl + C to stop...")

    try:
        sniff(iface=interface, filter=bpf_filter, prn=print_packet, count=packet_count, store=False)
    except PermissionError:
        logging.error("Permission denied. Try running with sudo/admin.")
    except Exception as e:
        logging.error(f"Capture error: {e}")
