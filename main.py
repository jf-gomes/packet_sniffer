import argparse
from sniffer import capture_packets

def main():
    parser = argparse.ArgumentParser(
        description="🐍 Packet Sniffer tool developed with Python"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Select the network interface that will be listened (ex: eth0, wlan0)",
        required=True
    )

    parser.add_argument(
        "-p", "--protocol",
        help="Protocol filter (tcp, udp, icmp)",
        choices=["tcp", "udp", "icmp"],
        default=None
    )

    parser.add_argument(
        "-c", "--count",
        help="How many packets to capture. Default: 0 (infinite).",
        type=int,
        default=0
    )

    args = parser.parse_args()

    capture_packets(interface=args.interface, protocol=args.protocol, packet_count=args.count)

if __name__ == "__main__":
    main()
