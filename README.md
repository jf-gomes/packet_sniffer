# 🐍 Packet Sniffer made with Python

## Overview

A network packet sniffer developed with Python with Scapy framework.
Allows you to capture network packets in time, filter them by protocol, and storage JSON logs.

## ▶️ How to Run

1. **Clone this repo**

```
git clone https://github.com/jf-gomes/packet_sniffer.git
cd packet_sniffer
```

2. **Create and activate virtual environment (optional, but recommended)**

```
# macOS/Linux
python -m venv venv
source venv/bin/activate

# Windows
python3 -m venv venv
venv\Scripts\activate
```

3. **Install dependencies**

```
pip install -r requirements.txt
```

4. **Run the sniffer (sudo/admin privileges needed)**

```
# Capture all packets. Change "wlan0" to your network interface.
sudo python main.py -i wlan0

# Capture only TCP packets.
sudo python main.py -i wlan0 -p tcp

# Capture 10 UDP packets.
sudo python main.py -i wlan0 -p udp -c 10
```

## Used Technologies

- Python
- [Scapy](https://scapy.net/)

## Project structure

```
packet_sniffer/
├── main.py
├── sniffer.py
├── requirements.txt
├── logs/
│   └── captured_packets.json
└── README.md
```

## Author

João Gomes
[LinkedIn](https://www.linkedin.com/in/joao-v-f-gomes/)