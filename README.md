C-Based Network Packet Sniffer & Protocol Analyzer

A lightweight, extensible packet sniffer written in C, designed to capture, analyze, and visualize network traffic in real-time.

---

## 🚀 Features

- 📡 **Live packet capture** using `libpcap`
- 🔍 **Protocol parsing**: Ethernet, IP, TCP, UDP, ARP, DNS, HTTP, TLS
- 🎯 **Custom filters**: by protocol, IP address, port, or protocol number
- 📊 **CSV & PCAP logging**: easy to export or replay
- 📈 **Auto-generated HTML reports** with graphs (via Python)
- ✅ Works on **macOS**, **Linux**, and **M1 ARM64** devices

---

## 📸 Terminal Output (Boxed)

![alt text](image.png)

## 📦 Installation

### Prerequisites
- `libpcap` (default on macOS and Linux)
- `gcc` or `clang`
- Python 3 for report generation (`pip install pandas matplotlib`)

### Build

git clone https://github.com/KarthikChayanam/C-Based-Network-Packet-Sniffer.git
cd C-Based-Network-Packet-Sniffer
make

### Run

sudo ./build/sniffer -i <interface> --all -n <packet_count> -o <csv_file> --pcap <pcap_file>

### Flags

-i <iface>	                                           Network interface (e.g., en0, eth0)
--tcp                                                      / --udp / --icmp / --all	Protocol filter
-n <N>	                                                Number of packets to capture
-o <file.csv>	                                    CSV output log
--pcap <file.pcap>	                          Save raw packets to .pcap
--src-ip                                                 IP	Filter by source IP
--dst-ip                                                 IP	Filter by destination IP
--src-port                                            PORT	Filter by source port
--dst-port                                            PORT	Filter by destination port
--proto-num                                       N	Filter by protocol number


#### Report

python3 scripts/report.py

Reports are :
reports/pps.png: Packets per second
reports/proto_dist.png: Protocol distribution
reports/top_hosts.csv: Top senders
reports/sniff-summary.html: Full HTML report



