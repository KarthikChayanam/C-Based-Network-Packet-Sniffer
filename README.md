# 🕵️‍♂️ C-Based Network Packet Sniffer & Protocol Analyzer
A lightweight, extensible packet sniffer written in C, designed to **capture, analyze, and visualize** network traffic in real-time.

## 🚀 Features
- 📡 **Live packet capture** using `libpcap`
- 🔍 **Protocol parsing**: Ethernet, IP, TCP, UDP, ARP, DNS, HTTP, TLS
- 🎯 **Custom filters**: by protocol, IP address, port, or protocol number
- 📊 **CSV & PCAP logging**: easy to export or replay in Wireshark
- 📈 **Auto-generated HTML reports** with graphs (via Python)
- ✅ **Cross-platform**: macOS, Linux, and Apple Silicon (M1 ARM64)

## 📸 Terminal Output (Boxed Format)
```
┌──── Ethernet ─────────────────────────────┐
│  Src MAC: AA:E0:4E:C1:9C:44               │
│  Dst MAC: B4:A7:C6:18:43:10               │
│  Type:    0x0800                          │
├──── IP Header ────────────────────────────┤
│  Src IP:  192.168.1.3                     │
│  Dst IP:  162.159.134.234                 │
│  Proto:   TCP (6)                         │
├──── TCP Segment ──────────────────────────┤
│  Src Port: 59569                          │
│  Dst Port: 443                            │
└───────────────────────────────────────────┘
```

## 📦 Installation

### Prerequisites
- `libpcap` (usually pre-installed on macOS/Linux)
- `gcc` or `clang`
- Python 3 with:
  ```bash
  pip install pandas matplotlib
  ```

### Build Instructions
```bash
git clone https://github.com/KarthikChayanam/C-Based-Network-Packet-Sniffer.git
cd C-Based-Network-Packet-Sniffer
make
```

## 🧪 Run the Sniffer
```bash
sudo ./build/sniffer -i <interface> --all -n <packet_count> -o <csv_file> --pcap <pcap_file>
```
> Example:
> ```bash
> sudo ./build/sniffer -i en0 --all -n 100 -o log/sample.csv --pcap log/sample.pcap
> ```

## 🔧 CLI Flags

| Flag               | Description                                 |
|--------------------|---------------------------------------------|
| `-i <iface>`       | Interface to capture on (e.g., `en0`, `eth0`) |
| `--tcp` / `--udp` / `--icmp` / `--all` | Protocol filter         |
| `-n <N>`           | Number of packets to capture                |
| `-o <file.csv>`    | Output CSV log file                         |
| `--pcap <file.pcap>` | Save raw packet dump to `.pcap`           |
| `--src-ip <IP>`    | Filter by source IP                         |
| `--dst-ip <IP>`    | Filter by destination IP                    |
| `--src-port <port>`| Filter by source port                       |
| `--dst-port <port>`| Filter by destination port                  |
| `--proto-num <N>`  | Filter by protocol number (e.g., 6 for TCP) |

## 📊 Generate Report (Step 9)
Use the Python script to analyze the capture and generate visual reports.
```bash
python3 scripts/report.py
```

### Report Outputs:

| File                             | Description                     |
|----------------------------------|---------------------------------|
| `reports/pps.png`                | Packets per second over time    |
| `reports/proto_dist.png`         | Protocol distribution bar chart |
| `reports/top_hosts.csv`          | Top talkers (source IPs)        |
| `reports/sniff-summary.html`     | Full visual HTML report         |

> You can open the HTML report with:
> ```bash
> xdg-open reports/sniff-summary.html   # Linux
> open reports/sniff-summary.html       # macOS
> ```

## 🛣️ Roadmap
- ✅ Deep protocol parsers (DNS, HTTP, TLS, ARP)
- ✅ CSV & PCAP export
- ✅ Step 9: Visual graph-based report
- 🔜 Step 10: IDS heuristics (SYN flood, port scan, bandwidth spike)
- 🔜 Step 11: TUI Dashboard (`htop` style)
- 🔜 Step 12: More protocols (ICMP, DHCP, FTP, MQTT)
- 🔜 Step 13: PCAP replay support (`--read <file.pcap>`)
- 🔜 Step 14: JSON output + SIEM integration

## 📄 License
Licensed under the [MIT License](LICENSE).

## 🙌 Author
**Karthik Chayanam**  
GitHub: [@KarthikChayanam](https://github.com/KarthikChayanam)

## ⭐ Star the Repo
If you find this project useful, consider giving it a ⭐ to support its development!
