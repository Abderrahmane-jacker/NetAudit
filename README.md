# 🔍 NetAudit - Python Network Scanner

**NetAudit** is a lightweight, multi-threaded network scanner. It combines ARP discovery, port scanning, and service banner grabbing into a single command-line tool.

> **⚠️ Disclaimer:** This tool is for educational purposes and authorized testing only. Scanning networks without permission is illegal. The author is not responsible for misuse.

## 🚀 Features
- **ARP Discovery:** Identifies active devices (IP, MAC, and Hostname) on a local network.
- **Multi-threaded Port Scanning:** Scans hundreds of ports per second.
- **Banner Grabbing:** Attempts to identify the service running on open ports.
- **CLI Interface:** Professional command-line arguments using `argparse`.
- **Progress Tracking:** Visual progress bars for long scans.

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone [https://github.com/Abderrahmane-jacker/NetworkScanner.git](https://github.com/Abderrahmane-jacker/NetworkScanner.git)
   cd NetworkScanner
2. **Run the tool**
   ```bash
   pip install requirements.txt
   # Windows (Run as Admin)
    python net_audit.py -t 192.168.1.1/24 -m discovery
   # Linux / macOS (Run with sudo)
    sudo python3 net_audit.py -t 192.168.1.1/24 -m discovery
