# 🛡️ NetAudit - Advanced Python Network Scanner

**NetAudit** is a professional-grade, multi-threaded network scanner built for cybersecurity education. It combines low-level packet crafting (ARP) with high-level socket operations to perform deep network reconnaissance.

Unlike basic scanners, NetAudit features **Smart Service Detection**, which identifies running services even if the server is silent or headerless.

> **⚠️ Disclaimer:** This tool is for educational purposes and authorized security testing only. Scanning networks or websites without permission is illegal.

## 🚀 Key Features

* **⚡ Multi-Threaded Port Scanning:** Scans thousands of ports in seconds using concurrent threading.
* **📡 ARP Network Discovery:** Maps local networks to find active devices (IP, MAC, & Hostname).
* **🕵️‍♂️ Smart Service Detection:**
    * **Banner Grabbing:** Uses a "Listen-Trigger-Clean" strategy to capture banners from shy services (like Telnet).
    * **Auto-Identification:** Falls back to a database of well-known ports if the banner is hidden.
* **🌐 Web Reconnaissance:** Automatically fetches HTTP headers (Server type, X-Powered-By) when scanning domains.
* **📊 Visual Progress:** Real-time progress bars using `tqdm`.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Abderrahmane-jacker/Net_Audit.git
    cd NetAudit
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

**Note for Windows Users:** You must install [Npcap](https://npcap.com/) (select "Install in WinPcap API-compatible Mode") for ARP scanning to work.

## 💻 Usage

Run the tool using `python net_audit.py`. You must select a mode: `discovery` or `port`.

### 1. Port Scan (Server/Website)
Best for auditing specific servers. It resolves domains, checks Web Headers, and scans ports with service detection.
```bash
# Scan a Network (Discovery scan)
python net_audit.py -t 192.168.1.0/24 -m discovery

# Scan a website (Standard Scan)
python net_audit.py -t scanme.nmap.org -m port

# Deep Scan (Specific Range + High Speed)
python net_audit.py -t 192.168.1.15 -m port -s 1 -e 5000 --threads 200
