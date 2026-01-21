import argparse
import socket
import scapy.all as scapy
import concurrent.futures
import requests
import string
import sys
from datetime import datetime
from tqdm import tqdm

def identify_service(port):
    """
    Tries to map a port number to a service name.
    """
    # 1. Manual Dictionary for very common aliases
    # You can add whatever you want here!
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
    }

    if port in common_ports:
        return common_ports[port]

    # 2. If not in our list, ask the Operating System
    try:
        service_name = socket.getservbyport(port, "tcp")
        return service_name.upper()
    except:
        return "Unknown"

# --- 1. ARGUMENT PARSING ---
def get_arguments():
    parser = argparse.ArgumentParser(
        description="NetAudit - Advanced Python Network Scanner",
        epilog="""Examples:
  [Discovery Mode - Find Devices on Wi-Fi]
  sudo python net_audit.py -t 192.168.1.1/24 -m discovery

  [Port Scan Mode - Scan a Server/Website]
  python net_audit.py -t scanme.nmap.org -m port -s 1 -e 1000
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", dest="target", help="Target IP, Domain, or Range", required=True)
    parser.add_argument("-m", "--mode", dest="mode", help="Scan Mode: 'discovery' or 'port'", required=True)
    parser.add_argument("-s", "--start", dest="start_port", help="Start Port (Default: 1)", type=int, default=1)
    parser.add_argument("-e", "--end", dest="end_port", help="End Port (Default: 1024)", type=int, default=1024)
    parser.add_argument("--threads", dest="threads", help="Max Threads (Default: 100)", type=int, default=100)

    # Print help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

# --- 2. RECONNAISSANCE MODULES ---
def resolve_target(target):
    """Converts Domain (google.com) to IP (142.250.x.x)"""
    try:
        ip = socket.gethostbyname(target)
        print(f"[*] Resolved Target: {target} -> {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target}'.")
        return None

def scan_web_headers(target):
    """Fetches HTTP headers to identify Web Server software"""
    print(f"\n[*] Fetching HTTP Headers for: {target}")
    print("-" * 60)
    
    for protocol in ["http", "https"]:
        url = f"{protocol}://{target}"
        try:
            response = requests.head(url, timeout=3, allow_redirects=True)
            print(f"[{protocol.upper()}] Status: {response.status_code}")
            
            headers_of_interest = ["Server", "X-Powered-By", "Date", "Content-Type"]
            for header in headers_of_interest:
                if header in response.headers:
                    print(f"    {header}: {response.headers[header]}")
            print("") # Newline for readability
        except requests.exceptions.RequestException:
            pass # Silent fail if protocol not supported

# --- 3. DISCOVERY MODULE (ARP) ---
def scan_arp(ip):
    """Finds active devices on local network using ARP"""
    print(f"\n[*] Starting ARP Discovery on: {ip}")
    print("-" * 60)
    
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    except PermissionError:
        print("[!] Error: You need sudo/admin privileges for ARP scans.")
        return []

    clients_list = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
        
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except socket.herror:
            hostname = "Unknown"
            
        clients_list.append({"ip": ip_addr, "mac": mac_addr, "hostname": hostname})

    return clients_list

def print_arp_result(results_list):
    print("IP Address\t\tMAC Address\t\tHostname")
    print("-" * 70)
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['hostname']}")

# --- 4. PORT SCANNING MODULE ---
def grab_banner(s):
    """Robust Banner Grabbing: Listen, Trigger, Clean"""
    try:
        # STRATEGY 1: Passive Listen (Wait 2s for server to speak)
        try:
            banner_bytes = s.recv(1024)
        except socket.timeout:
            banner_bytes = b""

        # STRATEGY 2: Active Trigger (If silent, send Enter key)
        if len(banner_bytes) == 0:
            s.send(b'\r\n')
            try:
                banner_bytes = s.recv(1024)
            except socket.timeout:
                pass

        # STRATEGY 3: Clean & Filter (Remove Telnet/Binary garbage)
        if not banner_bytes:
            return "Unknown Service"
            
        banner_str = banner_bytes.decode('utf-8', errors='ignore')
        # Keep only printable characters to avoid crashing the terminal
        clean_banner = ''.join(filter(lambda x: x in string.printable, banner_str)).strip()
        
        return clean_banner if clean_banner else "Unknown Service (Empty)"
        
    except Exception:
        return "Unknown Service"

def scan_single_port(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) 
        
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            # Port is open! Try to grab banner
            s.settimeout(2)
            banner = grab_banner(s)
            s.close()
            
            # --- NEW LOGIC HERE ---
            # If banner is generic/empty, use the Port Map
            if "Unknown" in banner or not banner:
                service_name = identify_service(port)
                # We label it as (Default) so we know we guessed it
                banner = f"{service_name} (Default)"
            # ----------------------
            
            return port, True, banner
        
        s.close()
        return port, False, None 
    except:
        return port, False, None

def run_threaded_port_scan(target_ip, start_port, end_port, max_threads):
    print(f"\n[*] Starting Port Scan on: {target_ip}")
    print(f"[*] Range: {start_port}-{end_port} | Threads: {max_threads}")
    print("-" * 60)
    
    port_range = range(start_port, end_port + 1)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_single_port, target_ip, port): port for port in port_range}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_port), total=len(port_range), desc="Scanning", ncols=80):
            port, is_open, banner = future.result()
            if is_open:
                tqdm.write(f"[+] Port {port:<5} OPEN : {banner}")

# --- 5. MAIN EXECUTION ---
if __name__ == "__main__":
    args = get_arguments()
    start_time = datetime.now()

    # STEP 1: RESOLVE TARGET
    target_ip = resolve_target(args.target)

    if target_ip:
        # STEP 2: MODE SELECTION
        if args.mode.lower() == "discovery":
            # ARP Scan (Requires Root/Admin usually)
            results = scan_arp(target_ip)
            if results:
                print_arp_result(results)
            else:
                print("[*] No devices found. (Ensure you are scanning a local subnet like 192.168.1.1/24)")

        elif args.mode.lower() == "port":
            # Check if input was a Domain (not an IP) to run Web Headers
            if not args.target.replace('.','').isdigit():
                 scan_web_headers(args.target)

            # Run Port Scan
            run_threaded_port_scan(target_ip, args.start_port, args.end_port, args.threads)
        
        else:
            print("[!] Invalid Mode. Use 'discovery' or 'port'.")

    end_time = datetime.now()
    print(f"\n[*] Scan completed in: {end_time - start_time}")
