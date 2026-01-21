import argparse
import socket
import scapy.all as scapy
import concurrent.futures
from datetime import datetime
from tqdm import tqdm

# --- 1. ARGUMENT PARSING ---
def get_arguments():
    parser = argparse.ArgumentParser(description="Advanced Python Network Scanner ")
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range (e.g. 192.168.1.1 or 192.168.1.0/24)", required=True)
    parser.add_argument("-m", "--mode", dest="mode", help="Scan Mode: 'discovery' (ARP) or 'port' (Port Scan)", required=True)
    parser.add_argument("-s", "--start", dest="start_port", help="Start Port (Default: 1)", type=int, default=1)
    parser.add_argument("-e", "--end", dest="end_port", help="End Port (Default: 1024)", type=int, default=1024)
    parser.add_argument("--threads", dest="threads", help="Max Threads (Default: 100)", type=int, default=100)
    return parser.parse_args()

# --- 2. MODULE: ARP DISCOVERY (Layer 2) ---
def scan_arp(ip):
    print(f"\n[*] Starting ARP Discovery on: {ip}")
    print("-" * 60)
    
    # Create ARP Request + Ethernet Frame
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    # Send packet
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    except PermissionError:
        print("[!] Error: You need sudo/admin privileges to run ARP scans.")
        return []

    clients_list = []
    for element in answered_list:
        ip_addr = element[1].psrc
        mac_addr = element[1].hwsrc
        
        # Reverse DNS Lookup (Get Hostname)
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except socket.herror:
            hostname = "Unknown"
            
        clients_list.append({"ip": ip_addr, "mac": mac_addr, "hostname": hostname})

    return clients_list

def print_arp_result(results_list):
    print("IP Address\t\tMAC Address\t\tHostname")
    print("-" * 60)
    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['hostname']}")

# --- 3. MODULE: PORT SCANNING (Layer 3/4) ---
def grab_banner(s):
    try:
        # Try to read 1024 bytes from the socket
        return s.recv(1024).decode().strip()
    except:
        return "Unknown Service"

def scan_single_port(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Fast timeout
        
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            # If open, try to grab the banner
            banner = grab_banner(s)
            s.close()
            return port, True, banner
        
        s.close()
        return port, False, None
    except:
        return port, False, None

def run_threaded_port_scan(target_ip, start_port, end_port, max_threads):
    print(f"\n[*] Starting Port Scan on: {target_ip}")
    print(f"[*] Range: {start_port}-{end_port} | Threads: {max_threads}")
    print("-" * 60)
    
    open_ports = []
    
    # Setup the Progress Bar range
    port_range = range(start_port, end_port + 1)
    
    # ThreadPoolExecutor manages the threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Map submits all tasks at once
        # We wrap 'port_range' with tqdm for the progress bar
        future_to_port = {executor.submit(scan_single_port, target_ip, port): port for port in port_range}
        
        for future in tqdm(concurrent.futures.as_completed(future_to_port), total=len(port_range), desc="Scanning", ncols=80):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))
                # Use tqdm.write to print without breaking the bar
                tqdm.write(f"[+] Port {port:<5} OPEN : {banner}")
                
    return open_ports

# --- 4. MAIN ORCHESTRATION ---
if __name__ == "__main__":
    args = get_arguments()
    
    start_time = datetime.now()
    
    if args.mode.lower() == "discovery":
        # Run ARP Scan
        results = scan_arp(args.target)
        if results:
            print_arp_result(results)
        else:
            print("[*] No devices found or permission denied.")
            
    elif args.mode.lower() == "port":
        # Run Port Scan
        # Check if target is a subnet (naive check)
        if "/" in args.target:
            print("[!] Error: Port scanning requires a single IP, not a range.")
        else:
            run_threaded_port_scan(args.target, args.start_port, args.end_port, args.threads)
            
    else:
        print("[!] Invalid Mode. Use 'discovery' or 'port'.")
        
    end_time = datetime.now()
    print(f"\n[*] Scan completed in: {end_time - start_time}")
        