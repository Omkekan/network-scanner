import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *

# Dictionary to hold scan results
scan_results = {}

# Function to display results
def display_results(results):
    print("\nOpen Ports and Services:")
    for port, info in results.items():
        if info["State"] == "Open":
            print(f"Port: {port} - Service: {info['Service']}")

# Function to scan a single port
def scan_port(target, port):
    src_port = RandShort()
    syn_packet = IP(dst=target)/TCP(dport=port, sport=src_port, flags='S')
    try:
        response = sr1(syn_packet, timeout=1, verbose=0)

        if response is None:
            scan_results[port] = {"State": "Filtered"}
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                service_name = get_service(port)
                scan_results[port] = {"State": "Open", "Service": service_name}
                # Send RST to close the connection
                rst_packet = IP(dst=target)/TCP(dport=port, sport=src_port, flags='R')
                send(rst_packet, verbose=0)
            elif response[TCP].flags == 0x14:  # RST
                scan_results[port] = {"State": "Closed"}
    except Exception as e:
        print(f"Error scanning port {port}: {e}")

# Function to get service name for a port
def get_service(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except OSError:
        return "Unknown"

# Function to scan a range of ports using ThreadPoolExecutor
def scan_ports(target, port_range):
    print(f"Starting TCP scan on {target}...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in port_range}

        for future in futures:
            try:
                future.result()  # Wait for the port scan to finish
            except Exception as e:
                print(f"Exception occurred: {e}")

# Main function
if __name__ == "__main__":
    target_ip = input("Enter target IP address: ")
    start_port = int(input("Enter start port (1-65535): "))
    end_port = int(input("Enter end port (1-65535): "))

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Please enter values between 1 and 65535.")
    else:
        # Scan TCP ports
        scan_ports(target_ip, range(start_port, end_port + 1))

        # Display results
        display_results(scan_results)

        print("Scan finished.")
