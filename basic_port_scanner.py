#!/usr/bin/env python3

import socket # Import socket library for network connections and port scanning

def scan_ports(target_ip, ports=None):

    if ports is None:
        ports = range(1, 65536) # Scan all ports

    print(f"Scanning {target_ip}")

    for port in ports: # Loop through each port in the list or range
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket using IPv4
        sock.settimeout(0.5) # Short timeout to speed up scanning
        result = sock.connect_ex((target_ip, port)) # Try to connect to the target IP and port, returns 0 if successful
        if result == 0: # If connection succeeded, port is open
            try:
                service = socket.getservbyport(port) # Try to get the standard service name for this port
            except:
                service = "Unknown" # If service name is not found, mark as Unknown
            print(f"[OPEN] Port {port} - service: {service}") # Print open port and service

        sock.close() # Close the socket to free system resources

    print("Scan Completed.")

# Get target IP from user
target_ip = input("Enter Target IP: ")

# Ask user if they want to scan specific ports or all
choice = input("Do you want to scan specific ports? (y/n)").lower()

if choice == "y":
    ports_input = input("Enter ports separated by commas (e.g. 22,80, 443)")
    # Convert input to a list of integers
    ports_to_scan = [int(p.strip()) for p in ports_input.split(",")] # Convert input string into list of integers
else:
    ports_to_scan = None #Scan all ports
# Call the scanning function with the target IP and chosen ports
scan_ports(target_ip, ports_to_scan) # Execute the port  scanning function