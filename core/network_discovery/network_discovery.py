#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File: /netScanX/netScanX/core/network_discovery.py

import os
import socket
import subprocess
import ipaddress
import configparser
from threading import Thread, Lock
from datetime import datetime

# Load configuration
config = configparser.ConfigParser()
config.read('config/configuration.ini')
interface = config.get('Settings', 'WiFiInterface')

# Global variables
discovered_devices = []
lock = Lock()

def get_local_ip_and_cidr():
    """Get the local IP address and its CIDR prefix."""
    try:
        # Create a socket to determine the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        ip = s.getsockname()[0]
        s.close()
        
        # Get the network interface that has this IP
        output = subprocess.check_output(['ip', '-o', 'addr'], text=True)
        for line in output.split('\n'):
            if f"inet {ip}/" in line:
                # Extract CIDR notation (the /XX part after the IP)
                cidr = int(line.split(f"inet {ip}/")[1].split()[0])
                return ip, cidr
        
        # If we couldn't determine the CIDR, fall back to /24
        print("\033[1;33m[!] Could not determine subnet mask, using default /24\033[0m")
        return ip, 24
    except Exception as e:
        print(f"\033[1;31m[!] Error getting local IP: {e}\033[0m")
        return "127.0.0.1", 8

def get_network_range():
    """Get the network range based on the local IP and actual subnet mask."""
    ip, cidr = get_local_ip_and_cidr()
    try:
        # Create network with the detected CIDR
        network = ipaddress.IPv4Network(f"{ip}/{cidr}", strict=False)
        return ip, network
    except Exception as e:
        print(f"\033[1;31m[!] Error determining network range: {e}\033[0m")
        # Default to a common private network range
        return ip, ipaddress.IPv4Network("192.168.1.0/24")

def ping_host(ip, timeout=1):
    """Ping a host to check if it's alive."""
    param = '-n' if os.name == 'nt' else '-c'
    command = ['ping', param, '1', '-w', str(timeout), str(ip)]
    
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_call(command, stdout=devnull, stderr=devnull)
        return True
    except subprocess.CalledProcessError:
        return False

def get_hostname(ip):
    """Get the hostname of a device."""
    try:
        hostname = socket.getfqdn(str(ip))
        return hostname if hostname != str(ip) else "Unknown"
    except Exception:
        return "Unknown"

def scan_host(ip):
    """Scan a single host."""
    if ping_host(ip):
        hostname = get_hostname(ip)
        mac_address = get_mac_address(ip)
        
        with lock:
            discovered_devices.append({
                'ip': str(ip),
                'hostname': hostname,
                'mac_address': mac_address
            })
            print(f"\033[1;32m[+] Device found: {ip} ({hostname})\033[0m")

def get_mac_address(ip):
    """Get the MAC address of a device."""
    try:
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(f"arp -a {ip}", shell=True).decode('utf-8')
            mac_address = output.split(str(ip))[1].split()[1].strip()
            return mac_address if mac_address != "ff-ff-ff-ff-ff-ff" else "Unknown"
        else:  # Linux/Mac
            output = subprocess.check_output(f"arp -n {ip}", shell=True).decode('utf-8')
            lines = output.strip().split('\n')
            if len(lines) > 1:
                mac_address = lines[1].split()[2]
                return mac_address if mac_address != "ff:ff:ff:ff:ff:ff" else "Unknown"
            return "Unknown"
    except Exception:
        return "Unknown"

def discover_network():
    """Discover devices on the network."""
    print("\033[1;36m[*] Starting network discovery...\033[0m")
    
    # Reset discovered devices
    global discovered_devices
    discovered_devices = []
    
    # Get local IP and network range with proper subnet mask
    local_ip, network = get_network_range()
    
    # Calculate total hosts to scan
    total_hosts = network.num_addresses - 2  # Subtract network and broadcast addresses
    
    print(f"\033[1;36m[*] Local IP: {local_ip}\033[0m")
    print(f"\033[1;36m[*] Network: {network}\033[0m")
    print(f"\033[1;36m[*] Subnet Mask: {network.netmask}\033[0m")
    print(f"\033[1;36m[*] Total hosts to scan: {total_hosts}\033[0m")
    print(f"\033[1;36m[*] This may take a few minutes...\033[0m\n")
    
    # Start scanning threads
    threads = []
    for ip in network.hosts():
        thread = Thread(target=scan_host, args=(ip,))
        thread.start()
        threads.append(thread)
        
        # Limit the number of concurrent threads
        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []
    
    # Wait for remaining threads
    for t in threads:
        t.join()
    
    # Display results
    print(f"\n\033[1;36m[*] Discovery complete. Found {len(discovered_devices)} devices.\033[0m")
    
    if discovered_devices:
        print("\n\033[1;33m{:<15} {:<30} {:<17}\033[0m".format("IP Address", "Hostname", "MAC Address"))
        print("\033[1;33m" + "-" * 65 + "\033[0m")
        
        for device in discovered_devices:
            print("{:<15} {:<30} {:<17}".format(
                device['ip'],
                device['hostname'],
                device['mac_address']
            ))
    
    input("\n\033[1;34mPress Enter to continue...\033[0m")

if __name__ == "__main__":
    discover_network()