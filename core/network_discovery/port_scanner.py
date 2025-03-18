#!/usr/bin/env python3

import nmap
import os
import sys
import time
import configparser

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def scan(self, target, ports="1-1000", scan_type="-sS"):
        """
        Perform port scan using nmap
        
        Parameters:
        - target: IP address or hostname to scan
        - ports: Ports to scan (default: 1-1000)
        - scan_type: Scan type (-sS for SYN scan, -sT for connect, -sU for UDP)
        """
        print(f"[*] Starting port scan on {target}...")
        try:
            self.scanner.scan(target, ports, arguments=f"{scan_type} -v")
            
            print("\nScan Results:")
            print("=" * 60)
            
            for host in self.scanner.all_hosts():
                print(f"Host: {host} ({self.scanner[host].hostname()})")
                print(f"State: {self.scanner[host].state()}")
                
                for proto in self.scanner[host].all_protocols():
                    print(f"\nProtocol: {proto}")
                    
                    ports = sorted(self.scanner[host][proto].keys())
                    print("{:<10} {:<10} {:<15} {:<30}".format("Port", "State", "Service", "Version"))
                    print("-" * 60)
                    
                    for port in ports:
                        service = self.scanner[host][proto][port]
                        print("{:<10} {:<10} {:<15} {:<30}".format(
                            port, 
                            service['state'], 
                            service['name'], 
                            service.get('product', '') + ' ' + service.get('version', '')
                        ))
            
            return self.scanner
        except nmap.PortScannerError as e:
            print(f"\n[!] Error: {e}")
            print("[!] Make sure nmap is installed (sudo apt install nmap)")
            return None
        except Exception as e:
            print(f"\n[!] Unexpected error: {e}")
            return None

def port_scan():
    """Function to be called from CLI module"""
    try:
        target = input("\033[1;34mEnter target IP or hostname: \033[0m")
        if not target:
            print("\033[1;31m[!] No target specified\033[0m")
            return
            
        # Let user choose scan type
        print("\nSelect scan type:")
        print("1. SYN Scan (stealthy, default)")
        print("2. Connect Scan (more reliable but noisy)")
        print("3. UDP Scan (for UDP services)")
        
        scan_choice = input("\033[1;34mEnter choice [1]: \033[0m") or "1"
        
        scan_types = {
            "1": "-sS",
            "2": "-sT", 
            "3": "-sU"
        }
        
        scan_type = scan_types.get(scan_choice, "-sS")
        
        # Let user choose port range
        port_range = input("\033[1;34mEnter port range [1-1000]: \033[0m") or "1-1000"
        
        scanner = PortScanner()
        scanner.scan(target, port_range, scan_type)
        
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrupted\033[0m")
    finally:
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    # Check if running as root - needed for SYN scans
    if os.geteuid() != 0:
        print("\033[1;31m[!] This script must be run as root for SYN scans\033[0m")
        sys.exit(1)
        
    port_scan()