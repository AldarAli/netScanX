#!/usr/bin/env python3

import time
import os
import argparse
import subprocess
import re
import configparser

# ANSI color codes
COLOR_CODES = {
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "blue": "\033[1;34m",
    "purple": "\033[1;35m",
    "cyan": "\033[1;36m",
    "white": "\033[1;37m",
    "reset": "\033[0m"
}

class WiFiScanner:
    def __init__(self, config_path=None):
        self.networks = {}
        self.interface = None
        self.color = "green"  # Default color
        
        # Try to read configuration
        try:
            if config_path:
                self.config_path = config_path
            else:
                # Get the project root directory
                current_dir = os.path.dirname(os.path.abspath(__file__))
                project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
                self.config_path = os.path.join(project_root, 'config', 'configuration.ini')
            
            if os.path.exists(self.config_path):
                config = configparser.ConfigParser()
                config.read(self.config_path)
                if 'Settings' in config:
                    if 'WiFiInterface' in config['Settings']:
                        self.interface = config.get('Settings', 'WiFiInterface')
                        self.print_colored(f"[+] Using interface {self.interface} from configuration")
                    
                    if 'Color' in config['Settings']:
                        self.color = config.get('Settings', 'Color').lower()
                        if self.color not in COLOR_CODES:
                            self.color = "green"  # Fallback to default if invalid
        except Exception as e:
            self.print_colored(f"[!] Error reading config file: {e}", "red")
    
    def print_colored(self, text, color=None):
        """Print text with specified color"""
        if color is None:
            color = self.color
        print(f"{COLOR_CODES.get(color, COLOR_CODES['green'])}{text}{COLOR_CODES['reset']}")
    
    def scan_networks(self, interface=None):
        """Scan for WiFi networks using system commands"""
        if interface:
            self.interface = interface
            
        if not self.interface:
            self.print_colored("[!] No interface specified. Please set one in config file or provide with -i option", "red")
            return
        
        self.print_colored(f"[+] Scanning for WiFi networks on {self.interface}...", "cyan")
        self.networks = {}
        
        try:
            # Use iwlist to scan for networks
            self.print_colored(f"[*] Executing: sudo iwlist {self.interface} scan", "cyan")
                
            result = subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], 
                              capture_output=True, text=True, check=True)
            output = result.stdout
            
            self.print_colored("[*] Parsing scan results...", "cyan")
            
            # Print the table header for network display
            self.print_colored("\n{:<20} {:<25} {:<8} {:<12} {:<10} {:<15}".format(
                "MAC Address", "SSID", "Channel", "Signal (dBm)", "Auth", "Encryption"))
            self.print_colored("-" * 95)
            
            # Parse iwlist output
            cells = output.split('Cell ')
            
            # Track how many networks are found
            network_count = 0
                
            for cell in cells[1:]:  # Skip the first element which is the iwlist header
                # Extract BSSID (MAC)
                mac_match = re.search(r'Address:\s*([0-9A-F:]{17})', cell, re.IGNORECASE)
                bssid = mac_match.group(1) if mac_match else "Unknown"
                
                # Extract SSID
                ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
                ssid = ssid_match.group(1) if ssid_match else "Hidden"
                
                # Extract Channel
                channel_match = re.search(r'Channel:(\d+)', cell) or re.search(r'Channel\s*:(\d+)', cell)
                channel = int(channel_match.group(1)) if channel_match else 0
                
                # Extract Signal
                signal_match = re.search(r'Signal level[=:]([+-]\d+)\s*dBm', cell)
                signal = int(signal_match.group(1)) if signal_match else -100
                
                # Extract Encryption
                encryption = "None"
                auth = "Open"
                
                if "Encryption key:on" in cell:
                    if "WPA2" in cell:
                        auth = "WPA2"
                        encryption_match = re.search(r'Group Cipher\s*:([^\n]*)', cell)
                        encryption = encryption_match.group(1).strip() if encryption_match else "CCMP/AES"
                    elif "WPA" in cell:
                        auth = "WPA"
                        encryption = "TKIP"
                    else:
                        auth = "WEP"
                        encryption = "WEP"
                
                # Store network info
                self.networks[bssid] = {
                    "ssid": ssid,
                    "channel": channel,
                    "signal": signal,
                    "auth": auth,
                    "encryption": encryption,
                    "timestamp": time.time()
                }
                
                # Display each network as it's discovered
                self.print_colored("{:<20} {:<25} {:<8} {:<12} {:<10} {:<15}".format(
                    bssid,
                    ssid[:25],
                    channel,
                    signal,
                    auth,
                    encryption
                ))
                
                network_count += 1
                
        except subprocess.CalledProcessError as e:
            self.print_colored(f"[!] Error executing iwlist: {e}", "red")
            return
        except Exception as e:
            self.print_colored(f"[!] Error parsing scan results: {e}", "red")
            return
        
        # Show summary
        self.print_colored(f"\n[+] Total Networks Discovered: {network_count}", "green")
        
        return self.networks

def wifi_scan():
    """Function to be called from CLI module"""
    scanner = WiFiScanner()
    scanner.scan_networks()
    input("\nPress Enter to return to menu...")
    
def main():
    parser = argparse.ArgumentParser(description='WiFi Scanner - Simple network discovery tool')
    parser.add_argument('-i', '--interface', help='Wireless interface to use (overrides config file)')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("\033[1;31m[!] This script must be run as root to scan networks\033[0m")
        return
    
    scanner = WiFiScanner(config_path=args.config)
    scanner.scan_networks(interface=args.interface)

if __name__ == "__main__":
    main()