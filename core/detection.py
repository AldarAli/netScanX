from scapy.all import Ether, ARP, srp, sniff, conf, IP, TCP
from collections import Counter
import time
import threading
import socket
import ipaddress

class AttackDetector:
    def __init__(self, interface="wlan0", verbose=False):
        self.interface = interface
        self.syn_count = Counter()
        self.attack_detected = False
        self.stop_sniffing = False
        self.verbose = verbose
        
    def get_local_network(self):
        """
        Get the local network IP address and convert to CIDR notation
        
        Returns:
            str: Network in CIDR notation (e.g., '192.168.1.0/24')
        """
        try:
            # Try to get the IP address bound to the interface being used
            conf.iface = self.interface
            ip_addr = conf.iface.ip
            
            if ip_addr:
                # If IP detected via scapy, assume a /24 network (common default)
                subnet = '.'.join(ip_addr.split('.')[:3]) + '.0/24'
                if self.verbose:
                    print(f"\033[1;34m[INFO] Network detected via Scapy: {subnet}\033[0m")
                return subnet
        except Exception as e:
            if self.verbose:
                print(f"\033[1;33m[WARNING] Failed to detect network via Scapy: {str(e)}\033[0m")
            
        # Fallback method
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Connect to Google DNS
            ip_addr = s.getsockname()[0]
            s.close()
            
            # Assume a /24 subnet (most common for home networks)
            subnet = '.'.join(ip_addr.split('.')[:3]) + '.0/24'
            if self.verbose:
                print(f"\033[1;34m[INFO] Network detected via socket: {subnet}\033[0m")
            return subnet
        except Exception as e:
            if self.verbose:
                print(f"\033[1;33m[WARNING] Failed to detect network via socket: {str(e)}\033[0m")
            return "192.168.1.0/24"  # Default fallback
    
    def detect_choice(self, choice, target=None, tcp_port=80):
        """
        Route to appropriate detection function based on user choice.
        
        Args:
            choice (str): User selection ('1' for ARP spoof, '2' for TCP flood)
            target (str, optional): Network target for monitoring (e.g., '192.168.1.0/24')
                                  If None or empty, auto-detect the local network.
            tcp_port (int): TCP port to monitor for SYN flood
        """
        self.stop_sniffing = False
        
        # Auto-detect the target network if not specified
        if not target:
            target = self.get_local_network()
            print(f"\033[1;34m[INFO] Auto-detected network: {target}\033[0m")
        
        if choice == '1':
            print("\033[1;34m\n [RUNNING] ARP Spoofing Detector\033[0m")
            print(f"\033[1;34m Monitoring network: {target}\033[0m")
            if self.verbose:
                print("\033[1;34m [INFO] Verbose mode enabled\033[0m")
            print("\033[1;34m CTRL+C to EXIT\033[0m")
            try:
                self.arp_detection(target)
            except KeyboardInterrupt:
                print("\n\033[1;33mARP detection stopped\033[0m")
            return
        elif choice == '2':
            print("\033[1;34m\n [RUNNING] TCP SYN Flood Detector\033[0m")
            print(f"\033[1;34m Monitoring network: {target} on port {tcp_port}\033[0m")
            if self.verbose:
                print("\033[1;34m [INFO] Verbose mode enabled\033[0m")
                print(f"\033[1;34m [INFO] SYN threshold set to: 20 packets/2sec\033[0m")
            print("\033[1;34m CTRL+C to EXIT\033[0m")
            try:
                self.tcp_flood_detection(target, tcp_port)
            except KeyboardInterrupt:
                print("\n\033[1;33mTCP flood detection stopped\033[0m")
            return
        else:
            print("\033[1;31m[ERROR] Invalid detection choice\033[0m")
            return

    def arp_detection(self, target):
        """
        Detect ARP spoofing attacks on the network.
        
        Args:
            target (str): Network range to monitor (e.g., '192.168.1.0/24')
        """
        if self.verbose:
            print(f"\033[1;34m[INFO] Starting ARP spoofing detection on {self.interface}\033[0m")
            print(f"\033[1;34m[INFO] Detection assumptions: Different MAC for same IP = potential spoof\033[0m")
        
        sniff(store=False, prn=self.process_arp, iface=self.interface, 
              filter="arp", stop_filter=lambda x: self.stop_sniffing)

    def tcp_flood_detection(self, target, port=80):
        """
        Detect TCP SYN flood attacks on the network.
        
        Args:
            target (str): Network range to monitor (e.g., '192.168.1.0/24')
            port (int): TCP port to monitor
        """
        # Reset counters
        self.syn_count = Counter()
        self.attack_detected = False
        
        # Start counter reset thread
        reset_thread = threading.Thread(target=self.reset_counters)
        reset_thread.daemon = True
        reset_thread.start()
        
        # Start sniffing
        filter_str = f"tcp and dst net {target}"
        if port != 0:  # If port is specified
            filter_str += f" and dst port {port}"
        
        if self.verbose:
            print(f"\033[1;34m[INFO] Using BPF filter: {filter_str}\033[0m")
            print(f"\033[1;34m[INFO] Counter reset interval: 2 seconds\033[0m")
        
        sniff(store=False, prn=self.process_tcp, 
              filter=filter_str, iface=self.interface,
              stop_filter=lambda x: self.stop_sniffing)

    def reset_counters(self):
        """Periodically reset SYN packet counters to avoid false positives"""
        while not self.stop_sniffing:
            time.sleep(2)  # Reset counters every 2 seconds
            if self.verbose and any(self.syn_count.values()):
                print(f"\033[1;34m[INFO] Resetting SYN counters. Counts were: {dict(self.syn_count)}\033[0m")
            self.syn_count = Counter()

    def get_mac(self, ip):
        """
        Get the MAC address of a device on the network using ARP.
        
        Args:
            ip (str): IP address to lookup
            
        Returns:
            str: MAC address of the device if found
        """
        try:
            if self.verbose:
                print(f"\033[1;34m[INFO] Resolving MAC for {ip}\033[0m")
            p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
            result = srp(p, timeout=2, verbose=False, retry=1)[0]
            if result:
                mac = result[0][1].hwsrc
                if self.verbose:
                    print(f"\033[1;34m[INFO] Resolved {ip} → {mac}\033[0m")
                return mac
            if self.verbose:
                print(f"\033[1;33m[WARNING] Could not resolve MAC for {ip}\033[0m")
            return None
        except Exception as e:
            if self.verbose:
                print(f"\033[1;33m[WARNING] Error resolving MAC for {ip}: {str(e)}\033[0m")
            return None

    def process_arp(self, packet):
        """
        Process ARP packets to detect spoofing attempts.
        
        Args:
            packet: Scapy packet to analyze
        """
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            try:
                # Get the real MAC address of the sender
                src_ip = packet[ARP].psrc
                response_mac = packet[ARP].hwsrc
                
                if self.verbose:
                    print(f"\033[1;34m[INFO] ARP reply: {src_ip} claims to be at {response_mac}\033[0m")
                
                # Only verify suspicious ARP replies to reduce network traffic
                real_mac = self.get_mac(src_ip)
                if not real_mac:
                    return
                    
                # If they're different, it's likely an attack
                if real_mac != response_mac:
                    print(f"\033[1;31m[!] ARP SPOOFING DETECTED!\033[0m")
                    print(f"\033[1;31m    IP: {src_ip}\033[0m")
                    print(f"\033[1;31m    REAL-MAC: {real_mac.upper()}\033[0m")
                    print(f"\033[1;31m    FAKE-MAC: {response_mac.upper()}\033[0m")
            except Exception as e:
                if self.verbose:
                    print(f"\033[1;33m[WARNING] Error processing ARP packet: {str(e)}\033[0m")

    def process_tcp(self, packet):
        """
        Process TCP packets to detect SYN flood attacks.
        
        Args:
            packet: Scapy packet to analyze
        """
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Extract source IP and TCP flags
            src_ip = packet[IP].src
            tcp_flags = packet[TCP].flags
            
            # Check for SYN packets (flag 0x02)
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN but not ACK
                self.syn_count[src_ip] += 1
                
                # Extract packet information
                dst_ip = packet[IP].dst
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                
                # Define threshold (adjustable based on environment)
                syn_threshold = 20
                
                # Show information based on count and verbose mode
                if self.syn_count[src_ip] > 5 or self.verbose:
                    flow = f'TCP | {src_ip:15} | {sport:<5} | {dst_ip:15} | {dport:<5}'
                    
                    if self.syn_count[src_ip] >= syn_threshold:
                        if not self.attack_detected:
                            print(f"\033[1;31m[!] SYN FLOOD ATTACK DETECTED from {src_ip}\033[0m")
                            self.attack_detected = True
                        print(f"\033[1;33m{flow} | Count: {self.syn_count[src_ip]}\033[0m")
                    elif self.verbose:
                        print(f"{flow} | Count: {self.syn_count[src_ip]}")


# For backwards compatibility with existing code
def detect_choice(choice, target=None, tcp_port=80, intf="wlan0", verbose=False):
    detector = AttackDetector(interface=intf, verbose=verbose)
    detector.detect_choice(choice, target, tcp_port)

def arp_detection(target, interface="wlan0", verbose=False):
    detector = AttackDetector(interface=interface, verbose=verbose)
    detector.arp_detection(target)

def tcp_flood_detection(target, tcp_port=80, interface="wlan0", verbose=False):
    detector = AttackDetector(interface=interface, verbose=verbose)
    detector.tcp_flood_detection(target, tcp_port)