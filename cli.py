
import os
import sys
import time
import configparser
from core.network_discovery.wifi_scanner import wifi_scan 
from core.network_discovery.port_scanner import port_scan
from core.network_discovery.network_discovery import discover_network
from core.recon import recon_choice, validate_mac_address
from core.detection import detect_choice

config = configparser.ConfigParser()
config.read('config/configuration.ini')
interface = config.get('Settings', 'WiFiInterface')

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Display the netScanX banner."""
    banner = """
    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗ 
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ 
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
    """
    print("\033[1;36m" + banner + "\033[0m")  # Cyan color for banner
    print("\033[1;33m" + "=" * 70 + "\033[0m")  # Yellow separator line
    print("\033[1;32m" + " " * 20 + "Network Scanning Tool v1.0" + "\033[0m")  # Green subtitle
    print("\033[1;32m" + " " * 20 + "created by Aldar Ali" + "\033[0m")
    print("\033[1;32m" + " " * 20 + "https://github.com/AldarAli/netScanX" + "\033[0m")
    print("\033[1;33m" + "=" * 70 + "\033[0m\n")  # Yellow separator line
    
def display_menu():
    """Display the menu options."""
    options = [
        "1. Network Discovery", 
        "2. Reconnaissance",
        "3. Detection",
        "4. Exit"
    ]
    
    for option in options:
        print("\033[1;37m" + option + "\033[0m")
    
    print()

def get_user_choice():
    """Get the user's menu choice."""
    try:
        choice = input("\033[1;34mEnter your choice (1-4): \033[0m")
        return choice
    except KeyboardInterrupt:
        print("\n\033[1;31mProgram terminated by user.\033[0m")
        sys.exit(0)

def network_discovery_menu():
    """Display the network discovery options."""
    print("\033[1;37mNetwork Discovery Options:\033[0m")
    print("1. Discover Network Devices")
    print("2. Scan for Open Ports")
    print("3. Scan for Wi-Fi Networks")
    print("4. Back to Main Menu")
    
    choice = input("\033[1;34mEnter your choice (1-4): \033[0m")
    return choice

def reconnaissance_menu():
    """Display the reconnaissance options."""
    print("\033[1;37mReconnaissance Options:\033[0m")
    print("1. Scan Network and Select MAC Address")
    print("2. Enter MAC Address Manually")
    print("3. Back to Main Menu")
    
    choice = input("\033[1;34mEnter your choice (1-3): \033[0m")
    return choice

def detection_menu():
    """Display the detection options."""
    print("\033[1;37mDetection Options:\033[0m")
    print("1. Detect ARP Spoofing")
    print("2. Detect TCP SYN Flood")
    print("3. Back to Main Menu")
    
    choice = input("\033[1;34mEnter your choice (1-3): \033[0m")
    return choice

def handle_network_discovery_choice(choice):
    """Handle the user's choice in the network discovery menu."""
    if choice == '1':
        discover_network()
    elif choice == '2':
        port_scan()
    elif choice == '3':
        wifi_scan()  
    elif choice == '4':
        return
    else:
        print("\033[1;31mInvalid choice. Please try again.\033[0m")
        time.sleep(1)

def handle_reconnaissance_choice(choice):
    """Handle the user's choice in the reconnaissance menu."""
    if choice == '1':
        # Scan network and select MAC address - now uses auto-detection
        print("\033[1;34mDetecting local network...\033[0m")
        recon_choice('1')  # No need to pass target, it will auto-detect
    elif choice == '2':
        # Enter MAC address manually
        while True:
            manual_input = input("\033[1;34mEnter MAC address (e.g. 00:11:22:33:44:55): \033[0m")
            if validate_mac_address(manual_input):
                recon_choice('2', '', manual_input)
                break
            else:
                print("\033[1;31mInvalid MAC address format. Please use format like 00:11:22:33:44:55\033[0m")
    elif choice == '3':
        return
    else:
        print("\033[1;31mInvalid choice. Please try again.\033[0m")
        time.sleep(1)
    
    # Wait for user to press Enter before returning to menu
    input("\n\033[1;33mPress Enter to continue...\033[0m")

def handle_detection_choice(choice):
    """Handle the user's choice in the detection menu."""
    if choice == '1' or choice == '2':
        # Common settings for both detection types
        print("\033[1;34mStarting Detection...\033[0m")
        
        # Optional: Let user override the auto-detected network
        target = input("\033[1;34mEnter network range to monitor (or leave blank for auto-detection): \033[0m")
        
        # Ask for verbose mode
        verbose_input = input("\033[1;34mEnable verbose mode? (y/n, default: n): \033[0m").lower()
        verbose = verbose_input.startswith('y')
        
        if choice == '1':
            # ARP Spoofing detection
            detect_choice('1', target if target else None, intf=interface, verbose=verbose)
        else:
            # TCP SYN Flood detection
            port_input = input("\033[1;34mEnter TCP port to monitor (default: 80): \033[0m")
            port = int(port_input) if port_input.strip() and port_input.isdigit() else 80
            
            detect_choice('2', target if target else None, tcp_port=port, intf=interface, verbose=verbose)
        
    elif choice == '3':
        return
    else:
        print("\033[1;31mInvalid choice. Please try again.\033[0m")
        time.sleep(1)

def main():
    while True:
        clear_screen()
        print_banner()
        display_menu()
        choice = get_user_choice()
        
        if choice == '1':
            while True:
                clear_screen()
                print_banner()
                network_choice = network_discovery_menu()
                if network_choice == '4':
                    break
                handle_network_discovery_choice(network_choice)
        
        elif choice == '2':
            while True:
                clear_screen()
                print_banner()
                recon_choice = reconnaissance_menu()
                if recon_choice == '3':
                    break
                handle_reconnaissance_choice(recon_choice)
                
        elif choice == '3':
            while True:
                clear_screen()
                print_banner()
                detection_choice = detection_menu()
                if detection_choice == '3':
                    break
                handle_detection_choice(detection_choice)
        
        elif choice == '4':
            print("\033[1;31mExiting netScanX...\033[0m")
            time.sleep(0.2)
            clear_screen()
            sys.exit(0)
        else:
            print("\033[1;31mInvalid choice. Please try again.\033[0m")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;31mProgram terminated by user.\033[0m")
        sys.exit(0)