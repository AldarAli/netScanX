# File: /netScanX/netScanX/core/cli.py

import os
import sys
import time
import configparser
from network_discovery.wifi_scanner import WiFiScanner, wifi_scan  # Updated import
from network_discovery.port_scanner import port_scan

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

def handle_network_discovery_choice(choice):
    """Handle the user's choice in the network discovery menu."""
    if choice == '1':
        discover_network()
    elif choice == '2':
        port_scan()
    elif choice == '3':
        wifi_scan()  # This will now work correctly
    elif choice == '4':
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