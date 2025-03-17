import os
import sys
import time
from Network_discovery import scanner_choice
from result_output import print_output, print_input
import configparser

config = configparser.ConfigParser()
config.read('configration.ini')
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
        "2. Port Scanning",
        "3. Reconnaissance",
        "4. Detection",
        "5. Exit"
    ]
    
    for option in options:
        print("\033[1;37m" + option + "\033[0m")
    
    print()

def get_user_choice():
    """Get the user's menu choice."""
    try:
        choice = input("\033[1;34mEnter your choice (1-5): \033[0m")
        return choice
    except KeyboardInterrupt:
        print("\n\033[1;31mProgram terminated by user.\033[0m")
        sys.exit(0)

def main():
    while True:
        clear_screen()
        print_banner()
        display_menu()
        choice = get_user_choice()
        
        if choice == '1':
            print("\033[1;32mNetwork Discovery selected.\033[0m")
            while 1:
                print_output("\n 1. Network Scanner \n\n 2. WiFi Scanner \n\n 3. Port Scanner \n")
                resp = print_input(" SCAN INPUT >> ")
                target = ""
                if resp == "1" or resp == "3":
                    target = print_input(" NET IP ADDRESS (Eg: 192.168.1.1/24) >> ")
                interface = config.get('Settings', 'WiFiInterface')  # Initialize interface
                interface = print_input(f" NETWORK INTERFACE (default: {interface}) >> ") or interface
                break
            scanner_choice(resp, target, interface)
            continue
        elif choice == '2':
            print("\033[1;32mPort Scanning selected.\033[0m")
            time.sleep(1)
        elif choice == '3':
            print("\033[1;32mReconnaissance selected.\033[0m")
            time.sleep(1)
        elif choice == '4':
            print("\033[1;32mDetection selected.\033[0m")
            time.sleep(1)
        elif choice == '5':
            print("\033[1;31mExiting netScanX...\033[0m")
            time.sleep(1)
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