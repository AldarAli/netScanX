import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

import requests 
import json
import re
import subprocess
import scapy.all as scapy
from pick import pick


def get_local_network_info():
    """
    Automatically detect local network IP and subnet mask.
    
    Returns:
        str: Network range in CIDR notation (e.g., '192.168.1.0/24')
    """
    try:
        # Get primary interface (the one with default route)
        def_route_dev = scapy.conf.route.route("0.0.0.0")[0]
        
        # Get local IP address
        local_ip = scapy.get_if_addr(def_route_dev)
        
        # Try to get netmask via Linux 'ip' command
        try:
            cmd_output = subprocess.check_output(
                ["ip", "-o", "-f", "inet", "addr", "show", def_route_dev], 
                universal_newlines=True
            )
            # Parse output to get CIDR notation
            cidr_notation = cmd_output.strip().split()[3]  # Format: 192.168.1.2/24
            return cidr_notation
        except:
            # Fallback: use typical home/office subnet /24
            ip_parts = local_ip.split('.')
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
    except Exception as e:
        print(f"\033[1;33m\n WARNING: Could not automatically detect network - {str(e)}\033[0m")
        print("\033[1;33m\n Using fallback 192.168.1.0/24\033[0m")
        return "192.168.1.0/24"


def recon_choice(choice, target=None, manual_input=None):
    """
    Route to appropriate reconnaissance function based on user choice.
    
    Args:
        choice (str): User selection ('1' for scan, '2' for manual input)
        target (str): Network target for scanning (optional, auto-detected if None)
        manual_input (str): Manual MAC address input
    """
    if choice == '1':
        if not target:
            target = get_local_network_info()
            print(f"\033[1;34m\n Auto-detected network: {target}\033[0m")
        choose_mac_address(target)
        return
    elif choice == '2':
        input_mac_address(manual_input)
        return
    else:
        exit()


def choose_mac_address(target):
    """
    Scan network and let user choose a MAC address from discovered devices.
    
    Args:
        target (str): IP address range to scan (e.g., '192.168.1.0/24')
    """
    scan_addresses(target)
    return


def input_mac_address(manual_input):
    """
    Process a manually entered MAC address.
    
    Args:
        manual_input (str): MAC address entered by user
    """
    # Add validation for MAC address format
    if not validate_mac_address(manual_input):
        print("\033[1;31m\n Invalid MAC address format. Please use format like 00:11:22:33:44:55\033[0m")
        return
        
    address_api_call(manual_input, '')
    return


def validate_mac_address(mac):
    """
    Validate MAC address format.
    
    Args:
        mac (str): MAC address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))


# Helper Functions

def address_api_call(address, ip_address):
    """
    Query vendor database for information about a MAC address.
    """
    print("\033[1;34m\n SCANNING MAC ADDRESS...\033[0m")
    
    # Get API key from environment variables
    api_key = os.environ.get('MAC_ADDRESS_API_KEY')
    
    # Check if API key exists
    if not api_key:
        print("\033[1;31m\n ERROR: API key not found in environment variables\033[0m")
        return
        
    url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={address}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise exception for HTTP errors
        
        result = response.json()
        if "vendorDetails" in result:
            # Extract the vendor details to match our original format
            formatted_result = {
                "company": result.get("vendorDetails", {}).get("companyName", "Unknown"),
                "address": result.get("vendorDetails", {}).get("companyAddress", "N/A"),
                "country": result.get("vendorDetails", {}).get("countryCode", "N/A"),
                "type": result.get("macAddressDetails", {}).get("transmissionType", "N/A")
            }
            
            # Add block details if available
            block_details = result.get("blockDetails", {})
            if block_details.get("blockFound"):
                formatted_result["assignment"] = block_details.get("assignmentBlockSize", "N/A")
                formatted_result["registered"] = block_details.get("dateCreated", "N/A")
            
            transcribe_api_results(formatted_result, ip_address)
        else:
            print("\033[1;31m\n No MAC Address Found!\033[0m")
    except requests.RequestException as e:
        print(f"\033[1;31m\n ERROR: API request failed - {str(e)}\033[0m")
    except json.JSONDecodeError:
        print("\033[1;31m\n ERROR: Invalid response format from API\033[0m")
    except Exception as e:
        print(f"\033[1;31m\n ERROR: Unexpected error - {str(e)}\033[0m")


def transcribe_api_results(json_object, ip_address):
    """
    Display results from the MAC address vendor database.
    
    Args:
        json_object (dict): API response data
        ip_address (str): Associated IP address if available
    """
    for key in json_object:
        value = json_object[key]
        print(f"\033[1;32m\n {snake_case_to_normal(key)}: {value}\033[0m")
    if ip_address and len(ip_address) > 0:
        print(f"\033[1;32m\n IP ADDRESS: {ip_address}\033[0m")


def snake_case_to_normal(snake_text):
    """
    Convert snake_case to readable text format.
    
    Args:
        snake_text (str): Text in snake_case format
        
    Returns:
        str: Formatted text
    """
    temp = snake_text.split('_')
    res = temp[0].upper() + ''.join(' ' + ele.title().upper() for ele in temp[1:])
    return res


# Display MAC Address List

def scan_addresses(target):
    """
    Scan network for active devices and present selection to user.
    
    Args:
        target (str): IP address range to scan (e.g., '192.168.1.0/24')
    """
    try:
        print("\033[1;34m\n SCANNING NETWORK...\033[0m")
        broadcast_packets = create_packet(target)
        success_packets = transmit_packet(broadcast_packets)
        
        if not success_packets:
            print("\033[1;31m\n No devices found on network\033[0m")
            return
            
        entries = parse_response(success_packets)
        display_picker(entries)
    except Exception as e:
        print(f"\033[1;31m\n ERROR: Scan failed - {str(e)}\033[0m")


def create_packet(ip):
    """
    Create ARP request packet for network scanning.
    
    Args:
        ip (str): IP address or range to scan
        
    Returns:
        scapy.Packet: Configured packet for broadcasting
    """
    arp_request = scapy.ARP(pdst=ip)  # create a ARP request object by scapy
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # We have set the destination
    arp_request_broadcast = broadcast / arp_request
    return arp_request_broadcast


def transmit_packet(packet):
    """
    Send packet to network and collect responses.
    
    Args:
        packet (scapy.Packet): Packet to transmit
        
    Returns:
        list: Successful responses
    """
    success_list, failure_list = scapy.srp(packet, timeout=3, verbose=False)
    return success_list


def parse_response(success_list):
    """
    Parse scapy response into structured data.
    
    Args:
        success_list (list): Successful responses from scapy
        
    Returns:
        list: List of dictionaries with IP and MAC addresses
    """
    targets = []
    for success in success_list:
        entry = {'ip': success[1].psrc, 'mac': success[1].hwsrc}
        targets.append(entry)
    return targets


def display_picker(element_entries):
    """
    Display interactive picker for selecting a MAC address.
    
    Args:
        element_entries (list): List of dictionaries with device information
    """
    if not element_entries:
        print("\033[1;31m\n No devices found\033[0m")
        return
        
    # Format entries to show both MAC and IP for better selection
    display_entries = [f"{el['mac']} ({el['ip']})" for el in element_entries]
    
    try:
        option, index = pick(display_entries, 'SELECT MAC Address', indicator='=>', default_index=0)
        # Extract the MAC from the selected entry
        selected_mac = element_entries[index]['mac']
        address_api_call(selected_mac, element_entries[index]['ip'])
    except KeyboardInterrupt:
        print("\033[1;33m\n Selection cancelled\033[0m")
    except Exception as e:
        print(f"\033[1;31m\n ERROR: Selection failed - {str(e)}\033[0m")