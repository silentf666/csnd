# discover.py

from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import socket
import os
import configparser
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_hostname(ip):
    try:
        # Attempt to resolve the hostname from the IP address
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        # Return 'Unknown' if hostname cannot be resolved
        hostname = 'Unknown'
    return hostname

def ping_ip(ip):
    """ Perform an ICMP ping to a single IP address. """
    print(f"Scanning IP: {ip}")
    packet = IP(dst=str(ip)) / ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        hostname = resolve_hostname(str(ip))
        return {
            'ip': str(ip),
            'mac': 'N/A',  # MAC address not available via ping
            'hostname': hostname
        }
    return None

def ping_scan(network, num_workers):
    """ Perform an ICMP ping scan on the given network range using multiple workers. """
    devices = []
    try:
        # Create an IP network object
        ip_network = ipaddress.ip_network(network, strict=False)
        print(f"Scanning network with ICMP ping: {network}...")
        
        # Use ThreadPoolExecutor for concurrent IP scanning
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(ping_ip, ip) for ip in ip_network.hosts()]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    result['network'] = network  # Add network information
                    devices.append(result)
                    print(f"Pinged: IP={result['ip']}, Hostname={result['hostname']}")
    except ValueError as e:
        print(f"Error with network range '{network}': {e}")
    
    return devices

def discover_network(network, num_workers):
    """ Perform network discovery using ARP and fall back to ICMP ping if needed. """
    print(f"Scanning network with ARP: {network}...")
    
    # Set up ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send packet and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        hostname = resolve_hostname(received.psrc)
        devices.append({
            'network': network,  # Add network information
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': hostname
        })
        print(f"Discovered via ARP: IP={received.psrc}, MAC={received.hwsrc}, Hostname={hostname}")

    # If no devices found, fall back to ping scan
    if not devices:
        print(f"No devices found with ARP. Falling back to ICMP ping scan.")
        devices = ping_scan(network, num_workers)
    
    return devices

def save_inventory(devices, inventory_file):
    print(f"Saving results to {inventory_file}...")
    file_exists = os.path.isfile(inventory_file)
    try:
        with open(inventory_file, "a") as f:
            if not file_exists:
                # Write headers if file does not exist
                f.write("Network,IP Address,MAC Address,Hostname\n")
            for device in devices:
                # Provide a default value for 'network' if it's missing
                network = device.get('network', 'Unknown')
                f.write(f"{network},{device['ip']},{device['mac']},{device['hostname']}\n")
        print(f"Results saved to {inventory_file}")
    except IOError as e:
        print(f"Error saving results to {inventory_file}: {e}")


def read_config():
    """Read configuration settings from settings.ini."""
    config = configparser.ConfigParser()
    config.read('config/settings.ini')
    return config

def run_discovery():
    """Perform network discovery and save results."""
    # Read configuration
    config = read_config()
    
    # Extract settings
    inventory_file = config['settings']['inventory_file']
    num_workers = int(config['settings'].get('workers', 10))  # Default to 10 workers if not specified
    
    # Get the list of networks from the config
    networks = [value for key, value in config.items('networks')]

    all_devices = []
    
    for network in networks:
        print(f"Starting discovery for network: {network}")
        devices = discover_network(network, num_workers)
        all_devices.extend(devices)
        save_inventory(devices, inventory_file)
    
    print("Discovery complete for all networks.")
    return all_devices