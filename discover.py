from scapy.all import ARP, Ether, srp
import configparser

def discover_network(network):
    # Set up ARP request packet
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and capture responses
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def save_inventory(devices, inventory_file):
    with open(inventory_file, "a") as f:
        for device in devices:
            f.write(f"{device['ip']} - {device['mac']}\n")

def run_discovery(networks, config_path='config/settings.ini'):
    config = configparser.ConfigParser()
    config.read(config_path)
    inventory_file = config['settings']['inventory_file']

    for network in networks:
        devices = discover_network(network)
        save_inventory(devices, inventory_file)
