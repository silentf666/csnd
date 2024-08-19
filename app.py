from flask import Flask, render_template, request, redirect, url_for
import csv
import collections
import configparser
import os
import logging
from discover import run_discovery
import threading
import time
import schedule

app = Flask(__name__)
config_file_path = 'config/settings.ini'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load or create the config file
def load_config():
    config = configparser.ConfigParser()
    if not os.path.exists(config_file_path):
        config['networks'] = {}
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
    else:
        config.read(config_file_path)
    return config
    
def read_networks():
    config = configparser.ConfigParser()
    config.read(config_file_path)
    networks = dict(config.items('networks'))
    return networks
    
def save_networks(networks):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    config['networks'] = networks
    with open(config_file_path, 'w') as configfile:
        config.write(configfile)

def get_network_name_mapping(config_file_path, network_to_translate):
    """
    Translate a network CIDR to its corresponding network name based on the configuration file.

    Args:
        config_file_path (str): Path to the configuration file.
        network_to_translate (str): The network CIDR to be translated.

    Returns:
        str: The network name associated with the given CIDR, or the CIDR itself if no name is found.
    """
    config = configparser.ConfigParser()
    config.read(config_file_path)
    
    # Check if 'networks' section exists
    if 'networks' in config:
        # Reverse the mapping from CIDR to name
        network_mappings = {v: k for k, v in config.items('networks')}
        
        # Return the network name if found, otherwise return the CIDR itself
        return network_mappings.get(network_to_translate, network_to_translate)
    
    # Return the CIDR itself if the 'networks' section is not present
    return network_to_translate

@app.route('/')
def index():
    # Load inventory data from file
    devices_by_network = collections.defaultdict(list)
    try:
        with open('data/inventory.txt', 'r') as f:
            reader = csv.DictReader(f, fieldnames=['network', 'ip', 'mac', 'hostname'])
            for row in reader:
                devices_by_network[row['network']].append(row)
    except FileNotFoundError:
        print("Inventory file not found.")
    
    # Create a mapping of CIDR to network names
    network_name_mapping = {v: k for k, v in load_config().items('networks')}
    
    # Pass the mapping and devices to the template
    return render_template('index.html', devices_by_network=devices_by_network, network_name_mapping=network_name_mapping)


@app.route('/networks', methods=['GET'])
def networks():
    config = load_config()
    networks = dict(config.items('networks'))
    return render_template('networks.html', networks=networks)

@app.route('/add_network', methods=['GET', 'POST'])
def add_network():
    if request.method == 'POST':
        network_name = request.form['network_name']
        network_address = request.form['network_address']
        networks = read_networks()
        networks[network_name] = network_address
        save_networks(networks)
        return redirect(url_for('networks'))
    return render_template('add_network.html')

@app.route('/edit_network/<network_name>', methods=['GET', 'POST'])
def edit_network(network_name):
    networks = read_networks()
    if request.method == 'POST':
        new_network_name = request.form['network_name']
        network_address = request.form['network_address']
        if new_network_name != network_name:
            del networks[network_name]
            networks[new_network_name] = network_address
        else:
            networks[network_name] = network_address
        save_networks(networks)
        return redirect(url_for('networks'))
    
    network_address = networks.get(network_name, '')
    return render_template('edit_network.html', network_name=network_name, network_address=network_address)

@app.route('/remove_network/<network_name>')
def remove_network(network_name):
    config = load_config()
    networks = dict(config.items('networks'))
    if network_name in networks:
        del networks[network_name]
        config['networks'] = networks
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
    return redirect(url_for('networks'))

@app.route('/view_inventory')
def view_inventory():
    inventory_file = 'data/inventory.txt'
    devices_by_network = collections.defaultdict(list)
    
    try:
        with open(inventory_file, 'r') as f:
            reader = csv.DictReader(f, fieldnames=['network', 'ip', 'mac', 'hostname'])
            for row in reader:
                devices_by_network[row['network']].append(row)
    except FileNotFoundError:
        print(f"Inventory file {inventory_file} not found.")
    
    return render_template('view_inventory.html', devices_by_network=devices_by_network)

@app.route('/run_discovery_now')
def run_discovery_now():
    # Run the network discovery and get devices
    devices = run_discovery()

    # Render the results in a template
    return render_template('scan_results.html', devices=devices)

def read_interval_from_config():
    """Read the scan interval from settings.ini."""
    config = configparser.ConfigParser()
    config.read(config_file_path)
    interval = int(config['settings'].get('scan_interval_minutes', 30))
    return interval
    
def schedule_discovery():
    """Schedule the discovery task."""
    interval = read_interval_from_config()
    schedule.every(interval).minutes.do(run_discovery)
    
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == '__main__':
    # Start the scheduler in a separate thread
    threading.Thread(target=schedule_discovery, daemon=True).start()
    app.run(debug=True)
