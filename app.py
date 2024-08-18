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

@app.route('/')
def index():
    # Load inventory data from file
    devices_by_network = {}
    try:
        with open('data/inventory.txt', 'r') as f:
            for line in f:
                network, ip, mac, hostname = line.strip().split(',', 3)
                if network not in devices_by_network:
                    devices_by_network[network] = []
                devices_by_network[network].append({
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname
                })
    except FileNotFoundError:
        devices_by_network = {}

    return render_template('index.html', devices_by_network=devices_by_network)

@app.route('/networks', methods=['GET'])
def networks():
    config = load_config()
    networks = dict(config.items('networks'))
    return render_template('networks.html', networks=networks)

@app.route('/add_network', methods=['GET', 'POST'])
def add_network():
    config = load_config()
    if request.method == 'POST':
        network_name = request.form['network_name']
        network_address = request.form['network_address']
        if 'networks' not in config:
            config['networks'] = {}

        # Check if the network is already in the configuration
        if network_name in config['networks']:
            return render_template('add_network.html', message=f"Network {network_name} already exists!")

        # Add the new network
        config['networks'][network_name] = network_address
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
        return redirect(url_for('networks'))
    return render_template('add_network.html')

@app.route('/edit_network/<network_name>', methods=['GET', 'POST'])
def edit_network(network_name):
    config = load_config()
    networks = dict(config.items('networks'))

    if request.method == 'POST':
        new_network_name = request.form['network_name']
        network_address = request.form['network_address']

        if new_network_name != network_name:
            del networks[network_name]
            networks[new_network_name] = network_address
        else:
            networks[network_name] = network_address

        config['networks'] = networks
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
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
