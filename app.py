from flask import Flask, render_template, request, redirect, url_for, jsonify

import csv
import collections
import configparser
import os
import logging
from discover import load_inventory, save_inventory, run_discovery, read_config, get_scan_status, update_scan_status
import threading
import time
import schedule
from datetime import datetime

app = Flask(__name__)
config_file_path = 'config/settings.ini'
config = read_config()
SCAN_DIR = config['settings']['SCAN_DIR']
SCAN_HISTORY_AMOUNT = int(config['settings']['scan_history_files'])

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Global state to track if a scan is running
scan_state = {'running': False, 'result': None}
app_scan_status = get_scan_status()





def ensure_scan_dir_exists():
    """ Ensure the scans directory exists. """

    if not os.path.exists(SCAN_DIR):
        os.makedirs(SCAN_DIR)



@app.route('/delete_device/<ip>', methods=['POST'])
def delete_device(ip):
    # Load existing inventory
    devices_by_network = load_inventory()
    
    # Filter out the device with the given IP
    for network, devices in devices_by_network.items():
        devices_by_network[network] = [device for device in devices if device['ip'] != ip]
    
    # Save the updated inventory
    save_inventory(devices_by_network)
    
    return redirect(url_for('view_inventory'))


@app.route('/toggle_keep/<ip>', methods=['POST'])
def toggle_keep(ip):
    keep = request.form.get('keep')
    
    # Load the existing inventory
    devices_by_network = load_inventory()
    
    # Find the device and update the keep status
    for network, devices in devices_by_network.items():
        for device in devices:
            if device['ip'] == ip:
                device['keep'] = keep
                break
    
    # Save the updated inventory
    save_inventory(devices_by_network)
    
    return redirect(url_for('view_inventory'))



@app.route('/update_comment/<ip>', methods=['POST'])
def update_comment(ip):
    comment = request.form.get('comment')
    keep = request.form.get('keep')
    print("KEEEEEEEEEEEEP:", keep)

    # Load the existing inventory
    devices_by_network = load_inventory()
    
    # Flag to check if the device was found and updated
    device_found = False
    
    # Find the device and update the comment and keep status
    for network, devices in devices_by_network.items():
        for device in devices:
            if device['ip'] == ip:
                device['comment'] = comment
                device['keep'] = keep
                device_found = True
                break
        if device_found:
            break
    
    if not device_found:
        # Optionally, handle the case where the device is not found
        return jsonify({'error': 'Device not found'}), 404

    # Save the updated inventory
    save_inventory(devices_by_network)
    
    return redirect(url_for('view_inventory'))



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

def get_network_name_mapping(config_file_path):
    config = configparser.ConfigParser()
    config.read(config_file_path)
    
    network_name_mapping = {}
    
    if 'networks' in config:
        network_name_mapping = {v: k for k, v in config.items('networks')}
    
    return network_name_mapping

@app.route('/scan_status')
def app_get_scan_status():
    global app_scan_status
    app_scan_status = get_scan_status()
    return jsonify(status=app_scan_status)
    


@app.route('/')
def index():
    
    config = read_config()
    networks = {key: value for key, value in config.items('networks')}  # Extract network names and addresses from config

    #SCAN_HISTORY_AMOUNT = 50 files per default
    ensure_scan_dir_exists()
    
    # Load all scan files from the scans directory and sort by newest
    scan_files = sorted(os.listdir(SCAN_DIR), reverse=True)

    # Keep only the 50 most recent scan files
    if len(scan_files) > SCAN_HISTORY_AMOUNT:
        # Identify files that should be deleted
        files_to_delete = scan_files[SCAN_HISTORY_AMOUNT:]
        for file in files_to_delete:
            os.remove(os.path.join(SCAN_DIR, file))
        # Update the scan_files list after deletion
        scan_files = scan_files[:SCAN_HISTORY_AMOUNT]

    # Load the new devices from the file
    new_devices = []
    if os.path.exists('data/new_devices.txt'):
        with open('data/new_devices.txt', 'r') as f:
            new_devices = [line.strip() for line in f.readlines()]

    return render_template('index.html', scan_files=scan_files, new_devices=new_devices, networks=networks)

@app.route('/approve_new_devices', methods=['POST'])
def approve_new_devices():
    # Clear the new_devices.txt file
    open('data/new_devices.txt', 'w').close()
    
    return redirect(url_for('index'))

def load_scans_from_file(file_path):
    """ Load scan results from a file. """
    scans = collections.defaultdict(list)
    try:
        with open(file_path, 'r') as f:
            reader = csv.DictReader(f, fieldnames=['network', 'ip', 'mac', 'hostname'])
            for row in reader:
                scans[row['network']].append(row)
    except FileNotFoundError:
        print(f"File {file_path} not found.")
    return scans


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
    selected_network = request.args.get('network')
    devices_by_network = load_inventory()
    network_name_mapping = get_network_name_mapping(config_file_path)
    
    if selected_network and selected_network in devices_by_network:
        devices_by_network = {selected_network: devices_by_network[selected_network]}
    
    return render_template('view_inventory.html', devices_by_network=devices_by_network, network_name_mapping=network_name_mapping, selected_network=selected_network)

@app.route('/view_scan/<filename>')
def view_scan(filename):
    file_path = os.path.join(SCAN_DIR, filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404

    with open(file_path, 'r') as file:
        content = file.read()

    return render_template('view_scan.html', filename=filename, content=content)

@app.route('/run_discovery_now', methods=['GET', 'POST'])
def run_discovery_now():
    global scan_state
    if scan_state['running']:
        return redirect(url_for('index'))  # Prevent duplicate scans if one is already running
 
    
    network = request.form.get('network')  # Get the network from the form submission (if any)

    def discovery_thread():
        scan_state['running'] = True
        scan_state['result'] = run_discovery(network)  # Pass the network to the discovery function
        scan_state['running'] = False
    
    threading.Thread(target=discovery_thread).start()
    return redirect(url_for('index'))

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
    app.run(host='0.0.0.0', port=6000, debug=False)
