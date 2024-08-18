#pip install flask configparser schedule scapy
from flask import Flask, render_template, request, redirect, url_for
import configparser
import os

app = Flask(__name__)
config_file_path = 'config/settings.ini'

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
    return render_template('index.html')

@app.route('/add_network', methods=['GET', 'POST'])
def add_network():
    config = load_config()
    if request.method == 'POST':
        network = request.form['network']
        if 'networks' not in config:
            config['networks'] = {}

        # Check if the network is already in the configuration
        if network in config['networks']:
            return render_template('add_network.html', message=f"Network {network} already exists!")

        # Add the new network
        config['networks'][network] = network
        with open(config_file_path, 'w') as configfile:
            config.write(configfile)
        return redirect(url_for('index'))
    return render_template('add_network.html')

@app.route('/view_inventory')
def view_inventory():
    inventory_file = config_file_path
    inventory_data = []
    if os.path.exists(inventory_file):
        with open(inventory_file, 'r') as f:
            inventory_data = f.readlines()
    return render_template('view_inventory.html', inventory=inventory_data)
    
@app.route('/run_discovery_now')
def run_discovery_now():
    # Logic to run the discovery immediately
    return "Network discovery is running!"


if __name__ == '__main__':
    app.run(debug=True, port=5000)

