
Home/Index
![csnd-index](https://github.com/user-attachments/assets/b2841f96-844d-4853-9173-72cb4e23f5c8)

Network "Management"
![csnd-network-mgmt](https://github.com/user-attachments/assets/d1c5e2b7-1e10-4e88-a701-e6c7eed2f04f)

Inventory
![csnd-inventory](https://github.com/user-attachments/assets/79e7b7f2-5d91-45dd-a277-16b6ce36e1b1)




Install:

sudo git clone https://github.com/silentf666/csnd.git
sudo setcap cap_net_raw+ep $(eval readlink -f `which python3`) ### is needed to scapy
pip install scapy
flask run --host=0.0.0.0 --port=5001 ### test if everything is working so far

if you want to run in autostart (Linux/Raspi)

sudo nano /etc/systemd/system/csnd.service

[Unit]
Description=Crazy Simple NETWORK DISCOVERY
After=network-online.target
Wants=network-online.target

[Service]
User=your username
WorkingDirectory=/home/user/code/csnd/ ### place where the git code is cloned in
ExecStart=/usr/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target


sudo systemctl daemon-reload

sudo systemctl enable csnd.service

view console Output of the Service: 
journalctl -f -u csnd.servic


Additional Info:
Script tries to make arp scan, if its not possible (routed networks) it falls back to simple ICMP.
