
Install:

sudo git clone https://github.com/silentf666/csnd.git
sudo setcap cap_net_raw+ep $(eval readlink -f `which python3`) ### is needed to scapy
pip install scapy
flask run --host=0.0.0.0 --port=5001 ### test if everything is working so far

if you want to run in autostart (Linux/Raspi)

sudo nano /etc/systemd/system/csnd.service

[Unit]
Description=Crazy Simple NETWORK DISCOVERY
After=network.target

[Service]
User=your username
WorkingDirectory=/home/user/code/csnd/ ### place where the git code is cloned in
ExecStart=python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target


sudo systemctl daemon-reload

sudo systemctl enable csnd.service

view console Output of the Service: 
journalctl -f -u csnd.servic
