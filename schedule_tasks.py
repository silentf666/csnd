import schedule
import time
from discover.py import run_discovery

def schedule_discovery(networks):
    schedule.every(30).minutes.do(run_discovery, networks=networks)
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    networks = ["192.168.10.0/24", "172.16.0.0/24"]
    schedule_discovery(networks)
