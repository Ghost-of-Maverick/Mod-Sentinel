import os
import time
import yaml
from packet_capture import capture_packets
from parser import parse_modbus_packet
from detector import detect
from logger import log_event
from utils import write_pid, remove_pid, check_pid

CONFIG_FILE = 'config.yaml'

def load_config():
    with open(CONFIG_FILE, 'r') as file:
        return yaml.safe_load(file)

def daemon_loop():
    config = load_config()
    interface = config.get('interface', 'eth0')

    for packet in capture_packets(interface):
        modbus_data = parse_modbus_packet(packet)
        if modbus_data:
            status, rule = detect(modbus_data)
            log_event(packet, modbus_data, status, rule)

def start_daemon():
    if check_pid():
        print("ModGuard já está em execução.")
        return
    pid = os.fork()
    if pid == 0:
        write_pid()
        try:
            daemon_loop()
        finally:
            remove_pid()

def stop_daemon():
    pid = check_pid()
    if pid:
        os.kill(pid, 15)
        remove_pid()
