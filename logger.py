import csv
import json
from datetime import datetime

LOG_FILE = 'logs/modguard.log'

def log_event(packet, data, status, rule):
    event = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": packet['IP'].src,
        "dst_ip": packet['IP'].dst,
        "src_port": packet['TCP'].sport,
        "dst_port": packet['TCP'].dport,
        "function_code": data['function_code'],
        "payload": data['payload'],
        "status": status,
        "rule": rule
    }

    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')
