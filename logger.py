import json
from datetime import datetime

LOG_FILE = 'logs/modguard.log'

def log_event(packet, data, status, rule):
    # Suporte para pacotes falsos (modo de teste)
    if isinstance(packet, dict):
        src_ip = packet['IP']['src']
        dst_ip = packet['IP']['dst']
        src_port = packet['TCP']['sport']
        dst_port = packet['TCP']['dport']
    else:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        src_port = packet['TCP'].sport
        dst_port = packet['TCP'].dport

    event = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "function_code": data['function_code'],
        "payload": data['payload'],
        "status": status,
        "rule": rule
    }

    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(event) + '\n')
