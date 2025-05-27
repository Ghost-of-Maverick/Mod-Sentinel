import os
from datetime import datetime

# Garante que existe a pasta de logs
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)

# Gera nome único por execução com timestamp
log_filename = f"modsentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
LOG_FILE = os.path.join(LOG_DIR, log_filename)

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

    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    function_code = data.get('function_code', '?')
    payload = data.get('payload', '')
    payload_short = payload[:32] + "..." if len(payload) > 32 else payload

    log_msg = (
        f"{timestamp} STATUS: {status}\n"
        f"→ From: {src_ip}:{src_port} → To: {dst_ip}:{dst_port}\n"
        f"→ Function Code: {function_code}\n"
        f"→ Payload: {payload_short}\n"
    )

    if rule:
        log_msg += f"→ Rule: {rule}\n"

    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + "\n")
