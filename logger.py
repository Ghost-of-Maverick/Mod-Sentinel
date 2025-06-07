import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Gera nome único por execução com timestamp
log_filename = f"modsentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
LOG_FILE = os.path.join(LOG_DIR, log_filename)

def log_event(packet, data, status, rule):
    try:
        timestamp = packet.get('timestamp', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        src_ip = packet.get('src_ip', 'N/A')
        dst_ip = packet.get('dst_ip', 'N/A')
        src_port = packet.get('src_port', 'N/A')
        dst_port = packet.get('dst_port', 'N/A')
        src_mac = packet.get('src_mac', 'N/A')
        dst_mac = packet.get('dst_mac', 'N/A')
        function_code = packet.get('function_code', '?')
        flags = packet.get('flags', '')
        length = packet.get('length', '')
        transaction_id = packet.get('transaction_id', '')
        payload = packet.get('payload', '')
        payload_short = payload[:32] + "..." if len(payload) > 32 else payload

        log_msg = (
            f"[{timestamp}] STATUS: {status}\n"
            f"→ From: {src_ip}:{src_port} ({src_mac}) → To: {dst_ip}:{dst_port} ({dst_mac})\n"
            f"→ Function Code: {function_code} | Flags: {flags} | Length: {length} | TxID: {transaction_id}\n"
            f"→ Payload: {payload_short}\n"
        )

        if rule:
            log_msg += f"→ Rule: {rule}\n"

        with open(LOG_FILE, 'a') as f:
            f.write(log_msg + "\n")

    except Exception as e:
        with open(LOG_FILE, 'a') as f:
            f.write(f"[LOG ERROR] Erro ao processar pacote: {e}\n")
