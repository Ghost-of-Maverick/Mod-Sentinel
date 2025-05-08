from datetime import datetime

LOG_FILE = 'logs/modsentinel.log'

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

    # Formatação multi-linha clara
    if status == "Malicious":
        log_msg = (
            f"{timestamp} ALERT: Malicious Modbus Packet Detected\n"
            f"→ From: {src_ip}:{src_port} → To: {dst_ip}:{dst_port}\n"
            f"→ Function Code: {function_code}\n"
            f"→ Payload: {payload_short}\n"
            f"→ Rule: {rule}\n"
        )
    else:
        log_msg = (
            f"{timestamp} INFO: Normal Modbus Packet\n"
            f"→ From: {src_ip}:{src_port} → To: {dst_ip}:{dst_port}\n"
            f"→ Function Code: {function_code}\n"
        )

    with open(LOG_FILE, 'a') as f:
        f.write(log_msg + "\n")
