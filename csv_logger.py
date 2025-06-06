import csv
import os
from datetime import datetime

csv_file = None  # Nome do ficheiro atual
csv_writer = None
csv_handle = None

def set_csv_file(file_path):
    """Inicializa o CSV e mantém o handle aberto para escrita."""
    global csv_file, csv_writer, csv_handle
    csv_file = file_path
    os.makedirs(os.path.dirname(csv_file), exist_ok=True)
    csv_handle = open(csv_file, mode="w", newline="")
    csv_writer = csv.writer(csv_handle)
    csv_writer.writerow([
        "timestamp",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "function_code",
        "payload",
        "malicious",
    ])
    csv_handle.flush()

def close_csv_file():
    global csv_handle, csv_writer
    if csv_handle:
        csv_handle.close()
        csv_handle = None
        csv_writer = None

def log_to_csv(packet, data, status):
    """Escreve uma linha no CSV já aberto."""
    if not csv_writer:
        return  # CSV ainda não definido

    src_ip = packet["IP"]["src"]
    dst_ip = packet["IP"]["dst"]
    src_port = packet["TCP"]["sport"]
    dst_port = packet["TCP"]["dport"]
    function_code = data.get("function_code", "?")
    payload = data.get("payload", "")
    malicious = 1 if status == "Malicious" else 0

    csv_writer.writerow([
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        function_code,
        payload,
        malicious,
    ])
    if csv_handle:
        csv_handle.flush()
