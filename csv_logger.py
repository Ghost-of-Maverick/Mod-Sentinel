import csv
import os
from datetime import datetime

csv_file = None  # Nome do ficheiro atual

def set_csv_file(file_path):
    global csv_file
    csv_file = file_path
    os.makedirs(os.path.dirname(csv_file), exist_ok=True)
    with open(csv_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "function_code",
            "payload",
            "malicious",
        ])

def log_to_csv(packet, data, status):
    if not csv_file:
        return  # CSV ainda não definido

    src_ip = packet["IP"]["src"]
    dst_ip = packet["IP"]["dst"]
    src_port = packet["TCP"]["sport"]
    dst_port = packet["TCP"]["dport"]
    function_code = data.get("function_code", "?")
    payload = data.get("payload", "")
    malicious = 1 if status == "Malicious" else 0

    with open(csv_file, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            function_code,
            payload,
            malicious,
        ])
