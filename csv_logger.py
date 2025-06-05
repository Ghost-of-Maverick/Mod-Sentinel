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
            "eth_src",
            "eth_dst",
            "tcp_flags",
            "packet_length",
            "transaction_id",
        ])

def log_to_csv(packet, data):
    if not csv_file:
        return  # CSV ainda não definido

    src_ip = packet.get("IP", {}).get("src", "")
    dst_ip = packet.get("IP", {}).get("dst", "")
    src_port = packet.get("TCP", {}).get("sport", "")
    dst_port = packet.get("TCP", {}).get("dport", "")
    eth_src = packet.get("Ethernet", {}).get("src", "")
    eth_dst = packet.get("Ethernet", {}).get("dst", "")
    tcp_flags = packet.get("TCP", {}).get("flags", "")
    packet_length = packet.get("length", "")
    timestamp = packet.get("timestamp")
    if timestamp is not None:
        ts_str = datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    function_code = data.get("function_code", "?")
    payload = data.get("payload", "")
    transaction_id = data.get("transaction_id", "?")

    with open(csv_file, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            ts_str,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            function_code,
            payload,
            eth_src,
            eth_dst,
            tcp_flags,
            packet_length,
            transaction_id,
        ])
