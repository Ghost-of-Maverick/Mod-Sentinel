import csv
import os 

csv_file = None
csv_writer = None

def set_csv_file(path):
    global csv_file, csv_writer

    file_exists = os.path.exists(path)
    is_empty = not file_exists or os.stat(path).st_size == 0

    csv_file = open(path, mode='a', newline='')  # Append mode
    csv_writer = csv.DictWriter(csv_file, fieldnames=[
        'timestamp',
        'src_mac',
        'dst_mac',
        'src_ip',
        'src_port',
        'dst_ip',
        'dst_port',
        'function_code',
        'flags',
        'length',
        'transaction_id',
        'payload',
        'malicious'
    ])

    if is_empty:
        csv_writer.writeheader()

def log_to_csv(packet, data):
    if not csv_file:
        return  # CSV ainda não definido

    src_ip = packet["IP"]["src"]
    dst_ip = packet["IP"]["dst"]
    src_port = packet["TCP"]["sport"]
    dst_port = packet["TCP"]["dport"]
    function_code = data.get("function_code", "?")
    payload = data.get("payload", "")

    with open(csv_file, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            src_ip, src_port, dst_ip, dst_port,
            function_code, payload
        ])
