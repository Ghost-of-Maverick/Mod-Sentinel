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
        'unit_id',
        'protocol_id',  
        'flags',
        'length',
        'transaction_id',
        'payload',
        'malicious'
    ])

    if is_empty:
        csv_writer.writeheader()

def log_to_csv(packet, raw_data=None, status=0):
    if csv_writer is None:
        return

    try:
        row = {
            'timestamp': packet.get('timestamp', ''),
            'src_mac': packet.get('src_mac', ''),
            'dst_mac': packet.get('dst_mac', ''),
            'src_ip': packet.get('src_ip', ''),
            'src_port': packet.get('src_port', ''),
            'dst_ip': packet.get('dst_ip', ''),
            'dst_port': packet.get('dst_port', ''),
            'function_code': packet.get('function_code', ''),
            'unit_id': packet.get('unit_id', ''),
            'protocol_id': packet.get('protocol_id', ''),  
            'flags': packet.get('flags', ''),
            'length': packet.get('length', ''),
            'transaction_id': packet.get('transaction_id', ''),
            'payload': packet.get('payload', ''),
            'malicious': int(bool(status))
        }

        csv_writer.writerow(row)
        csv_file.flush()
    except Exception as e:
        print(f"[csv_logger] Erro ao escrever linha no CSV: {e}")

def close_csv_file():
    if csv_file:
        csv_file.close()
