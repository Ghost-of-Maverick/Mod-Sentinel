import threading
import subprocess
import json
import yaml
from queue import Queue
from parser import parse_modbus_packet

tshark_packet_queue = Queue()

def load_interface():
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config.get("interface", "eth0")
    except Exception:
        return "eth0"

def tshark_parser_thread():
    interface = load_interface()
    cmd = [
        "tshark", "-l", "-i", interface,
        "-Y", "tcp.port == 502",
        "-d", "tcp.port==502,modbus",
        "-T", "json"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        buffer = ""
        for line in proc.stdout:
            buffer += line
            if line.strip() == "]":
                try:
                    packets = json.loads(buffer)
                    for pkt in packets:
                        layers = pkt.get("_source", {}).get("layers", {})
                        timestamp = layers.get("frame.time_epoch", [None])[0]
                        frame_len = int(layers.get("frame.len", [0])[0])
                        eth_src = layers.get("eth.src", [None])[0]
                        eth_dst = layers.get("eth.dst", [None])[0]
                        ip_src = layers.get("ip.src", [None])[0]
                        ip_dst = layers.get("ip.dst", [None])[0]
                        tcp_sport = int(layers.get("tcp.srcport", [0])[0])
                        tcp_dport = int(layers.get("tcp.dstport", [0])[0])
                        tcp_flags = layers.get("tcp.flags", [""])[0]
                        payload = layers.get("data.data", [""])[0]

                        raw_bytes = bytes.fromhex(payload) if payload else b""
                        modbus_info = parse_modbus_packet(raw_bytes)

                        packet = {
                            "timestamp": float(timestamp) if timestamp else None,
                            "length": frame_len,
                            "Ethernet": {"src": eth_src, "dst": eth_dst},
                            "IP": {"src": ip_src, "dst": ip_dst},
                            "TCP": {
                                "sport": tcp_sport,
                                "dport": tcp_dport,
                                "flags": tcp_flags
                            },
                            "TCP_raw": raw_bytes,
                            "src_ip": ip_src,
                            "dst_ip": ip_dst,
                            "src_port": tcp_sport,
                            "dst_port": tcp_dport
                        }

                        if modbus_info:
                            packet.update(modbus_info)
                        else:
                            packet.update({
                                "transaction_id": None,
                                "protocol_id": None,
                                "unit_id": None,
                                "function_code": "?",
                                "payload": payload,
                            })

                        tshark_packet_queue.put(packet)
                except json.JSONDecodeError:
                    pass
                buffer = ""
    except FileNotFoundError:
        print("[ERRO] tshark não encontrado. Instala com: sudo apt install tshark")

def start_tshark_parser():
    thread = threading.Thread(target=tshark_parser_thread, daemon=True)
    thread.start()
