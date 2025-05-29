import threading
import subprocess
import json
from queue import Queue

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
                        ip_src = layers.get("ip.src", [None])[0]
                        ip_dst = layers.get("ip.dst", [None])[0]
                        tcp_sport = int(layers.get("tcp.srcport", [0])[0])
                        tcp_dport = int(layers.get("tcp.dstport", [0])[0])
                        payload = layers.get("data.data", [""])[0]

                        packet = {
                            "IP": {"src": ip_src, "dst": ip_dst},
                            "TCP": {"sport": tcp_sport, "dport": tcp_dport},
                            "TCP_raw": bytes.fromhex(payload) if payload else b""
                        }

                        tshark_packet_queue.put(packet)
                except json.JSONDecodeError:
                    pass
                buffer = ""
    except FileNotFoundError:
        print("[ERRO] tshark não encontrado. Instala com: sudo apt install tshark")

def start_tshark_parser():
    thread = threading.Thread(target=tshark_parser_thread, daemon=True)
    thread.start()
