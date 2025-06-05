import threading
import subprocess
import json
from queue import Queue
from typing import Optional, Dict
import yaml
from app_logger import logger

allowed_macs = {}
ip_mac_table = {}

def load_allowed_macs():
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            macs = config.get("allowed_macs", {})
            return {ip: mac.lower() for ip, mac in macs.items()}
    except Exception:
        return {}

def check_arp(ip: str, mac: str) -> None:
    mac = mac.lower()
    expected = allowed_macs.get(ip)
    previous = ip_mac_table.get(ip)
    if expected and mac != expected:
        logger.warning(f"[ARP] IP {ip} esperado {expected}, recebido {mac}")
    elif previous and mac != previous:
        logger.warning(f"[ARP] IP {ip} alterou de {previous} para {mac}")
    ip_mac_table[ip] = mac


def parse_modbus_packet(tcp_payload: bytes) -> Optional[Dict[str, int | str]]:
    """Parse raw Modbus/TCP payload and return a dictionary with key fields."""
    if not tcp_payload or len(tcp_payload) < 8:
        return None
    try:
        transaction_id = int.from_bytes(tcp_payload[0:2], "big")
        protocol_id = int.from_bytes(tcp_payload[2:4], "big")
        length = int.from_bytes(tcp_payload[4:6], "big")
        unit_id = tcp_payload[6]
        function_code = tcp_payload[7]
        payload = tcp_payload[7:].hex()
        return {
            "transaction_id": transaction_id,
            "protocol_id": protocol_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "payload": payload,
        }
    except Exception:
        return None
        
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
    global allowed_macs
    allowed_macs = load_allowed_macs()
    cmd = [
        "tshark", "-l", "-i", interface,
        "-Y", "tcp.port == 502 || arp",
        "-d", "tcp.port==502,modbus",
        "-T", "json"
    ]

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

                        arp_src_ip = layers.get("arp.src.proto_ipv4", [None])[0]
                        arp_src_mac = layers.get("arp.src.hw_mac", [None])[0]
                        if arp_src_ip and arp_src_mac:
                            check_arp(arp_src_ip, arp_src_mac)
                            continue

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
