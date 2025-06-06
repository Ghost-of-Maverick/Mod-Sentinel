import threading
import subprocess
import json
from queue import Queue
from typing import Optional, Dict, Any
import yaml
from app_logger import logger


def _first(value: Any):
    """Return the first element if value is a list, otherwise the value itself."""
    if isinstance(value, list):
        return value[0]
    return value

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

def check_arp(ip: str, mac: str) -> bool:
    """Verifica se o par IP/MAC é esperado. Devolve True se for suspeito."""
    mac = mac.lower()
    expected = allowed_macs.get(ip)
    previous = ip_mac_table.get(ip)
    suspicious = False
    if expected and mac != expected:
        logger.warning(f"[ARP] IP {ip} esperado {expected}, recebido {mac}")
        suspicious = True
    elif previous and mac != previous:
        logger.warning(f"[ARP] IP {ip} alterou de {previous} para {mac}")
        suspicious = True
    ip_mac_table[ip] = mac
    return suspicious


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
        "-T", "ek",
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                pkt = json.loads(line)
            except json.JSONDecodeError:
                continue

            layers = pkt.get("_source", {}).get("layers", {})
            timestamp = _first(layers.get("frame.time_epoch"))
            frame_len = int(_first(layers.get("frame.len", 0)) or 0)
            eth_src = _first(layers.get("eth.src"))
            eth_dst = _first(layers.get("eth.dst"))
            ip_src = _first(layers.get("ip.src"))
            ip_dst = _first(layers.get("ip.dst"))
            tcp_sport = int(_first(layers.get("tcp.srcport", 0)) or 0)
            tcp_dport = int(_first(layers.get("tcp.dstport", 0)) or 0)
            tcp_flags = _first(layers.get("tcp.flags", ""))
            payload = _first(layers.get("data.data", ""))

            arp_src_ip = _first(layers.get("arp.src.proto_ipv4"))
            arp_dst_ip = _first(layers.get("arp.dst.proto_ipv4"))
            arp_src_mac = _first(layers.get("arp.src.hw_mac"))

            if arp_src_ip and arp_src_mac:
                suspicious = check_arp(arp_src_ip, arp_src_mac)
                packet = {
                    "timestamp": float(timestamp) if timestamp else None,
                    "length": frame_len,
                    "Ethernet": {"src": eth_src, "dst": eth_dst},
                    "IP": {"src": arp_src_ip, "dst": arp_dst_ip},
                    "TCP": {"sport": 0, "dport": 0, "flags": ""},
                    "TCP_raw": b"",
                    "src_ip": arp_src_ip,
                    "dst_ip": arp_dst_ip,
                    "src_port": 0,
                    "dst_port": 0,
                    "protocol": "ARP",
                    "function_code": "",
                    "payload": "",
                    "arp_mismatch": suspicious,
                }
                tshark_packet_queue.put(packet)
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
                    "flags": tcp_flags,
                },
                "TCP_raw": raw_bytes,
                "src_ip": ip_src,
                "dst_ip": ip_dst,
                "src_port": tcp_sport,
                "dst_port": tcp_dport,
                "protocol": "Modbus",
            }

            if modbus_info:
                packet.update(modbus_info)
            else:
                packet.update(
                    {
                        "transaction_id": None,
                        "protocol_id": None,
                        "unit_id": None,
                        "function_code": "?",
                        "payload": payload,
                    }
                )

            tshark_packet_queue.put(packet)
    except FileNotFoundError:
        print("[ERRO] tshark não encontrado. Instala com: sudo apt install tshark")

def start_tshark_parser():
    thread = threading.Thread(target=tshark_parser_thread, daemon=True)
    thread.start()
