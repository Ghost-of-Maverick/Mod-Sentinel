import yaml

with open("config.yaml", "r") as f:
    _cfg = yaml.safe_load(f) or {}

MODBUS_CLIENTS = set(_cfg.get("MODBUS_CLIENT", []))
MODBUS_SERVERS = set(_cfg.get("MODBUS_SERVER", []))
ALLOWED_MACS   = {str(k): str(v).lower() for k, v in (_cfg.get("allowed_macs") or {}).items()}
 
KNOWN_ATTACKERS = set(_cfg.get("known_attackers", []) or ["172.27.224.40"])

def detect(pkt: dict):
    """
    Recebe dados do packet_sniffer.py e devolve (status, mensagem)
    status = 1 -> malicioso / suspeito
    status = 0 -> OK
    """
    if not pkt:
        return 0, None

    src_ip = str(pkt.get("src_ip") or "")
    dst_ip = str(pkt.get("dst_ip") or "")
    src_mac = str(pkt.get("src_mac") or "").lower()
    dst_port = str(pkt.get("dst_port") or "")

    if dst_port != "502":
        return 0, None

    # 1) ARP spoofing / MitM
    if src_ip in ALLOWED_MACS:
        expected_mac = ALLOWED_MACS[src_ip]
        if expected_mac and src_mac != expected_mac:
            return 1, f"[ARP SPOOFING / MITM] {src_ip} deveria ter MAC {expected_mac}, mas veio {src_mac}"

    # 2) IP atacante conhecido
    if src_ip in KNOWN_ATTACKERS:
        return 1, f"[IP NÃO AUTORIZADO] Origem {src_ip} a falar com {dst_ip}:502"

    # 3) DoS (IPs aleatórios / não autorizados)
    if src_ip not in MODBUS_CLIENTS and dst_ip in MODBUS_SERVERS:
        return 1, f"[DoS] Possível ataque de IP aleatório {src_ip} contra {dst_ip}:502"

    # OK
    return 0, None