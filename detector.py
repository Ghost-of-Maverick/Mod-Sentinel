import rules_loader
import binascii
import yaml

rules = []
modbus_state = {}  # Guarda pedidos Modbus por (src_ip, dst_ip, fc)

# Carrega os pares IP-MAC permitidos
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)
ALLOWED_MACS = config.get("allowed_macs", {})

def init_detector(rules_file):
    global rules
    rules = rules_loader.load_rules(rules_file)

def detect(modbus_data):
    if not modbus_data or "payload" not in modbus_data:
        return 0, None  # Nada suspeito

    # Verifica ARP spoofing
    src_ip = modbus_data.get("src_ip")
    src_mac = modbus_data.get("src_mac")
    if src_ip and src_mac:
        expected_mac = ALLOWED_MACS.get(src_ip)
        if expected_mac and expected_mac.lower() != src_mac.lower():
            return 1, f"[MITM] ARP Spoofing detected! IP {src_ip} should be {expected_mac}, got {src_mac}"

    payload_bytes = bytes.fromhex(modbus_data["payload"])
    dst_ip = modbus_data.get("dst_ip")
    fc = modbus_data.get("function_code")

    # Guarda pedidos
    if modbus_data.get("dst_port") == 502:
        modbus_state[(src_ip, dst_ip, fc)] = modbus_data

    # Verifica se é uma resposta e se é coerente com o pedido anterior
    elif modbus_data.get("src_port") == 502:
        key = (dst_ip, src_ip, fc)
        if key in modbus_state:
            last_request = modbus_state[key]
            if not is_response_consistent(last_request, modbus_data):
                return 1, "[MITM] Resposta incoerente com o pedido anterior"

    # Verificação baseada em regras
    for rule in rules:
        opts = rule["options"]
        all_match = True

        # Verifica flow (direção do tráfego)
        flow = opts.get("flow")
        if flow:
            is_client_to_server = modbus_data.get("dst_port") == 502
            is_server_to_client = modbus_data.get("src_port") == 502

            if "from_client" in flow and not is_client_to_server:
                continue
            if "to_client" in flow and not is_server_to_client:
                continue
            if "established" in flow and not (is_client_to_server or is_server_to_client):
                continue

        # Verifica dsize
        if "dsize" in opts:
            dsize = opts["dsize"]
            if ">" in dsize:
                min_size = int(dsize.strip(">").strip())
                if len(payload_bytes) <= min_size:
                    all_match = False
            else:
                expected_size = int(dsize)
                if len(payload_bytes) != expected_size:
                    all_match = False

        # Verifica contents
        if "contents" in opts:
            for c in opts["contents"]:
                try:
                    content = parse_content(c["content"])
                    offset = int(c.get("offset", 0))
                    depth = int(c.get("depth", len(payload_bytes) - offset))
                    if offset + depth > len(payload_bytes):
                        all_match = False
                        break
                    search_window = payload_bytes[offset:offset + depth]
                    if content not in search_window:
                        all_match = False
                        break
                except Exception:
                    all_match = False
                    break

        # Verifica pcre
        if "pcre" in opts:
            import re
            pcre = opts["pcre"]
            regex_body = pcre.strip("/").rstrip("iAR")
            pattern = re.compile(regex_body.encode(), re.DOTALL)
            if not pattern.search(payload_bytes):
                all_match = False

        # Verifica byte_test
        if "byte_test" in opts:
            try:
                bt = opts["byte_test"]
                size = int(bt["size"])
                operator = bt["operator"]
                value = int(bt["value"], 0)
                offset = int(bt["offset"])
                data = int.from_bytes(payload_bytes[offset:offset + size], byteorder="big")
                if operator == ">=" and not (data >= value):
                    all_match = False
                elif operator == "==" and not (data == value):
                    all_match = False
                elif operator == "<=" and not (data <= value):
                    all_match = False
            except Exception:
                all_match = False

        if all_match:
            msg = opts.get("msg", "[Regra sem mensagem]")
            sid = opts.get("sid", "N/A")
            return 1, f"[SID {sid}] {msg}"

    # Nenhuma regra bateu
    return 0, None

def is_response_consistent(request, response):
    if request["function_code"] != response["function_code"]:
        return False

    req_payload = bytes.fromhex(request["payload"])
    res_payload = bytes.fromhex(response["payload"])

    # Exemplo de verificação para FC=3 (Read Holding Registers)
    if response["function_code"] == 3:
        if len(req_payload) >= 6 and len(res_payload) >= 3:
            expected_registers = req_payload[5]
            expected_bytes = expected_registers * 2
            byte_count = res_payload[2]
            if byte_count != expected_bytes:
                return False
    return True

def parse_content(content_str):
    if content_str.startswith("|") and content_str.endswith("|"):
        hex_str = content_str.strip("|").replace(" ", "")
        return binascii.unhexlify(hex_str)
    else:
        return content_str.encode()
