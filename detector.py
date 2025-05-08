import rules_loader
import binascii

rules = []
modbus_state = {}  # Guarda pedidos Modbus por (src_ip, dst_ip, fc)

def init_detector(rules_file):
    global rules
    rules = rules_loader.load_rules(rules_file)

def detect(modbus_data):
    if not modbus_data or "payload" not in modbus_data:
        return "OK", None

    payload_bytes = bytes.fromhex(modbus_data["payload"])
    src_ip = modbus_data.get("src_ip")
    dst_ip = modbus_data.get("dst_ip")
    fc = modbus_data.get("function_code")

    # Verifica se é um pedido (porta destino 502)
    if modbus_data.get("dst_port") == 502:
        modbus_state[(src_ip, dst_ip, fc)] = modbus_data

    # Verifica se é uma resposta (porta origem 502)
    elif modbus_data.get("src_port") == 502:
        key = (dst_ip, src_ip, fc)
        if key in modbus_state:
            last_request = modbus_state[key]
            if not is_response_consistent(last_request, modbus_data):
                return "Malicious", "[MitM] Resposta incoerente com o pedido anterior"

    # Verificação baseada em regras
    for rule in rules:
        opts = rule["options"]
        all_match = True

        # Verifica flow (direção do tráfego)
        flow = opts.get("flow")
        if flow:
            is_client_to_server = modbus_data.get("dst_port") == 502
            is_server_to_client = modbus_data.get("src_port") == 502

            if flow == "from_client" and not is_client_to_server:
                continue
            if flow == "to_client" and not is_server_to_client:
                continue
            if flow == "established" and not (is_client_to_server or is_server_to_client):
                continue

        if "contents" in opts:
            for c in opts["contents"]:
                try:
                    content = parse_content(c["content"])
                    offset = int(c.get("offset", 0))
                    depth = int(c.get("depth", len(payload_bytes) - offset))
                    search_window = payload_bytes[offset:offset + depth]
                    if content not in search_window:
                        all_match = False
                        break
                except Exception:
                    all_match = False
                    break

        if all_match:
            msg = opts.get("msg", "[Regra sem mensagem]")
            sid = opts.get("sid", "N/A")
            return "Malicious", f"[SID {sid}] {msg}"

    return "OK", None

def is_response_consistent(request, response):
    if request["function_code"] != response["function_code"]:
        return False

    req_payload = bytes.fromhex(request["payload"])
    res_payload = bytes.fromhex(response["payload"])

    # Verificação mais robusta para FC=3 (Read Holding Registers)
    if response["function_code"] == 3:
        if len(req_payload) >= 6 and len(res_payload) >= 3:
            expected_registers = req_payload[5]  # nº de registos pedidos (último byte do pedido)
            expected_bytes = expected_registers * 2  # cada registo = 2 bytes
            byte_count = res_payload[2]  # campo byte count na resposta
            if byte_count != expected_bytes:
                return False
    return True

def parse_content(content_str):
    if content_str.startswith("|") and content_str.endswith("|"):
        hex_str = content_str.strip("|").replace(" ", "")
        return binascii.unhexlify(hex_str)
    else:
        return content_str.encode()